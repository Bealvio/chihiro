package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/boj/redistore"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/Bealvio/chihiro/internal/cluster"
	"github.com/Bealvio/chihiro/internal/server"
	"github.com/Bealvio/chihiro/internal/watcher"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web server",
	Long: `Start the web server that watches Cluster API resources and serves
the dashboard web interface. The server will automatically connect to your
Kubernetes cluster and begin monitoring clusters in real-time.`,
	Run: func(cmd *cobra.Command, args []string) {
		runServer()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServer() {
	// Configure structured logging
	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") != "" {
		logLevel = slog.LevelDebug
	}

	// Create a JSON handler for structured logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
		AddSource: true,
	})
	slog.SetDefault(slog.New(handler))

	slog.Info("Starting cluster watcher application", "version", "v1.0.0", "log_level", logLevel.String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeconfig := viper.GetString("kubeconfig")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	clusterWatcher, err := watcher.NewClusterWatcher(kubeconfig)
	if err != nil {
		slog.Error("Failed to create cluster watcher", "error", err)
		os.Exit(1)
	}

	clusterManager := cluster.NewManager(clusterWatcher.GetClient())

	// Setup OIDC authentication
	host := viper.GetString("host")
	port := viper.GetInt("port")

	var authConfig auth.Config
	viper.UnmarshalKey("oidc", &authConfig)

	// Override with environment variables (takes precedence over config file)
	if envSecret := os.Getenv("OIDC_CLIENT_SECRET"); envSecret != "" {
		authConfig.ClientSecret = envSecret
	}
	if envSessionKey := os.Getenv("SESSION_KEY"); envSessionKey != "" {
		authConfig.SessionKey = envSessionKey
	}

	// Set default redirect URL if not provided
	if authConfig.RedirectURL == "" {
		authConfig.RedirectURL = fmt.Sprintf("http://%s:%d/auth/callback", host, port)
	}

	// Validate OIDC configuration
	if authConfig.IssuerURL == "" || authConfig.ClientID == "" || authConfig.ClientSecret == "" {
		slog.Error("OIDC configuration incomplete", "missing_fields", "issuer-url, client-id, or client-secret")
		slog.Info("Set OIDC_CLIENT_SECRET environment variable or configure in config file")
		os.Exit(1)
	}

	// Validate session key (must be 32+ bytes for AES-256)
	if len(authConfig.SessionKey) < 32 {
		slog.Error("Session key must be at least 32 bytes", "current_length", len(authConfig.SessionKey))
		slog.Info("Set SESSION_KEY environment variable with a secure random key")
		os.Exit(1)
	}

	// Setup Redis session store
	redisAddr := viper.GetString("redis.addr")
	redisUsername := viper.GetString("redis.username")
	redisPassword := viper.GetString("redis.password")

	// Override Redis password with environment variable if set
	if envRedisPassword := os.Getenv("REDIS_PASSWORD"); envRedisPassword != "" {
		redisPassword = envRedisPassword
	}

	sessionTTL := viper.GetInt("redis.session_ttl")

	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	if sessionTTL <= 0 {
		sessionTTL = 3600 // 1 hour default
	}

	slog.Info("Connecting to Redis for session storage", "addr", redisAddr, "session_ttl", sessionTTL)

	// Test Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Username: redisUsername,
		Password: redisPassword,
	})

	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		slog.Error("Could not connect to Redis", "error", err)
		os.Exit(1)
	}
	redisClient.Close() // Close test connection

	// Create Redis session store
	sessionStore, err := redistore.NewRediStore(10, "tcp", redisAddr, redisUsername, redisPassword, []byte(authConfig.SessionKey))
	if err != nil {
		slog.Error("Could not create Redis session store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := sessionStore.Close(); err != nil {
			slog.Error("Failed to close Redis session store cleanly", "error", err)
		}
	}()
	sessionStore.SetMaxAge(sessionTTL)

	// Configure secure cookie options
	sessionStore.Options.Path = "/"
	sessionStore.Options.MaxAge = sessionTTL
	sessionStore.Options.HttpOnly = true
	// Only set Secure flag if running on HTTPS
	// For local development on HTTP, this must be false
	sessionStore.Options.Secure = false // TODO: Set to true in production with HTTPS
	sessionStore.Options.SameSite = http.SameSiteLaxMode // Lax mode for OAuth callbacks

	slog.Info("Redis session store initialized successfully")

	oidcProvider, err := auth.NewOIDCProvider(&authConfig, sessionStore)
	if err != nil {
		slog.Error("Failed to create OIDC provider", "error", err)
		os.Exit(1)
	}

	authMiddleware := auth.NewMiddleware(oidcProvider)

	clusterWatcher.Start(ctx)

	srv := server.NewServer(clusterWatcher, clusterManager, authMiddleware)

	address := fmt.Sprintf("%s:%d", host, port)

	httpServer := &http.Server{
		Addr:         address,
		Handler:      srv.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("Starting cluster watcher server", "address", address, "dashboard_url", fmt.Sprintf("http://%s", address))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server exited successfully")
}