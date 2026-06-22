package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") != "" || os.Getenv("CHIHIRO_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	})
	slog.SetDefault(slog.New(handler))

	slog.Info("Starting cluster watcher application", "version", "v1.0.0", "log_level", logLevel.String())
	slog.Info("Loading configuration from environment variables and config file")

	if env := os.Getenv("CHIHIRO_CLUSTER_DOMAIN"); env != "" {
		viper.Set("cluster.domain", env)
	}
	if env := os.Getenv("CHIHIRO_CLUSTER_PORT"); env != "" {
		if port, err := strconv.Atoi(env); err == nil {
			viper.Set("cluster.port", port)
		}
	}
	if env := os.Getenv("CHIHIRO_ADMIN_GROUPS"); env != "" {
		var groups []string
		for _, item := range strings.Split(env, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
		if len(groups) > 0 {
			viper.Set("cluster.admin_groups", groups)
		}
	}
	if env := os.Getenv("CHIHIRO_CREATOR_GROUPS"); env != "" {
		var groups []string
		for _, item := range strings.Split(env, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
		if len(groups) > 0 {
			viper.Set("cluster.creator_groups", groups)
		}
	}
	if env := os.Getenv("CHIHIRO_AVAILABLE_VERSIONS"); env != "" {
		var versions []string
		for _, item := range strings.Split(env, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				versions = append(versions, trimmed)
			}
		}
		if len(versions) > 0 {
			viper.Set("cluster.available_versions", versions)
		}
	}
	if env := os.Getenv("CHIHIRO_MAX_CLUSTERS"); env != "" {
		if maxClusters, err := strconv.Atoi(env); err == nil {
			viper.Set("cluster.limits.max_clusters", maxClusters)
		}
	}
	if env := os.Getenv("CHIHIRO_MAX_TOTAL_NODES"); env != "" {
		if maxNodes, err := strconv.Atoi(env); err == nil {
			viper.Set("cluster.limits.max_total_nodes", maxNodes)
		}
	}
	if env := os.Getenv("CHIHIRO_MAX_TOTAL_CP"); env != "" {
		if maxCP, err := strconv.Atoi(env); err == nil {
			viper.Set("cluster.limits.max_total_cp", maxCP)
		}
	}
	if err := cluster.ValidateConfig(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	clusterDomain := viper.GetString("cluster.domain")
	clusterPort := viper.GetInt("cluster.port")
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	creatorGroups := viper.GetStringSlice("cluster.creator_groups")
	availableVersions := viper.GetStringSlice("cluster.available_versions")
	maxClusters := viper.GetInt("cluster.limits.max_clusters")
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")
	maxTotalCP := viper.GetInt("cluster.limits.max_total_cp")

	slog.Info("Cluster configuration",
		"domain", clusterDomain,
		"port", clusterPort,
		"admin_groups", adminGroups,
		"creator_groups", creatorGroups,
		"available_versions", availableVersions,
		"max_clusters", maxClusters,
		"max_total_nodes", maxTotalNodes,
		"max_total_cp", maxTotalCP)

	kubeconfig := viper.GetString("kubeconfig")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	host := getEnvOrConfig("CHIHIRO_HOST", "host", "0.0.0.0")
	port := getEnvOrConfigInt("CHIHIRO_PORT", "port", 8080)
	slog.Info("Server configuration", "host", host, "port", port)

	var authConfig auth.Config
	viper.UnmarshalKey("oidc", &authConfig)

	if env := os.Getenv("CHIHIRO_OIDC_ISSUER_URL"); env != "" {
		authConfig.IssuerURL = env
	}
	if env := os.Getenv("CHIHIRO_OIDC_CLIENT_ID"); env != "" {
		authConfig.ClientID = env
	}
	if env := os.Getenv("CHIHIRO_OIDC_CLIENT_SECRET"); env != "" {
		authConfig.ClientSecret = env
	}
	if env := os.Getenv("CHIHIRO_SESSION_KEY"); env != "" {
		authConfig.SessionKey = env
	}

	// Placeholder — actual redirect URL is determined per-request from headers.
	if authConfig.RedirectURL == "" {
		authConfig.RedirectURL = "http://localhost:8080/auth/callback"
	}

	slog.Info(
		"OIDC configuration",
		"issuer_url",
		authConfig.IssuerURL,
		"client_id",
		authConfig.ClientID,
		"note",
		"redirect_url will be dynamically determined from request headers",
	)

	if authConfig.IssuerURL == "" || authConfig.ClientID == "" || authConfig.ClientSecret == "" {
		slog.Error("OIDC configuration incomplete", "missing_fields", "issuer-url, client-id, or client-secret")
		slog.Error("Set CHIHIRO_OIDC_ISSUER_URL, CHIHIRO_OIDC_CLIENT_ID, and CHIHIRO_OIDC_CLIENT_SECRET environment variables")
		os.Exit(1)
	}

	if len(authConfig.SessionKey) < 32 {
		slog.Error("Session key must be at least 32 bytes", "current_length", len(authConfig.SessionKey))
		slog.Error("Set CHIHIRO_SESSION_KEY environment variable with a secure random key (openssl rand -base64 32)")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clusterWatcher, err := watcher.NewClusterWatcher(kubeconfig)
	if err != nil {
		slog.Error("Failed to create cluster watcher", "error", err)
		os.Exit(1)
	}

	clusterManager := cluster.NewManager(clusterWatcher.GetClient(), clusterWatcher.GetClusterGVR())

	redisAddr := getEnvOrConfig("CHIHIRO_REDIS_ADDR", "redis.addr", "localhost:6379")
	redisUsername := getEnvOrConfig("CHIHIRO_REDIS_USERNAME", "redis.username", "")
	redisPassword := getEnvOrConfig("CHIHIRO_REDIS_PASSWORD", "redis.password", "")
	sessionTTL := getEnvOrConfigInt("CHIHIRO_SESSION_TTL", "redis.session_ttl", 3600)

	slog.Info("Redis configuration", "addr", redisAddr, "username", redisUsername, "session_ttl", sessionTTL)
	slog.Info("Connecting to Redis for session storage")

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Username: redisUsername,
		Password: redisPassword,
	})

	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		slog.Error("Could not connect to Redis", "error", err)
		os.Exit(1)
	}
	redisClient.Close()

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

	sessionStore.Options.Path = "/"
	sessionStore.Options.MaxAge = sessionTTL
	sessionStore.Options.HttpOnly = true
	// Drive the Secure flag from config/TLS rather than hardcoding it.
	// Precedence:
	//   1. Explicit CHIHIRO_SESSION_SECURE / session.secure setting.
	//   2. Otherwise auto-detect: true when the OIDC redirect URL is HTTPS
	//      (i.e. served behind TLS), false for local HTTP development.
	// The Secure flag must be false on plain HTTP or browsers drop the cookie.
	secureCookies := strings.HasPrefix(strings.ToLower(authConfig.RedirectURL), "https://")
	if env := os.Getenv("CHIHIRO_SESSION_SECURE"); env != "" {
		secureCookies = parseBool(env)
	} else if viper.IsSet("session.secure") {
		secureCookies = viper.GetBool("session.secure")
	}
	sessionStore.Options.Secure = secureCookies
	sessionStore.Options.SameSite = http.SameSiteLaxMode // Lax mode for OAuth callbacks

	slog.Info("Session cookie security configured", "secure", secureCookies)

	slog.Info("Redis session store initialized successfully")

	oidcProvider, err := auth.NewOIDCProvider(&authConfig, sessionStore)
	if err != nil {
		slog.Error("Failed to create OIDC provider", "error", err)
		os.Exit(1)
	}

	authMiddleware := auth.NewMiddleware(oidcProvider)

	srv := server.NewServer(clusterWatcher, clusterManager, authMiddleware)
	defer srv.Close()

	clusterWatcher.Start(ctx)

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

// parseBool interprets common truthy string values (1, t, true, yes, on)
// case-insensitively. Unrecognized values are treated as false.
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func getEnvOrConfig(envKey, configKey, defaultValue string) string {
	if env := os.Getenv(envKey); env != "" {
		return env
	}
	if val := viper.GetString(configKey); val != "" {
		return val
	}
	return defaultValue
}

func getEnvOrConfigInt(envKey, configKey string, defaultValue int) int {
	if env := os.Getenv(envKey); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			return val
		}
	}
	if val := viper.GetInt(configKey); val != 0 {
		return val
	}
	return defaultValue
}
