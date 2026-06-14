package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/Bealvio/chihiro/internal/cluster"
	"github.com/Bealvio/chihiro/internal/kubeconfig"
	"github.com/Bealvio/chihiro/internal/middleware"
	"github.com/Bealvio/chihiro/internal/watcher"
)

type Server struct {
	watcher       *watcher.ClusterWatcher
	manager       *cluster.Manager
	auth          *auth.Middleware
	kubeconfigGen *kubeconfig.Generator
	router        *gin.Engine
	stopCleanup   chan struct{}
}

var clusterNameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func NewServer(w *watcher.ClusterWatcher, m *cluster.Manager, authMiddleware *auth.Middleware) *Server {
	slog.Info("Initializing server with routes and middleware")

	// Set Gin to release mode to reduce log verbosity
	gin.SetMode(gin.ReleaseMode)

	// Disable Gin's default logging to use our slog instead
	if os.Getenv("DEBUG") == "" {
		gin.DefaultWriter = io.Discard
		gin.DefaultErrorWriter = io.Discard
	}

	kubeconfigGen := kubeconfig.NewGenerator(w.GetClient(), w.GetResolver())

	// Let the watcher probe kubeconfig (OIDC) readiness using the generator, so
	// the UI can grey out the download button until a kubeconfig can actually be
	// reconstituted from the cluster's control plane CR.
	w.SetOIDCProber(kubeconfigGen)

	s := &Server{
		watcher:       w,
		manager:       m,
		auth:          authMiddleware,
		kubeconfigGen: kubeconfigGen,
		router:        gin.New(),
		stopCleanup:   make(chan struct{}),
	}

	s.setupRoutes()

	slog.Info("Server initialized successfully with all routes configured")
	return s
}

func (s *Server) Router() *gin.Engine {
	return s.router
}

// Close stops background goroutines started by the server (e.g. rate limiter
// cleanup). Safe to call once during shutdown.
func (s *Server) Close() {
	if s.stopCleanup != nil {
		close(s.stopCleanup)
	}
}

func (s *Server) setupRoutes() {
	// Add custom recovery and logging middleware
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.securityHeadersMiddleware())
	s.router.Use(s.requestSizeLimitMiddleware())

	// Load HTML templates
	s.router.LoadHTMLGlob("web/templates/*")

	// Serve static files
	s.router.Static("/static", "web/static")

	// Create rate limiters and start periodic eviction of idle per-IP entries
	// so the limiter maps do not grow unbounded (DoS / memory-leak defense).
	authRateLimiter := middleware.AuthRateLimiter()
	apiRateLimiter := middleware.APIRateLimiter()
	authRateLimiter.StartCleanup(5*time.Minute, 15*time.Minute, s.stopCleanup)
	apiRateLimiter.StartCleanup(5*time.Minute, 15*time.Minute, s.stopCleanup)

	// Authentication routes (public) with strict rate limiting
	s.router.GET("/login", s.handleLoginPage)
	s.router.GET("/auth/login", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleLogin)
	s.router.GET("/auth/callback", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleCallback)
	s.router.GET("/auth/logout", s.auth.HandleLogout)
	s.router.GET("/health", s.handleHealth)
	s.router.GET("/favicon.ico", s.handleFavicon)

	// Protected routes with API rate limiting
	protected := s.router.Group("/")
	protected.Use(s.auth.RequireAuth())
	protected.Use(middleware.RateLimitMiddleware(apiRateLimiter))

	protected.GET("/", s.handleHome)
	protected.GET("/api/user", s.handleUserInfo)
	protected.GET("/api/config", s.handleGetConfig)
	protected.GET("/api/clusters", s.handleAPI)
	protected.POST("/api/clusters", s.handleCreateCluster)
	protected.DELETE("/api/clusters/:name", s.handleDeleteCluster)
	protected.PUT("/api/clusters/:name/groups", s.handleEditClusterGroups)
	protected.PUT("/api/clusters/:name/nodes", s.handleEditClusterNodes)
	protected.PUT("/api/clusters/:name/worker-groups", s.handleEditWorkerGroups)
	protected.PUT("/api/clusters/:name/control-plane", s.handleEditClusterControlPlane)
	protected.PUT("/api/clusters/:name/version", s.handleEditClusterVersion)
	protected.GET("/api/clusters/:name/kubeconfig", s.handleDownloadKubeconfig)
	protected.GET("/api/versions", s.handleGetVersions)
	protected.GET("/api/user/groups", s.handleGetUserGroups)
	protected.GET("/api/user/permissions", s.handleGetUserPermissions)
	protected.GET("/api/limits", s.handleGetLimits)
	protected.GET("/api/cluster/parameters", s.handleGetClusterParameters)
	protected.GET("/api/cluster/editable", s.handleGetEditableFields)
	protected.GET("/api/cluster/worker-flavors", s.handleGetWorkerFlavors)
	protected.GET("/api/cluster/worker-classes", s.handleGetWorkerClasses)
	protected.GET("/ws", s.handleWebSocket)
}

// Logging middleware for Gin
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		slog.Debug("HTTP request", "method", c.Request.Method, "path", c.Request.URL.Path, "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))
		c.Next()
	}
}

// Security headers middleware
func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-XSS-Protection", "1; mode=block")
		// HSTS header should only be set when using HTTPS
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

// Request size limit middleware
func (s *Server) requestSizeLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1048576) // 1MB limit
		c.Next()
	}
}

func (s *Server) handleLoginPage(c *gin.Context) {
	slog.Debug("Serving login page", "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))

	c.HTML(http.StatusOK, "login.html", nil)
}

func (s *Server) handleHome(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Serving dashboard page", "username", getUsernameOrAnon(user), "remote_addr", c.ClientIP())

	c.HTML(http.StatusOK, "dashboard.html", nil)
}

func (s *Server) handleAPI(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized API access attempt", "endpoint", "/api/clusters", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	clusters := s.watcher.GetClustersForUser(user.Groups)
	slog.Debug("Serving clusters API", "username", user.Username, "cluster_count", len(clusters), "user_groups", user.Groups)

	c.JSON(http.StatusOK, clusters)
}

func (s *Server) handleUserInfo(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if user is admin based on config admin groups
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Create a copy of the user with admin status
	userWithAdmin := *user
	userWithAdmin.IsAdmin = isAdmin

	slog.Debug("Serving user info", "username", user.Username, "groups", user.Groups, "isAdmin", isAdmin, "adminGroups", adminGroups)

	c.JSON(http.StatusOK, &userWithAdmin)
}

func (s *Server) handleGetConfig(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get documentation URL from config with environment variable override
	docsURL := viper.GetString("docs_url")
	if env := os.Getenv("CHIHIRO_DOCS_URL"); env != "" {
		docsURL = env
	}

	slog.Debug("Serving config", "username", user.Username, "docs_url", docsURL)

	c.JSON(http.StatusOK, gin.H{
		"docsUrl": docsURL,
	})
}

func (s *Server) handleWebSocket(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized WebSocket connection attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	upgrader := s.watcher.GetUpgrader()
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("Failed to upgrade to WebSocket", "username", user.Username, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to upgrade to WebSocket"})
		return
	}
	defer conn.Close()

	slog.Info("WebSocket connection established", "username", user.Username, "user_groups", user.Groups, "remote_addr", c.ClientIP())

	s.watcher.AddWebSocketClient(conn, user.Groups)
	defer func() {
		s.watcher.RemoveWebSocketClient(conn)
		slog.Info("WebSocket connection closed", "username", user.Username)
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			slog.Debug("WebSocket read error, closing connection", "username", user.Username, "error", err)
			break
		}
	}
}

func (s *Server) handleCreateCluster(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster creation attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req cluster.CreateClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid cluster creation request body", "username", user.Username, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate cluster name format
	if !clusterNameRegex.MatchString(req.Name) {
		slog.Warn("Invalid cluster name format", "username", user.Username, "cluster_name", req.Name)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster name format. Must be lowercase alphanumeric with hyphens"})
		return
	}

	// Check if user is admin (admins can always create)
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}

	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Check if user has permission to create clusters
	if !isAdmin {
		creatorGroups := viper.GetStringSlice("cluster.creator_groups")
		if len(creatorGroups) == 0 {
			// Fallback to admin groups if creator groups not configured
			creatorGroups = adminGroups
		}

		canCreate := auth.CheckUserGroups(user.Groups, creatorGroups)
		if !canCreate {
			slog.Warn("User attempted to create cluster without permission", "username", user.Username, "user_groups", user.Groups, "required_groups", creatorGroups)
			c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to create clusters. Required groups: " + strings.Join(creatorGroups, ", ")})
			return
		}
	}

	// Validate groups
	if isAdmin {
		// Admins can set any groups or leave empty
		slog.Info("Creating cluster with admin privileges", "username", user.Username, "cluster_name", req.Name, "groups", req.Groups, "user_groups", user.Groups)
	} else {
		// Non-admin users must assign at least one of their groups
		if req.Groups == "" {
			slog.Warn("Non-admin user attempted to create cluster without groups", "username", user.Username, "user_groups", user.Groups)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must assign at least one of your groups to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

		// Non-admin users can only assign groups they belong to
		requestedGroups := parseGroupsString(req.Groups)
		if len(requestedGroups) == 0 {
			slog.Warn("Non-admin user attempted to create cluster with empty groups", "username", user.Username, "user_groups", user.Groups)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must assign at least one of your groups to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

		userGroupMap := make(map[string]bool)
		for _, group := range user.Groups {
			userGroupMap[group] = true
		}

		// Check if user is requesting groups they don't belong to
		var invalidGroups []string
		for _, group := range requestedGroups {
			if !userGroupMap[group] {
				invalidGroups = append(invalidGroups, group)
			}
		}

		if len(invalidGroups) > 0 {
			slog.Warn("User attempted to assign groups they don't belong to", "username", user.Username, "user_groups", user.Groups, "requested_groups", requestedGroups, "invalid_groups", invalidGroups)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You can only assign groups you belong to",
				"invalid_groups": invalidGroups,
				"your_groups":    user.Groups,
			})
			return
		}

		slog.Info("Creating cluster with validated groups", "username", user.Username, "cluster_name", req.Name, "groups", req.Groups, "user_groups", user.Groups)
	}

	// Set creator information
	req.Creator = user.Username

	if err := s.manager.CreateCluster(c.Request.Context(), req); err != nil {
		slog.Error("Failed to create cluster", "username", user.Username, "cluster_name", req.Name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	c.JSON(http.StatusCreated, gin.H{
		"status": "created",
		"name":   req.Name,
		"user":   user.Username,
	})

	slog.Info("Cluster creation API response sent", "username", user.Username, "cluster_name", req.Name, "status", "created")
}

func (s *Server) handleDeleteCluster(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster deletion attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	name := c.Param("name")

	var bodyReq struct {
		Namespace string `json:"namespace"`
	}
	_ = c.ShouldBindJSON(&bodyReq)

	namespace := c.Query("namespace")
	if namespace == "" {
		namespace = bodyReq.Namespace
	}
	if namespace == "" {
		namespace = "capi-system"
	}

	// Check if user has access to this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == name && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to delete cluster without access", "username", user.Username, "cluster_name", name, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have access to this cluster"})
		return
	}

	// Check if user can modify this cluster
	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to delete cluster without modify permission", "username", user.Username, "cluster_name", name, "namespace", namespace, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have permission to delete this cluster"})
		return
	}

	slog.Info("Deleting cluster", "username", user.Username, "cluster_name", name, "namespace", namespace)

	if err := s.manager.DeleteCluster(c.Request.Context(), name, namespace); err != nil {
		slog.Error("Failed to delete cluster", "username", user.Username, "cluster_name", name, "namespace", namespace, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	c.JSON(http.StatusOK, gin.H{
		"status": "deleted",
		"name":   name,
		"user":   user.Username,
	})

	slog.Info("Cluster deletion API response sent", "username", user.Username, "cluster_name", name, "namespace", namespace, "status", "deleted")
}

func (s *Server) handleDownloadKubeconfig(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized kubeconfig download attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	clusterName := c.Param("name")

	namespace := c.Query("namespace")
	if namespace == "" {
		namespace = "capi-system"
	}

	// Check if user has access to this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to download kubeconfig for cluster without access", "username", user.Username, "cluster_name", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have access to this cluster"})
		return
	}

	slog.Info("Generating kubeconfig", "username", user.Username, "cluster_name", clusterName, "namespace", namespace)

	// Generate kubeconfig with OIDC authentication
	kubeconfigContent, err := s.kubeconfigGen.GenerateKubeconfig(c.Request.Context(), targetCluster, user.Username, user.Groups)
	if err != nil {
		slog.Error("Failed to generate kubeconfig", "username", user.Username, "cluster_name", clusterName, "namespace", namespace, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate kubeconfig: %v", err)})
		return
	}

	// Set headers for file download
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-kubeconfig.yaml\"", clusterName))
	c.Header("Content-Length", fmt.Sprintf("%d", len(kubeconfigContent)))

	// Write kubeconfig content
	c.String(http.StatusOK, kubeconfigContent)

	slog.Info("Kubeconfig downloaded successfully", "username", user.Username, "cluster_name", clusterName, "namespace", namespace, "file_size", len(kubeconfigContent))
}

func (s *Server) handleHealth(c *gin.Context) {
	slog.Debug("Health check requested", "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))

	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func (s *Server) handleGetVersions(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Getting available Kubernetes versions", "username", getUsernameOrAnon(user))

	versions := viper.GetStringSlice("cluster.available_versions")
	if len(versions) == 0 {
		slog.Warn("No available versions configured, using default")
		versions = []string{"v1.34.0", "v1.33.2", "v1.32.5", "v1.31.8"}
	}

	slog.Debug("Returning available versions", "username", getUsernameOrAnon(user), "version_count", len(versions))

	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

func (s *Server) handleGetUserGroups(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized access to user groups", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if user is admin
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}

	isAdmin := false
	for _, adminGroup := range adminGroups {
		for _, userGroup := range user.Groups {
			if userGroup == adminGroup {
				isAdmin = true
				break
			}
		}
		if isAdmin {
			break
		}
	}

	slog.Debug("Returning user groups", "username", user.Username, "groups", user.Groups, "is_admin", isAdmin)

	c.JSON(http.StatusOK, gin.H{
		"groups":  user.Groups,
		"isAdmin": isAdmin,
	})
}

func (s *Server) handleGetUserPermissions(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized access to user permissions", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if user is admin
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Check if user can create clusters (admins can always create)
	canCreate := isAdmin
	if !canCreate {
		creatorGroups := viper.GetStringSlice("cluster.creator_groups")
		if len(creatorGroups) == 0 {
			// Fallback to admin groups if creator groups not configured
			creatorGroups = adminGroups
		}
		canCreate = auth.CheckUserGroups(user.Groups, creatorGroups)
	}

	slog.Debug("Returning user permissions", "username", user.Username, "can_create", canCreate, "is_admin", isAdmin)

	c.JSON(http.StatusOK, gin.H{
		"canCreate": canCreate,
		"isAdmin":   isAdmin,
	})
}

func (s *Server) handleGetLimits(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized access to limits", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get limits from config
	maxClusters := viper.GetInt("cluster.limits.max_clusters")
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")
	maxTotalCP := viper.GetInt("cluster.limits.max_total_cp")

	// Get current cluster count and total nodes
	clusters := s.watcher.GetClusters() // Get all Chihiro-managed clusters to count
	currentClusters := len(clusters)
	currentTotalNodes := int32(0)

	for _, cluster := range clusters {
		currentTotalNodes += cluster.Nodes
	}

	// Count current control plane replicas from cluster specs
	currentTotalCP, err := s.manager.CountControlPlaneReplicas(c.Request.Context())
	if err != nil {
		slog.Error("Failed to count control plane replicas for limits", "username", user.Username, "error", err)
		currentTotalCP = 0
	}

	slog.Debug("Returning limits info (Chihiro-managed clusters only)", "username", user.Username, "current_clusters", currentClusters, "max_clusters", maxClusters, "current_nodes", currentTotalNodes, "max_nodes", maxTotalNodes, "current_cp", currentTotalCP, "max_cp", maxTotalCP)

	c.JSON(http.StatusOK, gin.H{
		"maxClusters":       maxClusters,
		"currentClusters":   currentClusters,
		"maxTotalNodes":     maxTotalNodes,
		"currentTotalNodes": currentTotalNodes,
		"availableNodes":    maxTotalNodes - int(currentTotalNodes),
		"maxTotalCP":        maxTotalCP,
		"currentTotalCP":    currentTotalCP,
		"availableCP":       maxTotalCP - int(currentTotalCP),
	})
}

func (s *Server) handleGetClusterParameters(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	templateStr := viper.GetString("cluster.template")
	params := cluster.DiscoverParameters(templateStr)

	slog.Debug("Serving cluster parameters", "username", user.Username, "param_count", len(params))
	c.JSON(http.StatusOK, params)
}

func (s *Server) handleGetEditableFields(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	fields := cluster.GetEditableFields(viper.GetString("cluster.template"))

	slog.Debug("Serving editable cluster fields", "username", user.Username, "field_count", len(fields))
	c.JSON(http.StatusOK, fields)
}

func (s *Server) handleGetWorkerFlavors(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	flavors := viper.GetStringSlice("cluster.worker_flavors")
	slog.Debug("Serving worker flavors", "username", user.Username, "flavor_count", len(flavors))
	c.JSON(http.StatusOK, gin.H{"flavors": flavors})
}

func (s *Server) handleGetWorkerClasses(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	classes := viper.GetStringSlice("cluster.worker_classes")
	slog.Debug("Serving worker classes", "username", user.Username, "class_count", len(classes))
	c.JSON(http.StatusOK, gin.H{"classes": classes})
}

func (s *Server) handleEditClusterGroups(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster groups edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !s.fieldEditable(c, user, "groups") {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		Groups    string `json:"groups"`
		Namespace string `json:"namespace"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit groups request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Use namespace from request body if provided
	if req.Namespace != "" {
		namespace = req.Namespace
	}

	// Check if user has permission to modify this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to modify cluster without access", "username", user.Username, "cluster", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to modify groups without permission", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	// Check if user is admin for group validation
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Validate groups
	if isAdmin {
		// Admins can set any groups or leave empty
		slog.Debug("Admin user updating cluster groups", "username", user.Username, "cluster", clusterName, "groups", req.Groups)
	} else {
		// Non-admin users have restrictions on editing groups

		// Parse requested groups
		requestedGroups := parseGroupsString(req.Groups)
		if len(requestedGroups) == 0 {
			slog.Warn("Non-admin user attempted to update cluster with empty groups", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must assign at least one of your groups to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

		// Build user group map for efficient lookup
		userGroupMap := make(map[string]bool)
		for _, group := range user.Groups {
			userGroupMap[group] = true
		}

		// Get current cluster groups to check what's being changed
		currentClusterGroups := targetCluster.Groups
		currentGroupMap := make(map[string]bool)
		for _, group := range currentClusterGroups {
			currentGroupMap[group] = true
		}

		// Check 1: User can only add/keep groups they belong to
		var invalidGroups []string
		for _, group := range requestedGroups {
			if !userGroupMap[group] {
				invalidGroups = append(invalidGroups, group)
			}
		}

		if len(invalidGroups) > 0 {
			slog.Warn("User attempted to assign groups they don't belong to", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "requested_groups", requestedGroups, "invalid_groups", invalidGroups)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You can only assign groups you belong to",
				"invalid_groups": invalidGroups,
				"your_groups":    user.Groups,
			})
			return
		}

		// Check 2: User cannot remove groups they don't belong to (preserve groups user doesn't control)
		requestedGroupMap := make(map[string]bool)
		for _, group := range requestedGroups {
			requestedGroupMap[group] = true
		}

		var removedGroupsNotOwned []string
		for _, currentGroup := range currentClusterGroups {
			// If a group is in current cluster but not in requested list, it's being removed
			if !requestedGroupMap[currentGroup] {
				// Check if user owns this group
				if !userGroupMap[currentGroup] {
					removedGroupsNotOwned = append(removedGroupsNotOwned, currentGroup)
				}
			}
		}

		if len(removedGroupsNotOwned) > 0 {
			slog.Warn("User attempted to remove groups they don't belong to", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "removed_groups", removedGroupsNotOwned)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You cannot remove groups you don't belong to. You can only manage your own groups.",
				"removed_groups": removedGroupsNotOwned,
				"your_groups":    user.Groups,
			})
			return
		}

		// Check 3: User must keep at least one of their own groups
		hasOwnGroup := false
		for _, group := range requestedGroups {
			if userGroupMap[group] {
				hasOwnGroup = true
				break
			}
		}

		if !hasOwnGroup {
			slog.Warn("Non-admin user attempted to remove all their groups", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "requested_groups", requestedGroups)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must keep at least one of your groups assigned to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

		slog.Info("Non-admin user updating cluster groups", "username", user.Username, "cluster", clusterName, "old_groups", currentClusterGroups, "new_groups", requestedGroups, "user_groups", user.Groups)
	}

	if err := s.manager.UpdateClusterGroups(c.Request.Context(), clusterName, namespace, req.Groups); err != nil {
		slog.Error("Failed to update cluster groups", "username", user.Username, "cluster", clusterName, "namespace", namespace, "groups", req.Groups, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster groups updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "groups", req.Groups)

	c.JSON(http.StatusOK, gin.H{
		"status":  "updated",
		"cluster": clusterName,
		"groups":  req.Groups,
	})
}

func (s *Server) handleEditClusterNodes(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster nodes edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !s.fieldEditable(c, user, "nodes") {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		Nodes int32 `json:"nodes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit nodes request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate node count
	if req.Nodes < 1 {
		slog.Warn("Invalid node count requested", "username", user.Username, "cluster", clusterName, "nodes", req.Nodes)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node count must be at least 1"})
		return
	}

	// Check if user has permission to modify this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to modify cluster without access", "username", user.Username, "cluster", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to modify node count without permission", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterNodeCount(c.Request.Context(), clusterName, namespace, req.Nodes); err != nil {
		slog.Error("Failed to update cluster node count", "username", user.Username, "cluster", clusterName, "namespace", namespace, "nodes", req.Nodes, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster node count updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "nodes", req.Nodes)

	c.JSON(http.StatusOK, gin.H{
		"status":  "updated",
		"cluster": clusterName,
		"nodes":   req.Nodes,
	})
}

func (s *Server) handleEditWorkerGroups(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized worker groups edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !s.fieldEditable(c, user, "workerGroups") {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		Namespace    string                `json:"namespace"`
		WorkerGroups []cluster.WorkerGroup `json:"workerGroups"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit worker groups request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Namespace != "" {
		namespace = req.Namespace
	}

	// Validate: at least one group required
	if len(req.WorkerGroups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one worker group is required"})
		return
	}

	// Check if user has permission to modify this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to modify cluster without access", "username", user.Username, "cluster", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to modify worker groups without permission", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterWorkerGroups(c.Request.Context(), clusterName, namespace, req.WorkerGroups); err != nil {
		slog.Error("Failed to update cluster worker groups", "username", user.Username, "cluster", clusterName, "namespace", namespace, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster worker groups updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "groups", len(req.WorkerGroups))

	c.JSON(http.StatusOK, gin.H{
		"status":  "updated",
		"cluster": clusterName,
	})
}

func (s *Server) handleEditClusterControlPlane(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster control plane edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !s.fieldEditable(c, user, "controlPlaneReplicas") {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		ControlPlaneReplicas int32 `json:"controlPlaneReplicas"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit control plane request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.ControlPlaneReplicas < 1 {
		slog.Warn("Invalid control plane replica count requested", "username", user.Username, "cluster", clusterName, "replicas", req.ControlPlaneReplicas)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Control plane replicas must be at least 1"})
		return
	}

	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to modify cluster without access", "username", user.Username, "cluster", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to modify control plane replicas without permission", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterControlPlaneReplicas(c.Request.Context(), clusterName, namespace, req.ControlPlaneReplicas); err != nil {
		slog.Error("Failed to update cluster control plane replicas", "username", user.Username, "cluster", clusterName, "namespace", namespace, "replicas", req.ControlPlaneReplicas, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster control plane replicas updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "replicas", req.ControlPlaneReplicas)

	c.JSON(http.StatusOK, gin.H{
		"status":               "updated",
		"cluster":              clusterName,
		"controlPlaneReplicas": req.ControlPlaneReplicas,
	})
}

func (s *Server) handleEditClusterVersion(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster version edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	if !s.fieldEditable(c, user, "version") {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		Version string `json:"version"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit version request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate version format and non-empty
	if req.Version == "" {
		slog.Warn("Empty version requested", "username", user.Username, "cluster", clusterName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Version cannot be empty"})
		return
	}

	// Check if user has permission to modify this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn("User attempted to modify cluster without access", "username", user.Username, "cluster", clusterName, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn("User attempted to modify version without permission", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "cluster_creator", targetCluster.Creator, "cluster_groups", targetCluster.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterVersion(c.Request.Context(), clusterName, namespace, req.Version); err != nil {
		slog.Error("Failed to update cluster version", "username", user.Username, "cluster", clusterName, "namespace", namespace, "version", req.Version, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster version updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "version", req.Version)

	c.JSON(http.StatusOK, gin.H{
		"status":  "updated",
		"cluster": clusterName,
		"version": req.Version,
	})
}

// Helper function to get username or "anonymous" for logging
func getUsernameOrAnon(user *auth.UserInfo) string {
	if user != nil && user.Username != "" {
		return user.Username
	}
	return "anonymous"
}

// Helper function to check if user can modify a cluster
// fieldEditable reports whether the given cluster field is opt-in editable per
// the editable flag on the matching cluster.parameters entry. When disabled it
// writes a 403 response and returns false so the caller can return early.
func (s *Server) fieldEditable(c *gin.Context, user *auth.UserInfo, field string) bool {
	f, ok := cluster.GetEditableField(viper.GetString("cluster.template"), field)
	if !ok || !f.Enabled {
		slog.Warn("Edit blocked: field is not editable in config", "username", user.Username, "field", field)
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("editing %q is disabled", field)})
		return false
	}
	return true
}

func (s *Server) canUserModifyCluster(user *auth.UserInfo, cluster *watcher.ClusterInfo) bool {
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	if isAdmin {
		return true
	}

	// User must be in creator groups to modify
	creatorGroups := viper.GetStringSlice("cluster.creator_groups")
	if len(creatorGroups) == 0 {
		creatorGroups = adminGroups
	}

	isCreatorGroupMember := auth.CheckUserGroups(user.Groups, creatorGroups)
	if !isCreatorGroupMember {
		return false
	}

	// Check if user is the creator OR shares a group with the cluster
	isCreator := cluster.Creator == user.Username
	sharesGroup := false
	for _, userGroup := range user.Groups {
		for _, clusterGroup := range cluster.Groups {
			if userGroup == clusterGroup {
				sharesGroup = true
				break
			}
		}
		if sharesGroup {
			break
		}
	}

	return isCreator || sharesGroup
}

// parseGroupsString parses a comma-separated groups string into a slice
func parseGroupsString(groupsStr string) []string {
	if groupsStr == "" {
		return nil
	}

	var groups []string
	for _, group := range strings.Split(groupsStr, ",") {
		trimmed := strings.TrimSpace(group)
		if trimmed != "" {
			groups = append(groups, trimmed)
		}
	}
	return groups
}

func (s *Server) handleFavicon(c *gin.Context) {
	c.File("web/static/favicon.ico")
}
