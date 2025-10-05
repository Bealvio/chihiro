package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/Bealvio/chihiro/internal/cluster"
	"github.com/Bealvio/chihiro/internal/kubeconfig"
	"github.com/Bealvio/chihiro/internal/middleware"
	"github.com/Bealvio/chihiro/internal/watcher"
)

type Server struct {
	watcher           *watcher.ClusterWatcher
	manager           *cluster.Manager
	auth              *auth.Middleware
	kubeconfigGen     *kubeconfig.Generator
	router            *gin.Engine
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

	kubeconfigGen := kubeconfig.NewGenerator(w.GetClient())

	s := &Server{
		watcher:       w,
		manager:       m,
		auth:          authMiddleware,
		kubeconfigGen: kubeconfigGen,
		router:        gin.New(),
	}

	s.setupRoutes()

	slog.Info("Server initialized successfully with all routes configured")
	return s
}

func (s *Server) Router() *gin.Engine {
	return s.router
}

func (s *Server) setupRoutes() {
	// Add custom recovery and logging middleware
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.securityHeadersMiddleware())
	s.router.Use(s.requestSizeLimitMiddleware())

	// Create rate limiters
	authRateLimiter := middleware.AuthRateLimiter()
	apiRateLimiter := middleware.APIRateLimiter()

	// Authentication routes (public) with strict rate limiting
	s.router.GET("/login", s.handleLoginPage)
	s.router.GET("/auth/login", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleLogin)
	s.router.GET("/auth/callback", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleCallback)
	s.router.GET("/auth/logout", s.auth.HandleLogout)
	s.router.GET("/health", s.handleHealth)

	// Protected routes with API rate limiting
	protected := s.router.Group("/")
	protected.Use(s.auth.RequireAuth())
	protected.Use(middleware.RateLimitMiddleware(apiRateLimiter))

	protected.GET("/", s.handleHome)
	protected.GET("/api/user", s.handleUserInfo)
	protected.GET("/api/clusters", s.handleAPI)
	protected.POST("/api/clusters", s.handleCreateCluster)
	protected.DELETE("/api/clusters/:name", s.handleDeleteCluster)
	protected.PUT("/api/clusters/:name/groups", s.handleEditClusterGroups)
	protected.PUT("/api/clusters/:name/nodes", s.handleEditClusterNodes)
	protected.PUT("/api/clusters/:name/version", s.handleEditClusterVersion)
	protected.GET("/api/clusters/:name/kubeconfig", s.handleDownloadKubeconfig)
	protected.GET("/api/ip-ranges/next", s.handleNextIPRange)
	protected.GET("/api/versions", s.handleGetVersions)
	protected.GET("/api/user/groups", s.handleGetUserGroups)
	protected.GET("/api/limits", s.handleGetLimits)
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

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, loginHTML)
}

func (s *Server) handleHome(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Serving dashboard page", "username", getUsernameOrAnon(user), "remote_addr", c.ClientIP())

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, dashboardHTML)
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

	// Validate groups unless user is admin
	if req.Groups != "" {
		if isAdmin {
			slog.Info("Creating cluster with admin privileges", "username", user.Username, "cluster_name", req.Name, "groups", req.Groups, "user_groups", user.Groups)
		} else {
			// Non-admin users can only assign groups they belong to
			requestedGroups := parseGroupsString(req.Groups)
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
					"error": "You can only assign groups you belong to",
					"invalid_groups": invalidGroups,
					"your_groups": user.Groups,
				})
				return
			}

			slog.Info("Creating cluster with validated groups", "username", user.Username, "cluster_name", req.Name, "groups", req.Groups, "user_groups", user.Groups)
		}
	} else {
		slog.Info("Creating cluster with default groups", "username", user.Username, "cluster_name", req.Name, "is_admin", isAdmin)
	}

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

	namespace := c.Query("namespace")
	if namespace == "" {
		namespace = "capi-system"
	}

	// Check if user has access to this cluster
	clusters := s.watcher.GetClustersForUser(user.Groups)
	canDelete := false
	for _, cluster := range clusters {
		if cluster.Name == name && cluster.Namespace == namespace {
			canDelete = true
			break
		}
	}

	if !canDelete {
		slog.Warn("User attempted to delete cluster without access", "username", user.Username, "cluster_name", name, "namespace", namespace, "user_groups", user.Groups)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have access to this cluster"})
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

func (s *Server) handleNextIPRange(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Getting next available IP range", "username", getUsernameOrAnon(user))

	ipRange, err := s.manager.GetNextAvailableIPRange(c.Request.Context())
	if err != nil {
		slog.Error("Failed to get next available IP range", "username", getUsernameOrAnon(user), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	slog.Debug("Returning next available IP range", "username", getUsernameOrAnon(user), "ip_range", ipRange)

	c.JSON(http.StatusOK, gin.H{"range": ipRange})
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
		"groups": user.Groups,
		"isAdmin": isAdmin,
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

	// Get current cluster count and total nodes
	clusters := s.watcher.GetClustersForUser([]string{}) // Get all clusters to count
	currentClusters := len(clusters)
	currentTotalNodes := int32(0)

	for _, cluster := range clusters {
		currentTotalNodes += cluster.Nodes
	}

	slog.Debug("Returning limits info (Chihiro-managed clusters only)", "username", user.Username, "current_clusters", currentClusters, "max_clusters", maxClusters, "current_nodes", currentTotalNodes, "max_nodes", maxTotalNodes)

	c.JSON(http.StatusOK, gin.H{
		"maxClusters": maxClusters,
		"currentClusters": currentClusters,
		"maxTotalNodes": maxTotalNodes,
		"currentTotalNodes": currentTotalNodes,
		"availableNodes": maxTotalNodes - int(currentTotalNodes),
	})
}

func (s *Server) handleEditClusterGroups(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster groups edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	var req struct {
		Groups string `json:"groups"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit groups request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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

	// Validate groups unless user is admin
	if req.Groups != "" && !isAdmin {
		// Non-admin users can only assign groups they belong to
		requestedGroups := parseGroupsString(req.Groups)
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
			slog.Warn("User attempted to assign groups they don't belong to", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups, "requested_groups", requestedGroups, "invalid_groups", invalidGroups)
			c.JSON(http.StatusForbidden, gin.H{
				"error": "You can only assign groups you belong to",
				"invalid_groups": invalidGroups,
				"your_groups": user.Groups,
			})
			return
		}
	}

	if err := s.manager.UpdateClusterGroups(c.Request.Context(), clusterName, namespace, req.Groups); err != nil {
		slog.Error("Failed to update cluster groups", "username", user.Username, "cluster", clusterName, "namespace", namespace, "groups", req.Groups, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster groups updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "groups", req.Groups, "is_admin", isAdmin)

	c.JSON(http.StatusOK, gin.H{
		"status": "updated",
		"cluster": clusterName,
		"groups": req.Groups,
	})
}

func (s *Server) handleEditClusterNodes(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster nodes edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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

	// Check if user is admin
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Non-admin users need to have access to the cluster to modify it
	if !isAdmin {
		clusters := s.watcher.GetClustersForUser(user.Groups)
		hasAccess := false
		for _, cluster := range clusters {
			if cluster.Name == clusterName {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			slog.Warn("User attempted to modify node count for cluster without access", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	if err := s.manager.UpdateClusterNodeCount(c.Request.Context(), clusterName, namespace, req.Nodes); err != nil {
		slog.Error("Failed to update cluster node count", "username", user.Username, "cluster", clusterName, "namespace", namespace, "nodes", req.Nodes, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster node count updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "nodes", req.Nodes, "is_admin", isAdmin)

	c.JSON(http.StatusOK, gin.H{
		"status": "updated",
		"cluster": clusterName,
		"nodes": req.Nodes,
	})
}

func (s *Server) handleEditClusterVersion(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster version edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
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

	// Check if user is admin
	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	// Non-admin users need to have access to the cluster to modify it
	if !isAdmin {
		clusters := s.watcher.GetClustersForUser(user.Groups)
		hasAccess := false
		for _, cluster := range clusters {
			if cluster.Name == clusterName {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			slog.Warn("User attempted to modify version for cluster without access", "username", user.Username, "cluster", clusterName, "user_groups", user.Groups)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	if err := s.manager.UpdateClusterVersion(c.Request.Context(), clusterName, namespace, req.Version); err != nil {
		slog.Error("Failed to update cluster version", "username", user.Username, "cluster", clusterName, "namespace", namespace, "version", req.Version, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Force immediate refresh and broadcast to all connected clients
	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info("Cluster version updated successfully", "username", user.Username, "cluster", clusterName, "namespace", namespace, "version", req.Version, "is_admin", isAdmin)

	c.JSON(http.StatusOK, gin.H{
		"status": "updated",
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