package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/Bealvio/chihiro/internal/auth"
	"github.com/Bealvio/chihiro/internal/cluster"
	"github.com/Bealvio/chihiro/internal/watcher"
)

func (s *Server) handleLoginPage(c *gin.Context) {
	slog.Debug("Serving login page", "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))
	c.HTML(http.StatusOK, "login.html", nil)
}

func (s *Server) handleHome(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Serving dashboard page", "username", getUsernameOrAnon(user), "remote_addr", c.ClientIP())
	c.HTML(http.StatusOK, "dashboard.html", nil)
}

func (s *Server) handleHealth(c *gin.Context) {
	slog.Debug("Health check requested", "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func (s *Server) handleFavicon(c *gin.Context) {
	c.File("web/static/favicon.ico")
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

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

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

	docsURL := viper.GetString("docs_url")
	if env := os.Getenv("CHIHIRO_DOCS_URL"); env != "" {
		docsURL = env
	}

	slog.Debug("Serving config", "username", user.Username, "docs_url", docsURL)
	c.JSON(http.StatusOK, gin.H{
		"docsUrl": docsURL,
	})
}

func (s *Server) handleGetVersions(c *gin.Context) {
	user, _ := auth.GetUserFromContext(c.Request.Context())
	slog.Debug("Getting available Kubernetes versions", "username", getUsernameOrAnon(user))

	versions := viper.GetStringSlice("cluster.available_versions")
	if len(versions) == 0 {
		slog.Warn("No available versions configured, using default")
		versions = []string{"v1.34.0", "v1.33.2", "v1.32.5", "v1.31.8"}
	}

	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

func (s *Server) handleGetUserGroups(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized access to user groups", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}

	isAdmin := false
	for _, adminGroup := range adminGroups {
		if slices.Contains(user.Groups, adminGroup) {
			isAdmin = true
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

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	canCreate := isAdmin
	if !canCreate {
		creatorGroups := viper.GetStringSlice("cluster.creator_groups")
		if len(creatorGroups) == 0 {
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

	maxClusters := viper.GetInt("cluster.limits.max_clusters")
	maxTotalNodes := viper.GetInt("cluster.limits.max_total_nodes")
	maxTotalCP := viper.GetInt("cluster.limits.max_total_cp")

	clusters := s.watcher.GetClusters()
	currentClusters := len(clusters)
	currentTotalNodes := int32(0)

	for _, cluster := range clusters {
		currentTotalNodes += cluster.Nodes
	}

	currentTotalCP, err := s.manager.CountControlPlaneReplicas(c.Request.Context())
	if err != nil {
		slog.Error("Failed to count control plane replicas for limits", "username", user.Username, "error", err)
		currentTotalCP = 0
	}

	slog.Debug(
		"Returning limits info",
		"username",
		user.Username,
		"current_clusters",
		currentClusters,
		"max_clusters",
		maxClusters,
		"current_nodes",
		currentTotalNodes,
		"max_nodes",
		maxTotalNodes,
		"current_cp",
		currentTotalCP,
		"max_cp",
		maxTotalCP,
	)
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

	// ?all=true returns every parameter regardless of visible_groups.
	if c.Query("all") != "true" {
		params = cluster.FilterParametersByGroups(params, user.Groups)
	}

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

	var filtered []cluster.EditableField
	for _, f := range fields {
		if cluster.UserCanEditField(f.VisibleGroups, user.Groups) {
			filtered = append(filtered, f)
		}
	}

	slog.Debug("Serving editable cluster fields", "username", user.Username, "field_count", len(filtered))
	c.JSON(http.StatusOK, filtered)
}

func (s *Server) handleGetWorkerGroupFields(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	fields := cluster.LoadWorkerGroupFields()
	fields = cluster.FilterWorkerGroupFieldsByGroups(fields, user.Groups)
	slog.Debug("Serving worker group fields", "username", user.Username, "field_count", len(fields))
	c.JSON(http.StatusOK, gin.H{"fields": fields})
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

	_ = conn.SetReadDeadline(time.Now().Add(watcher.WSPongWait()))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(watcher.WSPongWait()))
	})

	pingTicker := time.NewTicker(watcher.WSPingPeriod())
	defer pingTicker.Stop()
	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		for {
			select {
			case <-pingTicker.C:
				if err := s.watcher.PingClient(conn); err != nil {
					slog.Debug("WebSocket ping failed, closing connection", "username", user.Username, "error", err)
					conn.Close()
					return
				}
			case <-stopPing:
				return
			}
		}
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

	if !clusterNameRegex.MatchString(req.Name) {
		slog.Warn("Invalid cluster name format", "username", user.Username, "cluster_name", req.Name)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster name format. Must be lowercase alphanumeric with hyphens"})
		return
	}

	if bad := validateGroupNames(parseGroupsString(req.Groups)); bad != "" {
		slog.Warn("Invalid group name in cluster creation", "username", user.Username, "cluster_name", req.Name, "group", bad)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group name: only letters, digits and _.:/@- are allowed"})
		return
	}

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}

	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	if !isAdmin {
		creatorGroups := viper.GetStringSlice("cluster.creator_groups")
		if len(creatorGroups) == 0 {
			creatorGroups = adminGroups
		}

		canCreate := auth.CheckUserGroups(user.Groups, creatorGroups)
		if !canCreate {
			slog.Warn(
				"User attempted to create cluster without permission",
				"username",
				user.Username,
				"user_groups",
				user.Groups,
				"required_groups",
				creatorGroups,
			)
			c.JSON(
				http.StatusForbidden,
				gin.H{"error": "You don't have permission to create clusters. Required groups: " + strings.Join(creatorGroups, ", ")},
			)
			return
		}
	}

	if isAdmin {
		slog.Info(
			"Creating cluster with admin privileges",
			"username",
			user.Username,
			"cluster_name",
			req.Name,
			"groups",
			req.Groups,
			"user_groups",
			user.Groups,
		)
	} else {
		if req.Groups == "" {
			slog.Warn("Non-admin user attempted to create cluster without groups", "username", user.Username, "user_groups", user.Groups)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must assign at least one of your groups to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

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

		var invalidGroups []string
		for _, group := range requestedGroups {
			if !userGroupMap[group] {
				invalidGroups = append(invalidGroups, group)
			}
		}

		if len(invalidGroups) > 0 {
			slog.Warn(
				"User attempted to assign groups they don't belong to",
				"username",
				user.Username,
				"user_groups",
				user.Groups,
				"requested_groups",
				requestedGroups,
				"invalid_groups",
				invalidGroups,
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You can only assign groups you belong to",
				"invalid_groups": invalidGroups,
				"your_groups":    user.Groups,
			})
			return
		}

		slog.Info(
			"Creating cluster with validated groups",
			"username",
			user.Username,
			"cluster_name",
			req.Name,
			"groups",
			req.Groups,
			"user_groups",
			user.Groups,
		)
	}

	req.Creator = user.Username

	if err := s.manager.CreateCluster(c.Request.Context(), req); err != nil {
		slog.Error("Failed to create cluster", "username", user.Username, "cluster_name", req.Name, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	c.JSON(http.StatusCreated, gin.H{
		"status": "created",
		"name":   req.Name,
		"user":   user.Username,
	})

	slog.Info("Cluster creation API response sent", "username", user.Username, "cluster_name", req.Name, "status", "created")
}

// handlePreviewCluster renders the cluster template for the supplied form values
// and returns the resulting manifest as YAML, without creating anything.
func (s *Server) handlePreviewCluster(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster preview attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req cluster.CreateClusterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid cluster preview request body", "username", user.Username, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if !clusterNameRegex.MatchString(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cluster name format. Must be lowercase alphanumeric with hyphens"})
		return
	}

	if bad := validateGroupNames(parseGroupsString(req.Groups)); bad != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group name: only letters, digits and _.:/@- are allowed"})
		return
	}

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	if len(adminGroups) == 0 {
		adminGroups = []string{"cluster-admin"}
	}
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)
	if !isAdmin {
		creatorGroups := viper.GetStringSlice("cluster.creator_groups")
		if len(creatorGroups) == 0 {
			creatorGroups = adminGroups
		}
		if !auth.CheckUserGroups(user.Groups, creatorGroups) {
			slog.Warn("User attempted to preview cluster without create permission", "username", user.Username, "user_groups", user.Groups)
			c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to create clusters"})
			return
		}

		requestedGroups := parseGroupsString(req.Groups)
		userGroupMap := make(map[string]bool, len(user.Groups))
		for _, g := range user.Groups {
			userGroupMap[g] = true
		}
		for _, g := range requestedGroups {
			if !userGroupMap[g] {
				c.JSON(http.StatusForbidden, gin.H{"error": "You can only assign groups you belong to"})
				return
			}
		}
	}

	req.Creator = user.Username

	yamlOut, err := s.manager.PreviewCluster(c.Request.Context(), req)
	if err != nil {
		slog.Error("Failed to render cluster preview", "username", user.Username, "cluster_name", req.Name, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	slog.Debug("Served cluster YAML preview", "username", user.Username, "cluster_name", req.Name)
	c.JSON(http.StatusOK, gin.H{"yaml": yamlOut})
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

	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == name && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn(
			"User attempted to delete cluster without access",
			"username",
			user.Username,
			"cluster_name",
			name,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have access to this cluster"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to delete cluster without modify permission",
			"username",
			user.Username,
			"cluster_name",
			name,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have permission to delete this cluster"})
		return
	}

	slog.Info("Deleting cluster", "username", user.Username, "cluster_name", name, "namespace", namespace)

	if err := s.manager.DeleteCluster(c.Request.Context(), name, namespace); err != nil {
		slog.Error("Failed to delete cluster", "username", user.Username, "cluster_name", name, "namespace", namespace, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	c.JSON(http.StatusOK, gin.H{
		"status": "deleted",
		"name":   name,
		"user":   user.Username,
	})

	slog.Info(
		"Cluster deletion API response sent",
		"username",
		user.Username,
		"cluster_name",
		name,
		"namespace",
		namespace,
		"status",
		"deleted",
	)
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

	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}

	if targetCluster == nil {
		slog.Warn(
			"User attempted to download kubeconfig for cluster without access",
			"username",
			user.Username,
			"cluster_name",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You don't have access to this cluster"})
		return
	}

	slog.Info("Generating kubeconfig", "username", user.Username, "cluster_name", clusterName, "namespace", namespace)

	kubeconfigContent, err := s.kubeconfigGen.GenerateKubeconfig(c.Request.Context(), targetCluster, user.Username, user.Groups)
	if err != nil {
		slog.Error(
			"Failed to generate kubeconfig",
			"username",
			user.Username,
			"cluster_name",
			clusterName,
			"namespace",
			namespace,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate kubeconfig: %v", err)})
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-kubeconfig.yaml\"", clusterName))
	c.Header("Content-Length", fmt.Sprintf("%d", len(kubeconfigContent)))
	c.String(http.StatusOK, kubeconfigContent)

	slog.Info(
		"Kubeconfig downloaded successfully",
		"username",
		user.Username,
		"cluster_name",
		clusterName,
		"namespace",
		namespace,
		"file_size",
		len(kubeconfigContent),
	)
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

	if req.Namespace != "" {
		namespace = req.Namespace
	}

	if bad := validateGroupNames(parseGroupsString(req.Groups)); bad != "" {
		slog.Warn("Invalid group name in groups edit", "username", user.Username, "cluster", clusterName, "group", bad)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid group name: only letters, digits and _.:/@- are allowed"})
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
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify groups without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	adminGroups := viper.GetStringSlice("cluster.admin_groups")
	isAdmin := auth.CheckUserGroups(user.Groups, adminGroups)

	if isAdmin {
		slog.Debug("Admin user updating cluster groups", "username", user.Username, "cluster", clusterName, "groups", req.Groups)
	} else {
		requestedGroups := parseGroupsString(req.Groups)
		if len(requestedGroups) == 0 {
			slog.Warn(
				"Non-admin user attempted to update cluster with empty groups",
				"username",
				user.Username,
				"cluster",
				clusterName,
				"user_groups",
				user.Groups,
			)
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

		currentClusterGroups := targetCluster.Groups

		var invalidGroups []string
		for _, group := range requestedGroups {
			if !userGroupMap[group] {
				invalidGroups = append(invalidGroups, group)
			}
		}

		if len(invalidGroups) > 0 {
			slog.Warn(
				"User attempted to assign groups they don't belong to",
				"username",
				user.Username,
				"cluster",
				clusterName,
				"user_groups",
				user.Groups,
				"requested_groups",
				requestedGroups,
				"invalid_groups",
				invalidGroups,
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You can only assign groups you belong to",
				"invalid_groups": invalidGroups,
				"your_groups":    user.Groups,
			})
			return
		}

		requestedGroupMap := make(map[string]bool)
		for _, group := range requestedGroups {
			requestedGroupMap[group] = true
		}

		var removedGroupsNotOwned []string
		for _, currentGroup := range currentClusterGroups {
			if !requestedGroupMap[currentGroup] {
				if !userGroupMap[currentGroup] {
					removedGroupsNotOwned = append(removedGroupsNotOwned, currentGroup)
				}
			}
		}

		if len(removedGroupsNotOwned) > 0 {
			slog.Warn(
				"User attempted to remove groups they don't belong to",
				"username",
				user.Username,
				"cluster",
				clusterName,
				"user_groups",
				user.Groups,
				"removed_groups",
				removedGroupsNotOwned,
			)
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "You cannot remove groups you don't belong to. You can only manage your own groups.",
				"removed_groups": removedGroupsNotOwned,
				"your_groups":    user.Groups,
			})
			return
		}

		hasOwnGroup := false
		for _, group := range requestedGroups {
			if userGroupMap[group] {
				hasOwnGroup = true
				break
			}
		}

		if !hasOwnGroup {
			slog.Warn(
				"Non-admin user attempted to remove all their groups",
				"username",
				user.Username,
				"cluster",
				clusterName,
				"user_groups",
				user.Groups,
				"requested_groups",
				requestedGroups,
			)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You must keep at least one of your groups assigned to the cluster",
				"your_groups": user.Groups,
			})
			return
		}

		slog.Info(
			"Non-admin user updating cluster groups",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"old_groups",
			currentClusterGroups,
			"new_groups",
			requestedGroups,
			"user_groups",
			user.Groups,
		)
	}

	if err := s.manager.UpdateClusterGroups(c.Request.Context(), clusterName, namespace, req.Groups); err != nil {
		slog.Error(
			"Failed to update cluster groups",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"groups",
			req.Groups,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster groups updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"groups",
		req.Groups,
	)
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

	if req.Nodes < 1 {
		slog.Warn("Invalid node count requested", "username", user.Username, "cluster", clusterName, "nodes", req.Nodes)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Node count must be at least 1"})
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
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify node count without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterNodeCount(c.Request.Context(), clusterName, namespace, req.Nodes); err != nil {
		slog.Error(
			"Failed to update cluster node count",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"nodes",
			req.Nodes,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster node count updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"nodes",
		req.Nodes,
	)
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

	if len(req.WorkerGroups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one worker group is required"})
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
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify worker groups without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterWorkerGroups(c.Request.Context(), clusterName, namespace, req.WorkerGroups); err != nil {
		slog.Error(
			"Failed to update cluster worker groups",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster worker groups updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"groups",
		len(req.WorkerGroups),
	)
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
		slog.Warn(
			"Invalid control plane replica count requested",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"replicas",
			req.ControlPlaneReplicas,
		)
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
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify control plane replicas without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterControlPlaneReplicas(
		c.Request.Context(),
		clusterName,
		namespace,
		req.ControlPlaneReplicas,
	); err != nil {
		slog.Error(
			"Failed to update cluster control plane replicas",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"replicas",
			req.ControlPlaneReplicas,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster control plane replicas updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"replicas",
		req.ControlPlaneReplicas,
	)
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

	var req struct {
		Namespace string `json:"namespace"`
		Version   string `json:"version"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit version request body", "username", user.Username, "cluster", clusterName, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = "capi-system"
	}

	if req.Version == "" {
		slog.Warn("Empty version requested", "username", user.Username, "cluster", clusterName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Version cannot be empty"})
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
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify version without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"user_groups",
			user.Groups,
			"cluster_creator",
			targetCluster.Creator,
			"cluster_groups",
			targetCluster.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterVersion(c.Request.Context(), clusterName, namespace, req.Version); err != nil {
		slog.Error(
			"Failed to update cluster version",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"version",
			req.Version,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster version updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"version",
		req.Version,
	)
	c.JSON(http.StatusOK, gin.H{
		"status":  "updated",
		"cluster": clusterName,
		"version": req.Version,
	})
}

func (s *Server) handleEditClusterParameter(c *gin.Context) {
	user, ok := auth.GetUserFromContext(c.Request.Context())
	if !ok {
		slog.Warn("Unauthorized cluster parameter edit attempt", "remote_addr", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error("Invalid edit parameter request body", "username", user.Username, "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parameter key is required"})
		return
	}

	if !s.fieldEditable(c, user, req.Key) {
		return
	}

	clusterName := c.Param("name")
	namespace := c.DefaultQuery("namespace", "capi-system")

	clusters := s.watcher.GetClustersForUser(user.Groups)
	var targetCluster *watcher.ClusterInfo
	for _, cluster := range clusters {
		if cluster.Name == clusterName && cluster.Namespace == namespace {
			targetCluster = cluster
			break
		}
	}
	if targetCluster == nil {
		slog.Warn(
			"User attempted to modify cluster without access",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"user_groups",
			user.Groups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}
	if !s.canUserModifyCluster(user, targetCluster) {
		slog.Warn(
			"User attempted to modify parameter without permission",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"parameter",
			req.Key,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify this cluster"})
		return
	}

	if err := s.manager.UpdateClusterParameter(c.Request.Context(), clusterName, namespace, req.Key, req.Value); err != nil {
		slog.Error(
			"Failed to update cluster parameter",
			"username",
			user.Username,
			"cluster",
			clusterName,
			"namespace",
			namespace,
			"parameter",
			req.Key,
			"error",
			err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.watcher.RefreshAndBroadcast(c.Request.Context())

	slog.Info(
		"Cluster parameter updated successfully",
		"username",
		user.Username,
		"cluster",
		clusterName,
		"namespace",
		namespace,
		"parameter",
		req.Key,
	)
	c.JSON(http.StatusOK, gin.H{
		"status":    "updated",
		"cluster":   clusterName,
		"parameter": req.Key,
		"value":     req.Value,
	})
}
