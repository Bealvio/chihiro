package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
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

// groupNameRegex restricts access-group names to a conservative charset as
// defense-in-depth against stored XSS via cluster annotations.
var groupNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,253}$`)

func validateGroupNames(groups []string) string {
	for _, g := range groups {
		if !groupNameRegex.MatchString(g) {
			return g
		}
	}
	return ""
}

func NewServer(w *watcher.ClusterWatcher, m *cluster.Manager, authMiddleware *auth.Middleware) *Server {
	slog.Info("Initializing server with routes and middleware")

	gin.SetMode(gin.ReleaseMode)

	if os.Getenv("DEBUG") == "" {
		gin.DefaultWriter = io.Discard
		gin.DefaultErrorWriter = io.Discard
	}

	kubeconfigGen := kubeconfig.NewGenerator(w.GetClient(), w.GetResolver())
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

// Close stops background goroutines started by the server. Safe to call once
// during shutdown.
func (s *Server) Close() {
	if s.stopCleanup != nil {
		close(s.stopCleanup)
	}
}

func (s *Server) setupRoutes() {
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.securityHeadersMiddleware())
	s.router.Use(s.requestSizeLimitMiddleware())

	s.router.LoadHTMLGlob("web/templates/*")
	s.router.Static("/static", "web/static")

	authRateLimiter := middleware.AuthRateLimiter()
	apiRateLimiter := middleware.APIRateLimiter()
	authRateLimiter.StartCleanup(5*time.Minute, 15*time.Minute, s.stopCleanup)
	apiRateLimiter.StartCleanup(5*time.Minute, 15*time.Minute, s.stopCleanup)

	s.router.GET("/login", s.handleLoginPage)
	s.router.GET("/auth/login", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleLogin)
	s.router.GET("/auth/callback", middleware.RateLimitMiddleware(authRateLimiter), s.auth.HandleCallback)
	s.router.GET("/auth/logout", s.auth.HandleLogout)
	s.router.GET("/health", s.handleHealth)
	s.router.GET("/favicon.ico", s.handleFavicon)

	protected := s.router.Group("/")
	protected.Use(s.auth.RequireAuth())
	protected.Use(middleware.RateLimitMiddleware(apiRateLimiter))

	protected.GET("/", s.handleHome)
	protected.GET("/api/user", s.handleUserInfo)
	protected.GET("/api/config", s.handleGetConfig)
	protected.GET("/api/clusters", s.handleAPI)
	protected.POST("/api/clusters", s.handleCreateCluster)
	protected.POST("/api/clusters/preview", s.handlePreviewCluster)
	protected.DELETE("/api/clusters/:name", s.handleDeleteCluster)
	protected.PUT("/api/clusters/:name/groups", s.handleEditClusterGroups)
	protected.PUT("/api/clusters/:name/nodes", s.handleEditClusterNodes)
	protected.PUT("/api/clusters/:name/worker-groups", s.handleEditWorkerGroups)
	protected.PUT("/api/clusters/:name/control-plane", s.handleEditClusterControlPlane)
	protected.PUT("/api/clusters/:name/version", s.handleEditClusterVersion)
	protected.PUT("/api/clusters/:name/parameter", s.handleEditClusterParameter)
	protected.GET("/api/clusters/:name/kubeconfig", s.handleDownloadKubeconfig)
	protected.GET("/api/versions", s.handleGetVersions)
	protected.GET("/api/user/groups", s.handleGetUserGroups)
	protected.GET("/api/user/permissions", s.handleGetUserPermissions)
	protected.GET("/api/limits", s.handleGetLimits)
	protected.GET("/api/cluster/parameters", s.handleGetClusterParameters)
	protected.GET("/api/cluster/editable", s.handleGetEditableFields)
	protected.GET("/api/cluster/worker-group-fields", s.handleGetWorkerGroupFields)
	protected.GET("/ws", s.handleWebSocket)
}

func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		slog.Debug(
			"HTTP request",
			"method",
			c.Request.Method,
			"path",
			c.Request.URL.Path,
			"remote_addr",
			c.ClientIP(),
			"user_agent",
			c.Request.Header.Get("User-Agent"),
		)
		c.Next()
	}
}

func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:",
		)
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-XSS-Protection", "1; mode=block")
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

func (s *Server) requestSizeLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1048576)
		c.Next()
	}
}

func getUsernameOrAnon(user *auth.UserInfo) string {
	if user != nil && user.Username != "" {
		return user.Username
	}
	return "anonymous"
}

// fieldEditable reports whether the given cluster field is opt-in editable per
// the editable flag on the matching cluster.parameters entry.
func (s *Server) fieldEditable(c *gin.Context, user *auth.UserInfo, field string) bool {
	f, ok := cluster.GetEditableField(viper.GetString("cluster.template"), field)
	if !ok || !f.Enabled {
		slog.Warn("Edit blocked: field is not editable in config", "username", user.Username, "field", field)
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("editing %q is disabled", field)})
		return false
	}
	if !cluster.UserCanEditField(f.VisibleGroups, user.Groups) {
		slog.Warn(
			"Edit blocked: user not in visible_groups",
			"username",
			user.Username,
			"field",
			field,
			"user_groups",
			user.Groups,
			"visible_groups",
			f.VisibleGroups,
		)
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("editing %q is not permitted for your groups", field)})
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

	creatorGroups := viper.GetStringSlice("cluster.creator_groups")
	if len(creatorGroups) == 0 {
		creatorGroups = adminGroups
	}

	isCreatorGroupMember := auth.CheckUserGroups(user.Groups, creatorGroups)
	if !isCreatorGroupMember {
		return false
	}

	isCreator := cluster.Creator == user.Username
	sharesGroup := false
	for _, userGroup := range user.Groups {
		if slices.Contains(cluster.Groups, userGroup) {
			sharesGroup = true
		}
		if sharesGroup {
			break
		}
	}

	return isCreator || sharesGroup
}

func parseGroupsString(groupsStr string) []string {
	if groupsStr == "" {
		return nil
	}

	var groups []string
	for group := range strings.SplitSeq(groupsStr, ",") {
		trimmed := strings.TrimSpace(group)
		if trimmed != "" {
			groups = append(groups, trimmed)
		}
	}
	return groups
}
