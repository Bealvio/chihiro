package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type contextKey string

const UserContextKey contextKey = "user"

type Middleware struct {
	provider *OIDCProvider
}

func NewMiddleware(provider *OIDCProvider) *Middleware {
	slog.Info("Initializing authentication middleware")
	return &Middleware{
		provider: provider,
	}
}

// RequireAuth middleware for Gin framework
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for public endpoints
		if isPublicEndpoint(c.Request.URL.Path) {
			slog.Debug("Allowing access to public endpoint", "path", c.Request.URL.Path, "method", c.Request.Method, "remote_addr", c.ClientIP())
			c.Next()
			return
		}

		user, err := m.provider.GetUserFromSession(c.Request)
		if err != nil {
			slog.Debug("User authentication failed", "path", c.Request.URL.Path, "method", c.Request.Method, "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"), "error", err)

			// Redirect to login for browser requests
			if strings.Contains(c.Request.Header.Get("Accept"), "text/html") {
				slog.Debug("Redirecting browser request to login", "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
				c.Redirect(http.StatusFound, "/login")
				c.Abort()
				return
			}
			// Return 401 for API requests
			slog.Debug("Returning 401 for API request", "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Add user to request context
		slog.Debug("User authenticated successfully", "username", user.Username, "groups", user.Groups, "path", c.Request.URL.Path, "method", c.Request.Method, "remote_addr", c.ClientIP())
		ctx := context.WithValue(c.Request.Context(), UserContextKey, user)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// GetUserFromContext extracts user info from request context
func GetUserFromContext(ctx context.Context) (*UserInfo, bool) {
	user, ok := ctx.Value(UserContextKey).(*UserInfo)
	return user, ok
}

// CheckUserGroups verifies if user has any of the required groups
func CheckUserGroups(userGroups []string, requiredGroups []string) bool {
	slog.Debug("Checking user groups", "user_groups", userGroups, "required_groups", requiredGroups)

	if len(requiredGroups) == 0 {
		slog.Debug("No group requirements, access granted")
		return true // No group requirement
	}

	userGroupMap := make(map[string]bool)
	for _, group := range userGroups {
		userGroupMap[group] = true
	}

	for _, required := range requiredGroups {
		if userGroupMap[required] {
			slog.Debug("User has required group, access granted", "matching_group", required)
			return true
		}
	}

	slog.Debug("User does not have any required groups, access denied")
	return false
}

// ParseClusterGroups extracts groups from cluster annotations
func ParseClusterGroups(annotations map[string]interface{}) []string {
	if annotations == nil {
		return nil
	}

	groupsValue, exists := annotations["chihiro.io/groups"]
	if !exists {
		return nil
	}

	groupsStr, ok := groupsValue.(string)
	if !ok {
		return nil
	}

	if groupsStr == "" {
		return nil
	}

	// Split by comma and trim spaces
	groups := strings.Split(groupsStr, ",")
	var result []string
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// HandleLogin initiates OIDC login flow
func (m *Middleware) HandleLogin(c *gin.Context) {
	slog.Info("Initiating OIDC login flow", "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"))

	state, err := GenerateState()
	if err != nil {
		slog.Error("Failed to generate OAuth state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Store state in session for verification
	session, err := m.provider.store.Get(c.Request, "cluster-watcher-session")
	if err != nil {
		slog.Debug("Failed to get session for OAuth (creating new session)", "error", err)
		// Create a new session if the old one is corrupted
		session, err = m.provider.store.New(c.Request, "cluster-watcher-session")
		if err != nil {
			slog.Error("Failed to create new session for OAuth", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
	}

	session.Values["oauth_state"] = state
	session.Values["oauth_state_time"] = time.Now().Unix()
	if err := session.Save(c.Request, c.Writer); err != nil {
		slog.Error("Failed to save session with OAuth state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	loginURL := m.provider.GetLoginURL(state)
	slog.Debug("Redirecting to OIDC provider", "login_url", loginURL, "state", state, "remote_addr", c.ClientIP())
	c.Redirect(http.StatusFound, loginURL)
}

// HandleCallback handles OIDC callback
func (m *Middleware) HandleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	slog.Info("Handling OIDC callback", "has_code", code != "", "state", state, "remote_addr", c.ClientIP())

	if code == "" {
		slog.Error("No authorization code in callback", "remote_addr", c.ClientIP(), "query_params", c.Request.URL.RawQuery)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization code"})
		return
	}

	// Verify state
	session, err := m.provider.store.Get(c.Request, "cluster-watcher-session")
	if err != nil {
		slog.Error("Failed to get session during OAuth callback (invalid session)", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session, please try logging in again"})
		return
	}

	storedState, ok := session.Values["oauth_state"].(string)
	if !ok || storedState != state {
		slog.Error("Invalid OAuth state parameter", "provided_state", state, "stored_state", storedState, "remote_addr", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Check state timestamp (prevent replay attacks)
	stateTime, ok := session.Values["oauth_state_time"].(int64)
	if !ok {
		slog.Error("Missing OAuth state timestamp", "remote_addr", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session state"})
		return
	}

	// State expires after 5 minutes
	if time.Now().Unix()-stateTime > 300 {
		slog.Error("OAuth state expired", "age_seconds", time.Now().Unix()-stateTime, "remote_addr", c.ClientIP())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication request expired, please try again"})
		return
	}

	// Exchange code for tokens
	user, err := m.provider.HandleCallback(c.Request.Context(), code, state)
	if err != nil {
		slog.Error("Failed to handle OAuth callback", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
		return
	}

	// Regenerate session ID to prevent session fixation
	session.Options.MaxAge = -1
	session.Save(c.Request, c.Writer)

	// Create new session
	newSession, err := m.provider.store.New(c.Request, "cluster-watcher-session")
	if err != nil {
		slog.Error("Failed to create new session after authentication", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Save user to new session
	newSession.Values["user_sub"] = user.Sub
	newSession.Values["user_name"] = user.Name
	newSession.Values["user_email"] = user.Email
	newSession.Values["user_username"] = user.Username
	newSession.Values["user_groups"] = strings.Join(user.Groups, ",")

	if err := newSession.Save(c.Request, c.Writer); err != nil {
		slog.Error("Failed to save new session after authentication", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Redirect to dashboard
	slog.Info("OIDC authentication completed successfully, redirecting to dashboard", "username", user.Username, "groups", user.Groups, "remote_addr", c.ClientIP())
	c.Redirect(http.StatusFound, "/")
}

// HandleLogout clears user session
func (m *Middleware) HandleLogout(c *gin.Context) {
	user, _ := GetUserFromContext(c.Request.Context())
	username := "unknown"
	if user != nil {
		username = user.Username
	}

	slog.Info("User logging out", "username", username, "remote_addr", c.ClientIP())

	if err := m.provider.ClearUserSession(c.Writer, c.Request); err != nil {
		slog.Warn("Failed to clear user session during logout", "username", username, "error", err)
	}

	slog.Debug("Redirecting to login page after logout", "username", username)
	c.Redirect(http.StatusFound, "/login")
}

// HandleUserInfo returns current user information
func (m *Middleware) HandleUserInfo(c *gin.Context) {
	user, ok := GetUserFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// isPublicEndpoint checks if the endpoint should be accessible without authentication
func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/auth/login",
		"/auth/callback",
		"/auth/logout",
		"/health",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}

	return false
}