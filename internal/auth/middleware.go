package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
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

func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isPublicEndpoint(c.Request.URL.Path) {
			slog.Debug("Allowing access to public endpoint", "path", c.Request.URL.Path, "method", c.Request.Method, "remote_addr", c.ClientIP())
			c.Next()
			return
		}

		user, err := m.provider.GetUserFromSession(c.Request)
		if err != nil {
			slog.Debug("User authentication failed", "path", c.Request.URL.Path, "method", c.Request.Method, "remote_addr", c.ClientIP(), "user_agent", c.Request.Header.Get("User-Agent"), "error", err)

			if strings.Contains(c.Request.Header.Get("Accept"), "text/html") {
				slog.Debug("Redirecting browser request to login", "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
				c.Redirect(http.StatusFound, "/login")
				c.Abort()
				return
			}
			slog.Debug("Returning 401 for API request", "path", c.Request.URL.Path, "remote_addr", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

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
		return true
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

// trustedRedirectHost reports whether host (host[:port]) is allowed to be used
// when constructing the OAuth redirect URL. X-Forwarded-* headers are
// attacker-controllable unless a trusted proxy overwrites them, so a forwarded
// host is only honored when it appears in an explicit allow-list. The allow-list
// is built from the configured OIDC redirect URL host and any entries in
// allowed_origins. An empty allow-list means "not configured" and the caller
// falls back to the request Host.
func trustedRedirectHost(host string) bool {
	if host == "" {
		return false
	}
	allowed := make(map[string]bool)
	if ru := viper.GetString("oidc.redirect_url"); ru != "" {
		if u, err := url.Parse(ru); err == nil && u.Host != "" {
			allowed[u.Host] = true
		}
	}
	if origins := viper.GetString("allowed_origins"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			if u, err := url.Parse(o); err == nil && u.Host != "" {
				allowed[u.Host] = true
			} else {
				allowed[o] = true // bare host[:port] form
			}
		}
	}
	return allowed[host]
}

// isLoopbackHost reports whether host is a loopback/localhost name, used to skip
// a dev-default OIDC redirect URL so it cannot override real proxy detection.
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// getRedirectURLFromRequest constructs the redirect URL based on the incoming
// request. When a configured OIDC redirect URL is present it is used verbatim,
// which is both the most secure option (it cannot be influenced by request
// headers) and the simplest for TLS-terminating-proxy deployments. Otherwise
// the URL is reconstructed from the request, honoring standard proxy headers.
func getRedirectURLFromRequest(r *http.Request) string {
	// Prefer the explicitly configured redirect URL. In production this is set
	// to the public HTTPS callback, so we never have to guess scheme/host from
	// proxy headers (which is where the http/https mismatch came from).
	//
	// Ignore the localhost/loopback dev default so a leftover value in a
	// committed config file does not force an http://localhost callback in a
	// real deployment — in that case fall through to request-based detection.
	if ru := viper.GetString("oidc.redirect_url"); ru != "" {
		if u, err := url.Parse(ru); err == nil && u.Host != "" && !isLoopbackHost(u.Hostname()) {
			redirectURL := fmt.Sprintf("%s://%s/auth/callback", u.Scheme, u.Host)
			slog.Debug("Using configured OIDC redirect URL", "redirect_url", redirectURL)
			return redirectURL
		}
	}

	// Fallback: reconstruct from the request. Default to the request's own Host
	// (set by the server, not the client).
	host := r.Host

	// Only trust X-Forwarded-Host when it matches a configured allow-list,
	// otherwise an attacker could poison the OAuth redirect_uri by spoofing the
	// header on a deployment that isn't fronted by a header-stripping proxy.
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		if trustedRedirectHost(fwd) {
			host = fwd
		} else {
			slog.Warn("Ignoring untrusted X-Forwarded-Host header", "forwarded_host", fwd, "request_host", r.Host)
		}
	}

	// Determine the scheme. X-Forwarded-Proto is the standard signal from a
	// TLS-terminating proxy (the request reaching us is plain HTTP in that
	// case), so honor it directly; restrict to http/https.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	}

	redirectURL := fmt.Sprintf("%s://%s/auth/callback", scheme, host)
	slog.Debug("Constructed redirect URL from request", "redirect_url", redirectURL, "host", host, "scheme", scheme)
	return redirectURL
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

	// Construct redirect URL from the incoming request
	redirectURL := getRedirectURLFromRequest(c.Request)

	// Store state and redirect URL in session for verification
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
	session.Values["oauth_redirect_url"] = redirectURL
	if err := session.Save(c.Request, c.Writer); err != nil {
		slog.Error("Failed to save session with OAuth state", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	loginURL := m.provider.GetLoginURL(state, redirectURL)
	slog.Debug("Redirecting to OIDC provider", "login_url", loginURL, "state", state, "redirect_url", redirectURL, "remote_addr", c.ClientIP())
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

	// Get redirect URL from session (or reconstruct if not found)
	redirectURL := ""
	if storedRedirectURL, ok := session.Values["oauth_redirect_url"].(string); ok {
		redirectURL = storedRedirectURL
	} else {
		// Fallback: reconstruct from current request in case session was lost
		redirectURL = getRedirectURLFromRequest(c.Request)
		slog.Warn("Redirect URL not found in session, reconstructing from request", "redirect_url", redirectURL)
	}

	// Exchange code for tokens
	user, err := m.provider.HandleCallback(c.Request.Context(), code, state, redirectURL)
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
		"/login",
		"/auth/login",
		"/auth/callback",
		"/auth/logout",
		"/health",
		"/favicon.ico",
	}

	for _, publicPath := range publicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}

	return false
}
