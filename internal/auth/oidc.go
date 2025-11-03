package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type Config struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	IssuerURL    string `mapstructure:"issuer_url"`
	RedirectURL  string `mapstructure:"redirect_url"`
	SessionKey   string `mapstructure:"session_key"`
}

type OIDCProvider struct {
	config       *Config
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	store        sessions.Store
}

type UserInfo struct {
	Sub      string   `json:"sub"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
	Username string   `json:"preferred_username"`
	IsAdmin  bool     `json:"isAdmin"`
}

func NewOIDCProvider(config *Config, sessionStore sessions.Store) (*OIDCProvider, error) {
	ctx := context.Background()

	slog.Info("Initializing OIDC provider", "issuer_url", config.IssuerURL, "client_id", config.ClientID)

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		slog.Error("Failed to create OIDC provider", "issuer_url", config.IssuerURL, "error", err)
		return nil, fmt.Errorf("failed to create OIDC provider: %v", err)
	}

	slog.Debug("OIDC provider created successfully", "issuer_url", config.IssuerURL)

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	slog.Info("OIDC provider initialized successfully", "redirect_url", config.RedirectURL, "scopes", oauth2Config.Scopes)

	return &OIDCProvider{
		config:       config,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		store:        sessionStore,
	}, nil
}

func (p *OIDCProvider) GetLoginURL(state string, redirectURL string) string {
	// Create a copy of the config with the dynamic redirect URL
	config := *p.oauth2Config
	if redirectURL != "" {
		config.RedirectURL = redirectURL
	}
	return config.AuthCodeURL(state)
}

// GetOAuth2Config returns the oauth2 config (used for token exchange with potential dynamic redirect URL)
func (p *OIDCProvider) GetOAuth2Config(redirectURL string) *oauth2.Config {
	config := *p.oauth2Config
	if redirectURL != "" {
		config.RedirectURL = redirectURL
	}
	return &config
}

func (p *OIDCProvider) HandleCallback(ctx context.Context, code, state, redirectURL string) (*UserInfo, error) {
	slog.Debug("Handling OAuth callback", "state", state)

	oauth2Config := p.GetOAuth2Config(redirectURL)
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		slog.Error("Failed to exchange OAuth code for token", "error", err)
		return nil, fmt.Errorf("authentication failed")
	}

	slog.Debug("Successfully exchanged OAuth code for token")

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Error("No ID token found in OAuth token response")
		return nil, fmt.Errorf("authentication failed")
	}

	slog.Debug("Extracted ID token from OAuth response")

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Error("Failed to verify ID token", "error", err)
		return nil, fmt.Errorf("authentication failed")
	}

	slog.Debug("Successfully verified ID token")

	var claims struct {
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}

	if err := idToken.Claims(&claims); err != nil {
		slog.Error("Failed to parse ID token claims", "error", err)
		return nil, fmt.Errorf("authentication failed")
	}

	slog.Info("User authenticated successfully", "username", claims.PreferredUsername, "email", claims.Email, "groups", claims.Groups)

	return &UserInfo{
		Sub:      claims.Sub,
		Name:     claims.Name,
		Email:    claims.Email,
		Groups:   claims.Groups,
		Username: claims.PreferredUsername,
	}, nil
}

func (p *OIDCProvider) SaveUserSession(w http.ResponseWriter, r *http.Request, user *UserInfo) error {
	slog.Debug("Saving user session", "username", user.Username, "groups", user.Groups)

	session, err := p.store.Get(r, "cluster-watcher-session")
	if err != nil {
		slog.Error("Failed to get session for saving user", "error", err)
		return fmt.Errorf("session error")
	}

	session.Values["user_sub"] = user.Sub
	session.Values["user_name"] = user.Name
	session.Values["user_email"] = user.Email
	session.Values["user_username"] = user.Username
	session.Values["user_groups"] = strings.Join(user.Groups, ",")

	err = session.Save(r, w)
	if err != nil {
		slog.Error("Failed to save user session", "username", user.Username, "error", err)
		return err
	}

	slog.Info("User session saved successfully", "username", user.Username)
	return nil
}

func (p *OIDCProvider) GetUserFromSession(r *http.Request) (*UserInfo, error) {
	session, err := p.store.Get(r, "cluster-watcher-session")
	if err != nil {
		slog.Debug("Failed to get session for user retrieval (possibly old session format)", "error", err)
		// Clear potentially corrupted session and return no user
		return nil, fmt.Errorf("no user in session")
	}

	sub, ok := session.Values["user_sub"].(string)
	if !ok || sub == "" {
		slog.Debug("No user found in session")
		return nil, fmt.Errorf("no user in session")
	}

	name, _ := session.Values["user_name"].(string)
	email, _ := session.Values["user_email"].(string)
	username, _ := session.Values["user_username"].(string)
	groupsStr, _ := session.Values["user_groups"].(string)

	var groups []string
	if groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}

	slog.Debug("Retrieved user from session", "username", username, "groups", groups)

	return &UserInfo{
		Sub:      sub,
		Name:     name,
		Email:    email,
		Username: username,
		Groups:   groups,
	}, nil
}

func (p *OIDCProvider) ClearUserSession(w http.ResponseWriter, r *http.Request) error {
	slog.Debug("Clearing user session")

	session, err := p.store.Get(r, "cluster-watcher-session")
	if err != nil {
		slog.Error("Failed to get session for clearing", "error", err)
		return fmt.Errorf("failed to get session: %v", err)
	}

	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		slog.Error("Failed to save cleared session", "error", err)
		return err
	}

	slog.Info("User session cleared successfully")
	return nil
}

func GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}