package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type tokenInfo struct {
	Email     string
	CreatedAt time.Time
}

type stateInfo struct {
	RedirectPort string
	WebMode      bool
	CreatedAt    time.Time
}

type Handler struct {
	oauthConfig   *oauth2.Config
	allowedDomain string
	serverDomain  string

	mu     sync.Mutex
	tokens map[string]*tokenInfo // one-time auth tokens
	states map[string]*stateInfo // OAuth state -> redirect info
}

func NewHandler(clientID, clientSecret, allowedDomain, serverDomain string) *Handler {
	h := &Handler{
		oauthConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"openid", "email"},
			Endpoint:     google.Endpoint,
		},
		allowedDomain: allowedDomain,
		serverDomain:  serverDomain,
		tokens:        make(map[string]*tokenInfo),
		states:        make(map[string]*stateInfo),
	}
	return h
}

// ValidateAndConsumeToken validates a one-time token and returns the associated email.
func (h *Handler) ValidateAndConsumeToken(token string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	info, ok := h.tokens[token]
	if !ok {
		return "", false
	}
	delete(h.tokens, token)

	if time.Since(info.CreatedAt) > 60*time.Second {
		return "", false
	}
	return info.Email, true
}

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	webMode := mode == "web"

	redirectPort := r.URL.Query().Get("redirect_port")
	if !webMode && redirectPort == "" {
		http.Error(w, "missing redirect_port", http.StatusBadRequest)
		return
	}

	state, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.states[state] = &stateInfo{
		RedirectPort: redirectPort,
		WebMode:      webMode,
		CreatedAt:    time.Now(),
	}
	h.mu.Unlock()

	h.oauthConfig.RedirectURL = fmt.Sprintf("https://%s/auth/callback", h.serverDomain)
	url := h.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	// Look up and consume state
	h.mu.Lock()
	si, ok := h.states[state]
	if ok {
		delete(h.states, state)
	}
	h.mu.Unlock()

	if !ok || time.Since(si.CreatedAt) > 5*time.Minute {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauthToken, err := h.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("OAuth exchange error: %v", err)
		http.Error(w, "oauth exchange failed", http.StatusInternalServerError)
		return
	}

	// Get user info
	email, err := h.getUserEmail(oauthToken)
	if err != nil {
		log.Printf("Failed to get user email: %v", err)
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}

	// Validate domain
	if !h.isAllowedEmail(email) {
		log.Printf("Rejected login from %s (domain not allowed)", email)
		http.Error(w, "access denied: email domain not allowed", http.StatusForbidden)
		return
	}

	// Generate one-time token
	authToken, err := randomHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.tokens[authToken] = &tokenInfo{
		Email:     email,
		CreatedAt: time.Now(),
	}
	h.mu.Unlock()

	log.Printf("Authenticated %s, issuing token", email)

	// Redirect to web result page or client's local callback
	var redirectURL string
	if si.WebMode {
		redirectURL = fmt.Sprintf("https://%s/web/result?token=%s", h.serverDomain, authToken)
	} else {
		redirectURL = fmt.Sprintf("http://localhost:%s/callback?token=%s", si.RedirectPort, authToken)
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) StartCleanup(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			h.cleanExpired()
		}
	}
}

func (h *Handler) cleanExpired() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	for k, v := range h.tokens {
		if now.Sub(v.CreatedAt) > 60*time.Second {
			delete(h.tokens, k)
		}
	}
	for k, v := range h.states {
		if now.Sub(v.CreatedAt) > 5*time.Minute {
			delete(h.states, k)
		}
	}
}

type googleUserInfo struct {
	Email string `json:"email"`
}

func (h *Handler) getUserEmail(token *oauth2.Token) (string, error) {
	client := h.oauthConfig.Client(nil, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("fetching userinfo: %w", err)
	}
	defer resp.Body.Close()

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decoding userinfo: %w", err)
	}
	if info.Email == "" {
		return "", fmt.Errorf("no email in response")
	}
	return info.Email, nil
}

func (h *Handler) isAllowedEmail(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	return strings.EqualFold(parts[1], h.allowedDomain)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
