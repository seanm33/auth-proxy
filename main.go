package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	auth0Domain        string
	auth0ClientID      string
	auth0ClientSecret  string
	auth0CallbackURL   string
	appBaseURL         string // Base URL where this auth service is hosted
	sessionSecretKey   string
	requiredRole       string
	roleClaimNamespace string // The namespace used in the Auth0 Action

	store        *sessions.CookieStore
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	verifier     *oidc.IDTokenVerifier
)

const sessionName = "studio-auth-session"
const stateSessionKey = "oauth_state"
const nonceSessionKey = "oauth_nonce"
const originalURLSessionKey = "original_url"
const idTokenSessionKey = "id_token"
const authenticatedSessionKey = "authenticated"

// CustomClaims structure to extract roles from the ID token
type CustomClaims struct {
	Roles []string `json:"roles"` // Assumes the claim is just "roles" within the namespace
}

func loadConfig() {
	// Optional: Load .env file for local development
	// godotenv.Load()

	auth0Domain = os.Getenv("AUTH0_DOMAIN")
	auth0ClientID = os.Getenv("AUTH0_CLIENT_ID")
	auth0ClientSecret = os.Getenv("AUTH0_CLIENT_SECRET")
	auth0CallbackURL = os.Getenv("AUTH0_CALLBACK_URL")     // e.g., http://studio-auth-proxy:8080/callback
	appBaseURL = os.Getenv("APP_BASE_URL")                 // e.g., http://studio-auth-proxy:8080
	sessionSecretKey = os.Getenv("SESSION_SECRET_KEY")     // Needs to be a strong, random key
	requiredRole = os.Getenv("REQUIRED_ROLE")              // e.g., studio-admin
	roleClaimNamespace = os.Getenv("ROLE_CLAIM_NAMESPACE") // e.g., https://supabase.services.seanflix.org/

	if auth0Domain == "" || auth0ClientID == "" || auth0ClientSecret == "" || auth0CallbackURL == "" || appBaseURL == "" || sessionSecretKey == "" || requiredRole == "" || roleClaimNamespace == "" {
		log.Fatal("Required environment variables are missing (AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_CALLBACK_URL, APP_BASE_URL, SESSION_SECRET_KEY, REQUIRED_ROLE, ROLE_CLAIM_NAMESPACE)")
	}
	// Ensure namespace ends with a slash if needed for claim matching
	if !strings.HasSuffix(roleClaimNamespace, "/") {
		roleClaimNamespace += "/"
	}

	log.Printf("Config loaded: Domain=%s, ClientID=%s, Callback=%s, AppBase=%s, Role=%s, Namespace=%s",
		auth0Domain, auth0ClientID, auth0CallbackURL, appBaseURL, requiredRole, roleClaimNamespace)
}

func main() {
	loadConfig()

	ctx := context.Background()
	var err error

	oidcProvider, err = oidc.NewProvider(ctx, "https://"+auth0Domain+"/")
	if err != nil {
		log.Fatalf("Failed to get OIDC provider: %v", err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     auth0ClientID,
		ClientSecret: auth0ClientSecret,
		RedirectURL:  auth0CallbackURL,
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"}, // Include roles scope if needed, profile/email good practice
	}

	// Configure the ID token verifier
	verifier = oidcProvider.Verifier(&oidc.Config{ClientID: auth0ClientID})

	// Initialize session store
	// Ensure the key is strong and ideally 32 or 64 bytes
	store = sessions.NewCookieStore([]byte(sessionSecretKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // Example: 7 days
		HttpOnly: true,
		Secure:   strings.HasPrefix(appBaseURL, "https://"), // Set Secure flag if served over HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/verify", handleVerify) // Endpoint for Traefik ForwardAuth
	mux.HandleFunc("/logout", handleLogout)

	log.Println("Auth proxy server starting on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// handleLogin initiates the Auth0 login flow
func handleLogin(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		// Ignore error on get, create new session
		log.Printf("Error getting session (ignoring, will create new): %v", err)
	}

	// Generate random state
	stateBytes := make([]byte, 32)
	_, err = rand.Read(stateBytes)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Generate nonce
	nonceBytes := make([]byte, 32)
	_, err = rand.Read(nonceBytes)
	if err != nil {
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	// Store state and nonce in session
	session.Values[stateSessionKey] = state
	session.Values[nonceSessionKey] = nonce

	// Store the URL the user was trying to access if provided (e.g., by frontend)
	if originalURL := r.URL.Query().Get("original_url"); originalURL != "" {
		session.Values[originalURLSessionKey] = originalURL
	}

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session before redirect: %v", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// Redirect to Auth0
	authURL := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	log.Printf("Redirecting to Auth0: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback processes the response from Auth0
func handleCallback(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Printf("Error getting session in callback: %v", err)
		http.Error(w, "Invalid session state", http.StatusBadRequest)
		return
	}

	// Verify state parameter
	expectedState, ok := session.Values[stateSessionKey].(string)
	if !ok || expectedState == "" || r.URL.Query().Get("state") != expectedState {
		log.Printf("Invalid state parameter. Expected '%s', got '%s'", expectedState, r.URL.Query().Get("state"))
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Extract the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Println("ID token missing from response")
		http.Error(w, "ID token missing", http.StatusInternalServerError)
		return
	}

	// Verify the ID token
	expectedNonce, ok := session.Values[nonceSessionKey].(string)
	if !ok || expectedNonce == "" {
		log.Println("Nonce missing from session")
		http.Error(w, "Invalid session state (nonce)", http.StatusBadRequest)
		return
	}
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("Failed to verify ID token: %v", err)
		http.Error(w, "Invalid ID token", http.StatusUnauthorized)
		return
	}

	// Verify nonce
	if idToken.Nonce != expectedNonce {
		log.Printf("Nonce mismatch. Expected '%s', got '%s'", expectedNonce, idToken.Nonce)
		http.Error(w, "Invalid nonce", http.StatusUnauthorized)
		return
	}

	// --- Role Check ---
	var claims map[string]interface{} // Use map for flexible claim access
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Failed to extract claims: %v", err)
		http.Error(w, "Failed to parse token claims", http.StatusInternalServerError)
		return
	}

	// Construct the namespaced claim key
	namespacedRolesKey := roleClaimNamespace + "roles" // e.g. "https://your.ns/roles"

	userRoles := []string{}
	if rolesClaim, ok := claims[namespacedRolesKey]; ok {
		if rolesSlice, ok := rolesClaim.([]interface{}); ok {
			for _, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					userRoles = append(userRoles, roleStr)
				}
			}
		}
	}

	hasRequiredRole := false
	for _, role := range userRoles {
		if role == requiredRole {
			hasRequiredRole = true
			break
		}
	}

	if !hasRequiredRole {
		log.Printf("User %s does not have the required role '%s'. Roles: %v", idToken.Subject, requiredRole, userRoles)
		http.Error(w, fmt.Sprintf("Access Denied: Required role '%s' not found.", requiredRole), http.StatusForbidden)
		return
	}
	// --- End Role Check ---

	// Authentication successful & role verified
	log.Printf("User %s authenticated successfully with role %s", idToken.Subject, requiredRole)

	// Store essential info in session
	session.Values[authenticatedSessionKey] = true
	session.Values[idTokenSessionKey] = rawIDToken // Store raw token if needed later
	// Clean up OIDC state/nonce
	delete(session.Values, stateSessionKey)
	delete(session.Values, nonceSessionKey)

	// Redirect user back to original URL or a default page
	redirectURL := "/" // Default redirect if original not stored
	if original, ok := session.Values[originalURLSessionKey].(string); ok && original != "" {
		redirectURL = original
		delete(session.Values, originalURLSessionKey) // Clean up original URL
	}

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session after successful login: %v", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleVerify is the endpoint hit by Traefik ForwardAuth
func handleVerify(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, sessionName)
	if err != nil {
		// If session doesn't exist or cookie is bad, treat as unauthenticated
		log.Printf("Verify: Session error (likely no session): %v", err)
		w.WriteHeader(http.StatusUnauthorized) // Signal Traefik to block
		return
	}

	// Check if authenticated flag is set and true
	authenticated, ok := session.Values[authenticatedSessionKey].(bool)
	if !ok || !authenticated {
		log.Println("Verify: Not authenticated")
		w.WriteHeader(http.StatusUnauthorized) // Signal Traefik to block
		return
	}

	// Optional: Add check for token expiry if needed (requires storing expiry in session)
	// ... check expiry ...
	// if expired {
	// 	log.Println("Verify: Session expired")
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	return
	// }

	// If authenticated, return 200 OK
	log.Println("Verify: Authenticated OK")
	w.WriteHeader(http.StatusOK)
}

// handleLogout clears the session and redirects to Auth0 logout endpoint
func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName) // Ignore error, just clear if exists

	// Clear session values
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1 // Expire cookie immediately

	err := session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session during logout: %v", err)
		// Continue with logout anyway
	}

	// Construct Auth0 logout URL
	logoutURL, err := url.Parse("https://" + auth0Domain + "/v2/logout")
	if err != nil {
		http.Error(w, "Failed to construct logout URL", http.StatusInternalServerError)
		return
	}

	// URL to redirect back to after Auth0 logout (must be in Allowed Logout URLs in Auth0 Tenant settings)
	returnToURL := appBaseURL // Or maybe the public Supabase URL? Choose appropriately.
	// returnToURL := "https://" + r.Host // Or dynamically figure out where to return

	parameters := url.Values{}
	parameters.Add("returnTo", returnToURL)
	parameters.Add("client_id", auth0ClientID)
	logoutURL.RawQuery = parameters.Encode()

	log.Printf("Redirecting to Auth0 logout: %s", logoutURL.String())
	http.Redirect(w, r, logoutURL.String(), http.StatusFound)
}
