// /api/index.go
package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/google/go-github/v39/github"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

var (
	// These will be read from environment variables for security.
	githubClientID      string
	githubClientSecret  string
	githubOrgName       string
	githubPat           string // Personal Access Token of an org owner
	successRedirectURL  string // URL to redirect to on success
	errorRedirectURL    string // URL to redirect to on error

	// oauth2.Config is configured once globally.
	oauthConf *oauth2.Config

	// A sync.Once to ensure initialization happens only once.
	initOnce sync.Once

	// A simple in-memory state store for CSRF protection.
	oauthStateString = "random-string-for-csrf-protection"
)

// initVars loads configuration and sets up the OAuth config once.
func initVars() {
	githubClientID = os.Getenv("GITHUB_CLIENT_ID")
	githubClientSecret = os.Getenv("GITHUB_CLIENT_SECRET")
	githubOrgName = os.Getenv("GITHUB_ORG_NAME")
	githubPat = os.Getenv("GITHUB_PAT")
	successRedirectURL = os.Getenv("SUCCESS_REDIRECT_URL")
	errorRedirectURL = os.Getenv("ERROR_REDIRECT_URL")

	if githubClientID == "" || githubClientSecret == "" || githubOrgName == "" || githubPat == "" || successRedirectURL == "" || errorRedirectURL == "" {
		log.Fatal("FATAL: Environment variables GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_ORG_NAME, GITHUB_PAT, SUCCESS_REDIRECT_URL, and ERROR_REDIRECT_URL must be set.")
	}

	oauthConf = &oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		Scopes:       []string{"read:user"},
		Endpoint:     githuboauth.Endpoint,
	}
}

// Handler is the main entry point for the Vercel serverless function.
// It acts as a router for all incoming requests.
func Handler(w http.ResponseWriter, r *http.Request) {
	// Ensure initialization happens only once per serverless instance lifecycle.
	initOnce.Do(initVars)

	// Route based on the path.
	switch r.URL.Path {
	case "/login":
		fmt.Println("Handling login request")
		handleLogin(w, r)
	case "/github/callback":
		fmt.Println("Handling callback")
		handleCallback(w, r)
	default:
		// Redirect any other path to the login endpoint.
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}
}

// handleLogin redirects the user to GitHub to authorize.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	redirectURL := oauthConf.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)
	fmt.Println("Redirecting to:", redirectURL)
	
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// handleCallback handles the user after they authorize with GitHub.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		redirectToErrorPage(w, r, "invalid_state", "State token mismatch. Please try again.")
		return
	}

	code := r.FormValue("code")
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		redirectToErrorPage(w, r, "oauth_exchange_failed", "Could not verify your GitHub login.")
		return
	}

	oauthClient := oauthConf.Client(context.Background(), token)
	userClient := github.NewClient(oauthClient)
	user, _, err := userClient.Users.Get(context.Background(), "")
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		redirectToErrorPage(w, r, "user_info_failed", "Could not fetch your GitHub profile.")
		return
	}
	username := *user.Login

	// Create a new client authenticated with the Personal Access Token (PAT)
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubPat})
	tc := oauth2.NewClient(ctx, ts)
	adminClient := github.NewClient(tc)

	// Invite the user to the organization by editing their org membership
	_, _, err = adminClient.Organizations.EditOrgMembership(ctx, username, githubOrgName, nil)

	if err != nil {
		log.Printf("Error inviting user %s: %v", username, err)
		redirectToErrorPage(w, r, "invitation_failed", fmt.Sprintf("Failed to invite '%s'. They may already be a member or already invited.", username))
		return
	}

	log.Printf("Successfully invited user %s", username)
	// Redirect to the success page on your main website.
	http.Redirect(w, r, successRedirectURL, http.StatusTemporaryRedirect)
}

// redirectToErrorPage redirects the user to your site's error page with details.
func redirectToErrorPage(w http.ResponseWriter, r *http.Request, code, message string) {
	// Parse the base error URL
	parsedURL, err := url.Parse(errorRedirectURL)
	if err != nil {
		http.Error(w, "Server configuration error: Invalid error redirect URL.", http.StatusInternalServerError)
		return
	}
	
	// Add error details as query parameters
	query := parsedURL.Query()
	query.Set("error_code", code)
	query.Set("error_message", message)
	parsedURL.RawQuery = query.Encode()

	http.Redirect(w, r, parsedURL.String(), http.StatusTemporaryRedirect)
}