package tdameritrade

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tianhai82/oauth2"
)

var (
	// ErrNoCode is returned when the TD Ameritrade request is missing a code.
	ErrNoCode = fmt.Errorf("missing code in request from TD Ameritrade")

	// ErrNoState is returned when TD Ameritrade request is missing state, indicating a CSRF attempt.
	ErrNoState = fmt.Errorf("missing state in request from TD Ameritrade")
)

// PersistentStore is meant to persist data from TD Ameritrade that is needed between requests.
// Implementations must return the same value they set for a user in StoreState in GetState, or the login process will fail.
// It is meant to allow credentials to be stored in cookies, JWTs and anything else you can think of.
type PersistentStore interface {
	StoreToken(token *oauth2.Token) error
	GetToken() (*oauth2.Token, error)
	StoreState(state string) error
	GetState() (string, error)
}

// Authenticator is a helper for TD Ameritrade's authentication.
// It authenticates users and validates the state returned from TD Ameritrade to protect users from CSRF attacks.
// It's recommended to use NewAuthenticator instead of creating this struct directly because TD Ameritrade requires Client IDs to be in the form clientid@AMER.OAUTHAP.
// This is not immediately obvious from the documentation.
// See https://developer.tdameritrade.com/content/authentication-faq
type Authenticator struct {
	Store  PersistentStore
	OAuth2 oauth2.Config
}

// NewAuthenticator will automatically append @AMER.OAUTHAP to the client ID to save callers hours of frustration.
func NewAuthenticator(store PersistentStore, oauth2 oauth2.Config) *Authenticator {
	oauth2.ClientID = oauth2.ClientID + "@AMER.OAUTHAP"
	return &Authenticator{
		Store:  store,
		OAuth2: oauth2,
	}
}

// AuthenticatedClient tries to create an authenticated `Client` from a user's request
func (a *Authenticator) AuthenticatedClient(ctx context.Context, req *http.Request) (*Client, error) {
	token, err := a.Store.GetToken()
	if err != nil {
		return nil, err
	}

	// authenticatedClient := a.OAuth2.Client(ctx, token)
	tokenSource := a.OAuth2.TokenSource(ctx, token)
	client := oauth2.NewClient(ctx, tokenSource)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}
	if newToken.AccessToken != token.AccessToken || newToken.RefreshToken != token.RefreshToken {
		a.Store.StoreToken(newToken)
	}
	return NewClient(client)
}

// StartOAuth2Flow returns TD Ameritrade's Auth URL and stores a random state value.
// Redirect users to the returned URL to begin authentication.
func (a *Authenticator) StartOAuth2Flow(w http.ResponseWriter, req *http.Request) (string, error) {
	// Do not leave state generation up to callers.
	// Experience has shown that people often do not know what OAuth2 state is and leave themselves vulnerable to CSRF attacks.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Instead, have callers store the state we give them and present it to us when we ask for it again.
	state := base64.RawURLEncoding.EncodeToString(b)
	err := a.Store.StoreState(state)
	if err != nil {
		return "", err
	}

	return a.OAuth2.AuthCodeURL(state), nil
}

// FinishOAuth2Flow finishes authenticating a user returning from TD Ameritrade.
// It verifies that TD Ameritrade has returned the expected state to prevent CSRF attacks and returns an authenticated `Client` on success.
func (a *Authenticator) FinishOAuth2Flow(ctx context.Context, w http.ResponseWriter, req *http.Request) (*Client, error) {
	code, ok := req.URL.Query()["code"]
	if !ok || len(code) == 0 || len(code[0]) == 0 {
		return nil, ErrNoCode
	}
	state, ok := req.URL.Query()["state"]
	if !ok || len(state) == 0 || len(state[0]) == 0 {
		return nil, ErrNoState
	}

	expectedState, err := a.Store.GetState()
	if err != nil {
		return nil, err
	}

	// Sanity check: users should never return an empty string from GetState.
	// Prevent users from making themselves vulnerable to CSRF by forcing them to set state.
	if len(expectedState) == 0 {
		return nil, ErrNoState
	}

	if state[0] != expectedState {
		return nil, fmt.Errorf("invalid state. expected: '%v', got '%v'", expectedState, state[0])
	}

	token, err := a.OAuth2.Exchange(ctx, code[0], oauth2.AccessTypeOffline)
	if err != nil {
		return nil, err
	}

	b, _ := json.Marshal(token)
	fmt.Println(string(b))

	err = a.Store.StoreToken(token)
	if err != nil {
		return nil, err
	}

	authenticatedClient := a.OAuth2.Client(ctx, token)
	return NewClient(authenticatedClient)
}
