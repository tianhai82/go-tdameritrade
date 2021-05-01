package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tianhai82/go-tdameritrade"
	"github.com/tianhai82/oauth2"
)

type HTTPHeaderStore struct{}

var cachedToken *oauth2.Token
var cachedState string

func (s *HTTPHeaderStore) StoreToken(token *oauth2.Token) error {
	cachedToken = token
	return nil
}

func (s HTTPHeaderStore) GetToken() (*oauth2.Token, error) {
	if cachedToken == nil {
		return nil, fmt.Errorf("no token")
	}
	return cachedToken, nil
}

func (s HTTPHeaderStore) StoreState(state string) error {
	cachedState = state
	return nil
}

func (s HTTPHeaderStore) GetState() (string, error) {
	if cachedState == "" {
		return "", fmt.Errorf("state not found")
	}

	return cachedState, nil
}

type TDHandlers struct {
	authenticator *tdameritrade.Authenticator
}

func (h *TDHandlers) Authenticate(w http.ResponseWriter, req *http.Request) {
	redirectURL, err := h.authenticator.StartOAuth2Flow(w, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
}

func (h *TDHandlers) Callback(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	_, err := h.authenticator.FinishOAuth2Flow(ctx, w, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/quote?ticker=SPY", http.StatusTemporaryRedirect)
}

func (h *TDHandlers) Quote(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ticker, ok := req.URL.Query()["ticker"]
	if !ok || len(ticker) == 0 {
		w.Write([]byte("ticker is required"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	quote, resp, err := client.Quotes.GetQuotes(ctx, ticker[0])
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(quote)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
	w.WriteHeader(resp.StatusCode)

}

func main() {
	clientID := os.Getenv("CLIENT_ID")

	authenticator := tdameritrade.NewAuthenticator(
		&HTTPHeaderStore{},
		oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://api.tdameritrade.com/v1/oauth2/token",
				AuthURL:  "https://auth.tdameritrade.com/auth",
			},
			RedirectURL: "http://localhost:8080/callback",
		},
	)
	handlers := &TDHandlers{authenticator: authenticator}
	http.HandleFunc("/authenticate", handlers.Authenticate)
	http.HandleFunc("/callback", handlers.Callback)
	http.HandleFunc("/quote", handlers.Quote)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
