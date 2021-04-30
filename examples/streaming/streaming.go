package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tianhai82/go-tdameritrade"
	"github.com/tianhai82/oauth2"
)

var cachedToken *oauth2.Token
var cachedState string

type HTTPHeaderStore struct{}

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

	http.Redirect(w, req, "/stream", http.StatusFound)
}

func (h *TDHandlers) Stream(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userPrincipals, resp, err := client.User.GetUserPrincipals(ctx, "streamerSubscriptionKeys", "streamerConnectionInfo")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("User Principals: [Status: %d] %+v", resp.StatusCode, *userPrincipals)

	streamingClient, err := tdameritrade.NewAuthenticatedStreamingClient(userPrincipals, userPrincipals.Accounts[0].AccountID)
	go func() {
		if err != nil {
			log.Fatal(err)
		}
		defer streamingClient.Close()
		messages, errors := streamingClient.ReceiveText()
		for {
			select {
			case message := <-messages:
				log.Printf("message: %s", message)

			case err := <-errors:
				log.Printf("error: %v", err)
				return
			}
		}
	}()

	streamingClient.SendCommand(tdameritrade.Command{
		Requests: []tdameritrade.StreamRequest{
			{
				Service:   "QUOTE",
				Requestid: "2",
				Command:   "SUBS",
				Account:   userPrincipals.Accounts[0].AccountID,
				Source:    userPrincipals.StreamerInfo.AppID,
				Parameters: tdameritrade.StreamParams{
					Keys:   "AAPL",
					Fields: "0,1,2,3,4,5,6,7,8",
				},
			},
		},
	})

	w.Write([]byte("Check the terminal for streaming data"))
	w.WriteHeader(http.StatusOK)

}

func main() {
	clientID := os.Getenv("TDAMERITRADE_CLIENT_ID")
	if clientID == "" {
		log.Fatal("Unauthorized: No client ID present")
	}

	authenticator := tdameritrade.NewAuthenticator(
		&HTTPHeaderStore{},
		oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://api.tdameritrade.com/v1/oauth2/token",
				AuthURL:  "https://auth.tdameritrade.com/auth",
			},
			RedirectURL: "https://127.0.0.1/callback",
		},
	)
	handlers := &TDHandlers{authenticator: authenticator}
	http.HandleFunc("/authenticate", handlers.Authenticate)
	http.HandleFunc("/callback", handlers.Callback)
	http.HandleFunc("/stream", handlers.Stream)
	log.Fatal(http.ListenAndServe(":8000", nil))
}
