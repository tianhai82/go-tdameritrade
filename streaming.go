package tdameritrade

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Command struct {
	Requests []StreamRequest `json:"requests"`
}

type StreamRequest struct {
	Service    string       `json:"service"`
	Requestid  string       `json:"requestid"`
	Command    string       `json:"command"`
	Account    string       `json:"account"`
	Source     string       `json:"source"`
	Parameters StreamParams `json:"parameters"`
}

type StreamParams struct {
	Keys   string `json:"keys"`
	Fields string `json:"fields"`
}

type StreamAuthCommand struct {
	Requests []StreamAuthRequest `json:"requests"`
}

type StreamAuthRequest struct {
	Service    string           `json:"service"`
	Command    string           `json:"command"`
	Requestid  int              `json:"requestid"`
	Account    string           `json:"account"`
	Source     string           `json:"source"`
	Parameters StreamAuthParams `json:"parameters"`
}

type StreamAuthResponse struct {
	Response []StreamAuthResponseBody `json:"response"`
}

type StreamAuthResponseBody struct {
	Service   string                    `json:"service"`
	Requestid string                    `json:"requestid"`
	Command   string                    `json:"command"`
	Timestamp int64                     `json:"timestamp"`
	Content   StreamAuthResponseContent `json:"content"`
}

type StreamAuthResponseContent struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

type StreamAuthParams struct {
	Credential string `json:"credential"`
	Token      string `json:"token"`
	Version    string `json:"version"`
}

// StreamingClient provides real time updates from TD Ameritrade's streaming API.
// See https://developer.tdameritrade.com/content/streaming-data for more information.
type StreamingClient struct {
	connection *websocket.Conn
	messages   chan []byte
	errors     chan error
	mu         sync.Mutex
}

// Close closes the underlying websocket connection.
func (s *StreamingClient) Close() error {
	close(s.messages)
	close(s.errors)
	return s.connection.Close()
}

// SendText sends a byte payload to TD Ameritrade's websocket.
// TD Ameritrade commands are JSON encoded payloads.
// You should generally be using SendCommand to send commands to TD Ameritrade.
func (s *StreamingClient) SendText(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connection.WriteMessage(websocket.TextMessage, payload)
}

// ReceiveText returns read-only channels with the raw byte responses from TD Ameritrade and errors generated while streaming.
// Callers should select over both of these channels to avoid blocking one.
// Callers are able to handle errors how thes see fit.
// All errors will be from Gorilla's websocket library and implement the net.Error interface.
func (s *StreamingClient) ReceiveText() (<-chan []byte, <-chan error) {
	return s.messages, s.errors
}

// SendCommand serializes and sends a Command struct to TD Ameritrade.
// It is a wrapper around SendText.
func (s *StreamingClient) SendCommand(command Command) error {
	commandBytes, err := json.Marshal(command)
	if err != nil {
		return err
	}

	return s.SendText(commandBytes)
}

// NewUnauthenticatedStreamingClient returns an unauthenticated streaming client that has a connection to the TD Ameritrade websocket.
// You can get an authenticated streaming client with NewAuthenticatedSteamingClient.
// To authenticate manually, send a JSON serialized StreamAuthCommand message.
// You'll need to Close a streaming client to free up the underlying resources.
func NewUnauthenticatedStreamingClient(userPrincipal *UserPrincipal) (*StreamingClient, error) {
	streamURL := url.URL{
		Scheme: "wss",
		Host:   userPrincipal.StreamerInfo.StreamerSocketURL,
		Path:   "/ws",
	}

	conn, _, err := websocket.DefaultDialer.Dial(streamURL.String(), nil)
	if err != nil {
		return nil, err
	}

	streamingClient := &StreamingClient{
		connection: conn,
		messages:   make(chan []byte),
		errors:     make(chan error),
	}

	// Pass messages and errors down the respective channels.
	go func() {
		for {
			_, message, err := streamingClient.connection.ReadMessage()
			if err != nil {
				streamingClient.errors <- err
				return
			}

			streamingClient.messages <- message
		}
	}()

	return streamingClient, nil
}

// NewAuthenticatedStreamingClient returns a client that will pull live updates for a TD Ameritrade account.
// It sends an initial authentication message to TD Ameritrade before returning.
// Use NewUnauthenticatedStreamingClient if you want to handle authentication yourself.
// You'll need to Close a StreamingClient to free up the underlying resources.
func NewAuthenticatedStreamingClient(userPrincipal *UserPrincipal, accountID string) (*StreamingClient, error) {
	streamingClient, err := NewUnauthenticatedStreamingClient(userPrincipal)
	if err != nil {
		return nil, err
	}

	// Authenticate with TD's websocket.
	// findAccount ensures that a user has passed us an account they control to avoid wasting TD Ameritrade's time.
	account, err := findAccount(userPrincipal, accountID)
	if err != nil {
		return nil, err
	}

	timestamp, err := time.Parse("2006-01-02T15:04:05-0700", userPrincipal.StreamerInfo.TokenTimestamp)
	if err != nil {
		return nil, err
	}
	credentials := url.Values{}
	credentials.Add("userid", account.AccountID)
	credentials.Add("token", userPrincipal.StreamerInfo.Token)
	credentials.Add("company", account.Company)
	credentials.Add("segment", account.Segment)
	credentials.Add("cddomain", account.AccountCdDomainID)
	credentials.Add("usergroup", userPrincipal.StreamerInfo.UserGroup)
	credentials.Add("accesslevel", userPrincipal.StreamerInfo.AccessLevel)
	credentials.Add("authorized", "Y")
	credentials.Add("timestamp", fmt.Sprintf("%d", timestamp.UnixNano()/int64(time.Millisecond)))
	credentials.Add("appid", userPrincipal.StreamerInfo.AppID)
	credentials.Add("acl", userPrincipal.StreamerInfo.ACL)

	// TD Ameritrade expects this JSON command from clients.
	authCmd := StreamAuthCommand{
		Requests: []StreamAuthRequest{
			{
				Service:   "ADMIN",
				Command:   "LOGIN",
				Requestid: 0,
				Account:   account.AccountID,
				Source:    userPrincipal.StreamerInfo.AppID,
				Parameters: StreamAuthParams{
					Credential: credentials.Encode(),
					Token:      userPrincipal.StreamerInfo.Token,
					Version:    "1.0",
				},
			},
		},
	}

	jsonCmd, err := json.Marshal(authCmd)
	if err != nil {
		return nil, err
	}

	err = streamingClient.SendText(jsonCmd)
	if err != nil {
		return nil, err
	}

	select {
	case message := <-streamingClient.messages:
		var authResponse StreamAuthResponse
		err = json.Unmarshal(message, &authResponse)
		if err != nil {
			return nil, err
		}

		if authResponse.Response[0].Content.Code != 0 {
			return nil, errors.New(authResponse.Response[0].Content.Msg)
		}

		return streamingClient, nil

	case err := <-streamingClient.errors:
		return nil, err
	}

}

func findAccount(userPrincipal *UserPrincipal, accountID string) (*UserAccountInfo, error) {
	for _, acc := range userPrincipal.Accounts {
		if acc.AccountID == accountID {
			return &acc, nil
		}
	}

	return nil, fmt.Errorf("account '%s' not found", accountID)
}
