package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	authorizeEndpoint = "https://accounts.spotify.com/authorize"
	tokenEndpoint     = "https://accounts.spotify.com/api/token"
)

type Result struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`

	// ExpiresIn is the optional expiration duration of the access token in seconds.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	ExpiresIn uint `json:"expires_in"`
}

type Config struct {
	ClientSecret string
	ClientId     string
	RedirectURI  string
}

func (config *Config) GetTokens(code string) (*Result, error) {
	val := url.Values{}
	val.Set("client_id", config.ClientId)
	val.Set("client_secret", config.ClientSecret)
	val.Set("redirect_uri", config.RedirectURI)
	val.Set("grant_type", "authorization_code")
	val.Set("code", code)

	return config.requestToken(val)
}

func (config *Config) RefreshAccessToken(refreshToken string) (*Result, error) {
	val := url.Values{}
	val.Set("client_id", config.ClientId)
	val.Set("client_secret", config.ClientSecret)
	val.Set("grant_type", "refresh_token")
	val.Set("refresh_token", refreshToken)

	return config.requestToken(val)
}

func (config *Config) requestToken(values url.Values) (*Result, error) {
	resp, err := http.PostForm(tokenEndpoint, values)
	if err != nil {
		// Retry since there is an nginx bug that causes http2 streams to get
		// an initial REFUSED_STREAM response
		// https://github.com/curl/curl/issues/804
		resp, err = http.PostForm(tokenEndpoint, values)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		return nil, fmt.Errorf("unexpected status content type %s", ct)
	}

	result := &Result{}

	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(result)

	if err != nil {
		return nil, err
	}

	if result.Error != "" {
		return nil, fmt.Errorf("error getting token %v", result.Error)
	}

	return result, nil
}

/*
func StartLocalOAuthServer(clientId string, clientSecret string, callback string) (string, chan OAuth) {
	ch := make(chan OAuth)

	urlPath := "https://accounts.spotify.com/authorize?" +
		"client_id=" + clientId +
		"&response_type=code" +
		"&redirect_uri=" + callback +
		"&scope=streaming"

	router := http.NewServeMux()
	server := &http.Server{
		// TODO pull port from callback
		Addr:    ":5000",
		Handler: router,
	}

	router.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		auth, err := GetOauthAccessToken(params.Get("code"), callback, clientId, clientSecret)
		if err != nil {
			fmt.Fprintf(w, "Error getting token: %q", err)
			return
		}
		fmt.Fprintf(w, "Got token, logging in.")
		ch <- *auth
		close(ch)

		time.Sleep(time.Second * 5)
		_ = server.Shutdown(context.Background())
	})

	go func() {
		_ = server.ListenAndServe()
	}()

	return urlPath, ch
}
*/

func (config *Config) AuthorizeURL() string {
	val := url.Values{}
	val.Set("client_id", config.ClientId)
	val.Set("response_type", "code")
	val.Set("redirect_uri", config.RedirectURI)
	val.Set("scope", "streaming")

	return authorizeEndpoint + "?" + val.Encode()
}

func (config *Config) SignIn() (*Result, error) {
	ch := make(chan *Result)

	fmt.Println("Go to this URL:", config.AuthorizeURL())

	// router := http.NewServeMux()
	// server := &http.Server{
	// 	// TODO pull port from callback
	// 	Addr:    ":5000",
	// 	Handler: router,
	// }
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		auth, err := config.GetTokens(params.Get("code"))
		if err != nil {
			fmt.Fprintf(w, "Error getting token %q", err)
			return
		}
		fmt.Fprintf(w, "Got token, loggin in")
		ch <- auth

		// time.Sleep(time.Second * 1)
		// _ = server.Shutdown(context.Background())
	})

	go func() {
		log.Fatal(http.ListenAndServe(":5000", nil))
	}()

	// Wait then bail
	select {
	case <-time.After(time.Second * 60):
		return nil, errors.New("timed out waiting for auth")
	case validAuth := <-ch:
		return validAuth, nil
	}
}
