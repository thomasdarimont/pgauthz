// Package oidc handles OIDC discovery and the authorization-code token exchange.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Metadata is the subset of the OIDC discovery document the BFF needs.
type Metadata struct {
	Issuer    string `json:"issuer"`
	AuthURL   string `json:"authorization_endpoint"`
	TokenURL  string `json:"token_endpoint"`
	LogoutURL string `json:"end_session_endpoint"`
}

// Discover fetches <issuer>/.well-known/openid-configuration and returns the
// authorize/token/logout endpoints. Keycloak runs with a fixed frontend URL
// (KC_HOSTNAME) + backchannel-dynamic, so fetching from the internal issuer yields
// public browser endpoints (authorize/logout) and an internal backchannel token
// endpoint — exactly the split the BFF needs, from a single ISSUER setting.
// Retries because the BFF may start before Keycloak is reachable.
func Discover(ctx context.Context, hc *http.Client, issuer string) (Metadata, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
		var meta Metadata
		if err := func() error {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			resp, err := hc.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return json.NewDecoder(resp.Body).Decode(&meta)
		}(); err != nil {
			lastErr = err
		} else if meta.AuthURL == "" || meta.TokenURL == "" {
			lastErr = errors.New("missing authorization/token endpoint")
		} else {
			return meta, nil
		}
		log.Printf("OIDC discovery %s: attempt %d failed: %v", u, attempt, lastErr)
		select {
		case <-ctx.Done():
			return Metadata{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return Metadata{}, fmt.Errorf("OIDC discovery %s: %w", u, lastErr)
}

// TokenResp is the relevant part of a Keycloak token endpoint response.
type TokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Client performs the confidential-client token exchange against the token endpoint.
type Client struct {
	HTTP         *http.Client
	ClientID     string
	ClientSecret string
	TokenURL     string
}

// Exchange posts the given form (grant_type + grant-specific params) to the token
// endpoint, adding the client credentials, and decodes the response.
func (c *Client) Exchange(ctx context.Context, form url.Values) (*TokenResp, error) {
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, errors.New(string(body))
	}
	var t TokenResp
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Refresh exchanges a refresh token for a fresh access token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResp, error) {
	return c.Exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}
