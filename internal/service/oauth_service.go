package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2"
)

type MapClaims func(claims map[string]any) model.Claims
type OAuthUserinfoExtractor func(client *http.Client, ctx context.Context, url string, mapClaims MapClaims) (*model.Claims, error)

type OAuthService struct {
	serviceCfg        model.OAuthServiceConfig
	config            *oauth2.Config
	ctx               context.Context
	userinfoExtractor OAuthUserinfoExtractor
	id                string
}

func NewOAuthService(config model.OAuthServiceConfig, id string, ctx context.Context) *OAuthService {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Insecure,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	vctx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	return &OAuthService{
		serviceCfg: config,
		config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthURL,
				TokenURL: config.TokenURL,
			},
		},
		ctx:               vctx,
		userinfoExtractor: defaultExtractor,
		id:                id,
	}
}

func (s *OAuthService) WithUserinfoExtractor(extractor OAuthUserinfoExtractor) *OAuthService {
	s.userinfoExtractor = extractor
	return s
}

func (s *OAuthService) Name() string {
	return s.serviceCfg.Name
}

func (s *OAuthService) ID() string {
	return s.id
}

func (s *OAuthService) NewRandom() string {
	// The generate verifier function just creates a random string,
	// so we can use it to generate a random state as well
	random := oauth2.GenerateVerifier()
	return random
}

func (s *OAuthService) GetAuthURL(state, verifier string) string {
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
}

func (s *OAuthService) GetToken(code string, verifier string) (*oauth2.Token, error) {
	return s.config.Exchange(s.ctx, code, oauth2.VerifierOption(verifier))
}

func (s *OAuthService) GetUserinfo(token *oauth2.Token) (*model.Claims, error) {
	client := oauth2.NewClient(s.ctx, oauth2.StaticTokenSource(token))
	claims, err := s.userinfoExtractor(client, s.ctx, s.serviceCfg.UserinfoURL, s.mapClaims)
	if err != nil {
		return nil, err
	}

	// aralab: Microsoft Entra ID does not return groups from its userinfo endpoint,
	// only in the ID token. Fall back to the ID token's groups claim when userinfo has none.
	if claims != nil && claims.Groups == nil {
		if idClaims, err := s.IDTokenClaims(token); err == nil && idClaims.Groups != nil {
			claims.Groups = idClaims.Groups
		}
	}

	return claims, nil
}

// aralab: IDTokenClaims holds the ID token claims used for group handling.
type IDTokenClaims struct {
	Sub    string
	Groups any
}

// IDTokenClaims decodes the id_token returned alongside an OAuth token. The
// signature is not verified: the token was received directly from the token
// endpoint over TLS by this server, which OIDC Core 3.1.3.7 allows in place of
// signature validation. Never call this on a token supplied by a client.
func (s *OAuthService) IDTokenClaims(token *oauth2.Token) (*IDTokenClaims, error) {
	if token == nil {
		return nil, errors.New("no token")
	}

	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("no id_token in token response")
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode id_token payload: %w", err)
	}

	var kv map[string]any
	if err := json.Unmarshal(payload, &kv); err != nil {
		return nil, fmt.Errorf("failed to parse id_token payload: %w", err)
	}

	if aud, ok := kv["aud"].(string); ok && aud != s.config.ClientID {
		return nil, fmt.Errorf("id_token audience mismatch")
	}

	return &IDTokenClaims{
		Sub:    mapClaim[string]("sub", "", kv),
		Groups: mapClaim[any]("groups", s.serviceCfg.Claims.Groups, kv),
	}, nil
}

// aralab: RefreshToken exchanges a refresh token for a new token set, used to
// re-read group membership without forcing the user to log in again.
func (s *OAuthService) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("no refresh token provided")
	}
	return s.config.TokenSource(s.ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

func (s *OAuthService) GetConfig() model.OAuthServiceConfig {
	return s.serviceCfg
}

func (s *OAuthService) UpdateConfig(config model.OAuthServiceConfig) {
	s.serviceCfg = config
	s.config.ClientID = config.ClientID
	s.config.ClientSecret = config.ClientSecret
	s.config.Scopes = config.Scopes
	s.config.Endpoint.AuthURL = config.AuthURL
	s.config.Endpoint.TokenURL = config.TokenURL
	s.config.RedirectURL = config.RedirectURL
}

func (s *OAuthService) mapClaims(claims map[string]any) model.Claims {
	return model.Claims{
		Sub:               mapClaim[string]("sub", "", claims),
		Name:              mapClaim[string]("name", s.serviceCfg.Claims.Name, claims),
		PreferredUsername: mapClaim[string]("preferred_username", s.serviceCfg.Claims.Username, claims),
		Email:             mapClaim[string]("email", s.serviceCfg.Claims.Email, claims),
		Groups:            mapClaim[any]("groups", s.serviceCfg.Claims.Groups, claims),
	}
}

func mapClaim[T any](fallback, override string, kv map[string]any) T {
	key := fallback
	if override != "" {
		key = override
	}
	v, ok := kv[key].(T)
	if !ok {
		var zero T
		return zero
	}
	return v
}
