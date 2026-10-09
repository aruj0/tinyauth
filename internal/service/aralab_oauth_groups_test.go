package service

// aralab: tests for the Entra ID group handling (ID token groups fallback and
// group refresh on 403 via refresh token).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/repository/memory"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"golang.org/x/oauth2"
)

const testClientID = "test-client"

func fakeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func tokenWithIDToken(t *testing.T, claims map[string]any) *oauth2.Token {
	t.Helper()
	return (&oauth2.Token{AccessToken: "at", RefreshToken: "rt-login"}).WithExtra(map[string]any{
		"id_token": fakeIDToken(t, claims),
	})
}

// fakeProvider serves a token endpoint (refresh grant) and a userinfo endpoint without groups.
type fakeProvider struct {
	server        *httptest.Server
	sub           atomic.Value
	groups        atomic.Value
	refreshCalls  atomic.Int32
	failRefresh   atomic.Bool
	lastRefreshRT atomic.Value
}

func newFakeProvider(t *testing.T) *fakeProvider {
	p := &fakeProvider{}
	p.sub.Store("user-sub")
	p.groups.Store([]string{"group-a"})

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		p.refreshCalls.Add(1)
		p.lastRefreshRT.Store(r.Form.Get("refresh_token"))
		if p.failRefresh.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at2",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-rotated",
			"id_token": fakeIDToken(t, map[string]any{
				"aud":    testClientID,
				"sub":    p.sub.Load().(string),
				"groups": p.groups.Load().([]string),
			}),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"user-sub","email":"user@example.com","name":"User"}`))
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) service() *OAuthService {
	return NewOAuthService(model.OAuthServiceConfig{
		ClientID:     testClientID,
		ClientSecret: "secret",
		TokenURL:     p.server.URL + "/token",
		AuthURL:      p.server.URL + "/authorize",
		UserinfoURL:  p.server.URL + "/userinfo",
	}, "microsoft", context.Background())
}

func newTestAuthService(t *testing.T, svc IOAuthService) (*AuthService, repository.Store) {
	t.Helper()
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	store := memory.New()
	auth := &AuthService{
		log:     log,
		config:  &model.Config{Auth: model.AuthConfig{SessionExpiry: 3600}},
		runtime: &model.RuntimeConfig{},
		queries: store,
		oauthBroker: &OAuthBrokerService{
			log:      log,
			services: map[string]IOAuthService{"microsoft": svc},
		},
	}
	auth.caches.oauthRefresh = cache.NewCacheStore[OAuthRefreshEntry](MaxOAuthRefreshEntries)
	return auth, store
}

func createOAuthSession(t *testing.T, store repository.Store, uuid string, groups string) {
	t.Helper()
	_, err := store.CreateSession(context.Background(), repository.CreateSessionParams{
		UUID:        uuid,
		Username:    "user",
		Email:       "user@example.com",
		Provider:    "microsoft",
		OAuthGroups: groups,
		Expiry:      time.Now().Add(time.Hour).Unix(),
		CreatedAt:   time.Now().Unix(),
		OAuthSub:    "user-sub",
	})
	require.NoError(t, err)
}

func TestUserinfoFallsBackToIDTokenGroups(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()

	claims, err := svc.GetUserinfo(tokenWithIDToken(t, map[string]any{
		"aud": testClientID, "sub": "user-sub", "groups": []string{"g1", "g2"},
	}))
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, []any{"g1", "g2"}, claims.Groups)
}

func TestIDTokenClaimsRejectsForeignAudience(t *testing.T) {
	svc := newFakeProvider(t).service()

	_, err := svc.IDTokenClaims(tokenWithIDToken(t, map[string]any{
		"aud": "someone-else", "sub": "user-sub", "groups": []string{"g1"},
	}))
	assert.Error(t, err)

	claims, err := svc.GetUserinfo(tokenWithIDToken(t, map[string]any{
		"aud": "someone-else", "sub": "user-sub", "groups": []string{"g1"},
	}))
	require.NoError(t, err)
	assert.Nil(t, claims.Groups, "groups from a foreign-audience id_token must be ignored")
}

func TestRefreshOAuthGroupsUpdatesSession(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)
	ctx := context.Background()

	createOAuthSession(t, store, "s1", "group-a")
	auth.StoreOAuthRefreshToken("s1", svc, tokenWithIDToken(t, map[string]any{"aud": testClientID, "sub": "user-sub"}))

	p.groups.Store([]string{"group-a", "group-b"})
	groups, err := auth.RefreshOAuthGroups(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, []string{"group-a", "group-b"}, groups)
	assert.Equal(t, "rt-login", p.lastRefreshRT.Load())

	session, err := store.GetSession(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "group-a,group-b", session.OAuthGroups)

	entry, ok := auth.caches.oauthRefresh.Get("s1")
	require.True(t, ok)
	assert.Equal(t, "rt-rotated", entry.RefreshToken, "rotated refresh token must be kept")
}

func TestRefreshOAuthGroupsCooldown(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)
	ctx := context.Background()

	createOAuthSession(t, store, "s1", "group-a")
	auth.StoreOAuthRefreshToken("s1", svc, tokenWithIDToken(t, map[string]any{"aud": testClientID, "sub": "user-sub"}))

	_, err := auth.RefreshOAuthGroups(ctx, "s1")
	require.NoError(t, err)
	_, err = auth.RefreshOAuthGroups(ctx, "s1")
	assert.Error(t, err)
	assert.Equal(t, int32(1), p.refreshCalls.Load(), "second refresh inside cooldown must not reach the provider")
}

func TestRefreshOAuthGroupsRejectsSubjectMismatch(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)
	ctx := context.Background()

	createOAuthSession(t, store, "s1", "group-a")
	auth.StoreOAuthRefreshToken("s1", svc, tokenWithIDToken(t, map[string]any{"aud": testClientID, "sub": "user-sub"}))

	p.sub.Store("other-user")
	p.groups.Store([]string{"admins"})
	_, err := auth.RefreshOAuthGroups(ctx, "s1")
	assert.Error(t, err)

	session, err := store.GetSession(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "group-a", session.OAuthGroups, "groups must not change on subject mismatch")

	_, ok := auth.caches.oauthRefresh.Get("s1")
	assert.False(t, ok, "refresh token must be dropped on subject mismatch")
}

func TestRefreshOAuthGroupsFailureDropsToken(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)

	createOAuthSession(t, store, "s1", "group-a")
	auth.StoreOAuthRefreshToken("s1", svc, tokenWithIDToken(t, map[string]any{"aud": testClientID, "sub": "user-sub"}))

	p.failRefresh.Store(true)
	_, err := auth.RefreshOAuthGroups(context.Background(), "s1")
	assert.Error(t, err)

	_, ok := auth.caches.oauthRefresh.Get("s1")
	assert.False(t, ok)
}

func TestRefreshOAuthGroupsWithoutToken(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)

	createOAuthSession(t, store, "s1", "group-a")
	// Token response without id_token subject: nothing stored
	auth.StoreOAuthRefreshToken("s1", svc, &oauth2.Token{AccessToken: "at", RefreshToken: "rt"})

	_, err := auth.RefreshOAuthGroups(context.Background(), "s1")
	assert.Error(t, err)
	assert.Equal(t, int32(0), p.refreshCalls.Load())
}

func TestDeleteSessionDropsRefreshToken(t *testing.T) {
	p := newFakeProvider(t)
	svc := p.service()
	auth, store := newTestAuthService(t, svc)

	createOAuthSession(t, store, "s1", "group-a")
	auth.StoreOAuthRefreshToken("s1", svc, tokenWithIDToken(t, map[string]any{"aud": testClientID, "sub": "user-sub"}))

	_, err := auth.DeleteSession(context.Background(), "s1")
	require.NoError(t, err)

	_, ok := auth.caches.oauthRefresh.Get("s1")
	assert.False(t, ok)
}
