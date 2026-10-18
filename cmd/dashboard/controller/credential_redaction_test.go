package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func TestGetProfile_RedactsPasswordHash(t *testing.T) {
	defer setupTenancyTest(t)()
	require.NoError(t, singleton.DB.AutoMigrate(&model.Oauth2Bind{}))

	passwordHash := "$2a$10$profilePasswordHashMustNotLeak012345678901"
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/profile", nil)
	c.Set(model.CtxKeyAuthorizedUser, &model.User{
		Common:   model.Common{ID: 10},
		Username: "alice",
		Password: passwordHash,
		Role:     model.RoleMember,
	})

	commonHandler(getProfile)(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), passwordHash)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, true, body["success"])
	data, ok := body["data"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "alice", data["username"])
	require.NotContains(t, data, "password")
}

func TestUpdateProfile_UsesStoredPasswordHashAfterRedaction(t *testing.T) {
	defer setupTenancyTest(t)()
	require.NoError(t, singleton.DB.AutoMigrate(&model.Oauth2Bind{}, &model.JWTSession{}))

	originalUserInfoMap := singleton.UserInfoMap
	originalAgentSecretToUserID := singleton.AgentSecretToUserId
	singleton.UserInfoMap = make(map[uint64]model.UserInfo)
	singleton.AgentSecretToUserId = make(map[string]uint64)
	defer func() {
		singleton.UserInfoMap = originalUserInfoMap
		singleton.AgentSecretToUserId = originalAgentSecretToUserID
	}()

	oldHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	require.NoError(t, err)
	user := model.User{
		Common:      model.Common{ID: 10},
		Username:    "alice",
		Password:    string(oldHash),
		Role:        model.RoleMember,
		AgentSecret: "profile-update-agent-secret",
	}
	require.NoError(t, singleton.DB.Create(&user).Error)

	_, err = updateProfile(profileUpdateContext(t, user, model.ProfileForm{
		OriginalPassword: "wrong-password",
		NewUsername:      "mallory",
		NewPassword:      "new-password",
	}))
	require.Error(t, err)

	var unchanged model.User
	require.NoError(t, singleton.DB.First(&unchanged, user.ID).Error)
	require.Equal(t, "alice", unchanged.Username)
	require.Equal(t, string(oldHash), unchanged.Password)

	_, err = updateProfile(profileUpdateContext(t, user, model.ProfileForm{
		OriginalPassword: "old-password",
		NewUsername:      "alice-renamed",
		NewPassword:      "new-password",
	}))
	require.NoError(t, err)

	var after model.User
	require.NoError(t, singleton.DB.First(&after, user.ID).Error)
	require.Equal(t, "alice-renamed", after.Username)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(after.Password), []byte("new-password")))
}

func profileUpdateContext(t *testing.T, user model.User, form model.ProfileForm) *gin.Context {
	t.Helper()

	body, err := json.Marshal(form)
	require.NoError(t, err)
	c := ctxAs(user.ID, user.Role)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/profile", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(model.CtxKeyAuthorizedUser, &user)
	return c
}

func TestListDDNS_CredentialVisibility(t *testing.T) {
	tests := []struct {
		name                string
		authenticated       bool
		uid                 uint64
		role                model.Role
		withPAT             bool
		wantOwn             bool
		wantForeign         bool
		exposeOwnSecret     bool
		exposeForeignSecret bool
	}{
		{
			name:            "jwt_member_owner_sees_own_credentials",
			authenticated:   true,
			uid:             10,
			role:            model.RoleMember,
			wantOwn:         true,
			exposeOwnSecret: true,
		},
		{
			name:                "jwt_admin_sees_all_credentials",
			authenticated:       true,
			uid:                 1,
			role:                model.RoleAdmin,
			wantOwn:             true,
			wantForeign:         true,
			exposeOwnSecret:     true,
			exposeForeignSecret: true,
		},
		{
			name:          "member_pat_redacts_access_secret",
			authenticated: true,
			uid:           10,
			role:          model.RoleMember,
			withPAT:       true,
			wantOwn:       true,
		},
		{
			name:          "admin_pat_redacts_all_access_secrets",
			authenticated: true,
			uid:           1,
			role:          model.RoleAdmin,
			withPAT:       true,
			wantOwn:       true,
			wantForeign:   true,
		},
		{
			name: "unauthenticated_does_not_expose_credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTenancyTest(t)()

			own, foreign := seedDDNSCredentialProfiles(t)
			newCtx := func(w http.ResponseWriter) *gin.Context {
				gin.SetMode(gin.TestMode)
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ddns", nil)
				if tt.authenticated {
					c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: tt.uid}, Role: tt.role})
				}
				if tt.withPAT {
					c.Set(model.CtxKeyAPIToken, &model.APIToken{ID: 9001})
				}
				return c
			}

			w := httptest.NewRecorder()
			listHandler(listDDNS)(newCtx(w))

			require.Equal(t, http.StatusOK, w.Code)
			var response model.CommonResponse[[]model.DDNSProfile]
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.True(t, response.Success)

			wantIDs := make([]uint64, 0, 2)
			gotIDs := make([]uint64, 0, len(response.Data))
			jsonProfiles := make(map[uint64]model.DDNSProfile, len(response.Data))
			for _, p := range response.Data {
				gotIDs = append(gotIDs, p.ID)
				jsonProfiles[p.ID] = p
			}
			if tt.wantOwn {
				wantIDs = append(wantIDs, own.ID)
			}
			if tt.wantForeign {
				wantIDs = append(wantIDs, foreign.ID)
			}
			require.ElementsMatch(t, wantIDs, gotIDs)

			body := w.Body.String()
			checkJSON := func(p model.DDNSProfile, want, exposeSecret bool) {
				if !want {
					require.NotContains(t, body, p.Name, "foreign DDNS configuration must not leak")
					require.NotContains(t, body, p.AccessID, "foreign DDNS access_id must not leak")
					require.NotContains(t, body, p.AccessSecret, "foreign DDNS access_secret must not leak")
					return
				}
				got, ok := jsonProfiles[p.ID]
				require.True(t, ok)
				require.Equal(t, p.AccessID, got.AccessID)
				if exposeSecret {
					require.Equal(t, p.AccessSecret, got.AccessSecret)
				} else {
					require.Empty(t, got.AccessSecret)
				}
				require.Empty(t, got.WebhookHeaders)
				require.Contains(t, body, p.Name)
				require.Contains(t, body, p.AccessID)
				if exposeSecret {
					require.Contains(t, body, p.AccessSecret)
				} else {
					require.NotContains(t, body, p.AccessSecret)
				}
			}
			checkJSON(own, tt.wantOwn, tt.exposeOwnSecret)
			checkJSON(foreign, tt.wantForeign, tt.exposeForeignSecret)

			direct, err := listDDNS(newCtx(httptest.NewRecorder()))
			require.NoError(t, err)
			directProfiles := make(map[uint64]*model.DDNSProfile, len(direct))
			for _, p := range direct {
				directProfiles[p.ID] = p
				require.Empty(t, p.WebhookHeaders, "webhook_headers must stay redacted in listDDNS")
			}
			checkDirect := func(p model.DDNSProfile, exposeSecret bool) {
				got, ok := directProfiles[p.ID]
				require.True(t, ok)
				require.Equal(t, p.AccessID, got.AccessID)
				if exposeSecret {
					require.Equal(t, p.AccessSecret, got.AccessSecret)
				} else {
					require.Empty(t, got.AccessSecret)
				}
			}
			checkDirect(own, tt.exposeOwnSecret)
			checkDirect(foreign, tt.exposeForeignSecret)

			requireDDNSCredentialsUnchanged(t, own, foreign)
		})
	}
}

func seedDDNSCredentialProfiles(t *testing.T) (model.DDNSProfile, model.DDNSProfile) {
	t.Helper()

	own := model.DDNSProfile{
		Common:         model.Common{UserID: 10},
		Name:           "owner-ddns-regression",
		Provider:       model.ProviderCloudflare,
		AccessID:       "synthetic-owner-access-id-6f5c",
		AccessSecret:   "synthetic-owner-access-secret-2b7d",
		WebhookHeaders: `{"X-Synthetic-Credential":"owner-header-91e4"}`,
	}
	foreign := model.DDNSProfile{
		Common:         model.Common{UserID: 999},
		Name:           "foreign-ddns-regression",
		Provider:       model.ProviderCloudflare,
		AccessID:       "synthetic-foreign-access-id-a83e",
		AccessSecret:   "synthetic-foreign-access-secret-f042",
		WebhookHeaders: `{"X-Synthetic-Credential":"foreign-header-57c1"}`,
	}
	for _, p := range []*model.DDNSProfile{&own, &foreign} {
		require.NoError(t, singleton.DB.Create(p).Error)
		singleton.DDNSShared.InsertForTest(p)
	}
	return own, foreign
}

func requireDDNSCredentialsUnchanged(t *testing.T, originals ...model.DDNSProfile) {
	t.Helper()

	for _, original := range originals {
		var stored model.DDNSProfile
		require.NoError(t, singleton.DB.First(&stored, original.ID).Error)
		require.Equal(t, original.AccessID, stored.AccessID)
		require.Equal(t, original.AccessSecret, stored.AccessSecret)
		require.Equal(t, original.WebhookHeaders, stored.WebhookHeaders)

		inMemory, ok := singleton.DDNSShared.Get(original.ID)
		require.True(t, ok)
		require.Equal(t, original.AccessID, inMemory.AccessID)
		require.Equal(t, original.AccessSecret, inMemory.AccessSecret)
		require.Equal(t, original.WebhookHeaders, inMemory.WebhookHeaders)
	}
}

func TestListDDNS_PATMiddlewareBridgeRedactsCredentials(t *testing.T) {
	tests := []struct {
		name  string
		scope string
	}{
		{name: "exact_ddns_read", scope: model.ScopeDDNSRead},
		{name: "nezha_wildcard", scope: model.ScopeNezhaAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer setupTenancyTest(t)()
			require.NoError(t, singleton.DB.AutoMigrate(&model.APIToken{}))

			own, foreign := seedDDNSCredentialProfiles(t)
			admin := model.User{
				Common:   model.Common{ID: 1},
				Username: "ddns-pat-admin",
				Role:     model.RoleAdmin,
			}
			require.NoError(t, singleton.DB.Create(&admin).Error)

			plaintext := "nzp_synthetic_ddns_pat_0123456789abcdef0123456789abcdef"
			token := model.APIToken{
				UserID:    admin.ID,
				Name:      "ddns-read-regression",
				TokenHash: model.HashAPIToken(plaintext),
			}
			token.SetScopes([]string{tt.scope})
			require.NoError(t, singleton.DB.Create(&token).Error)

			var legacyToken, contextToken *model.APIToken
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.GET(
				"/api/v1/ddns",
				func(c *gin.Context) { suppressAPITokenAuthWrites(c) },
				apiTokenAuthMiddleware(),
				restScopeMiddleware(model.ScopeDDNSRead),
				func(c *gin.Context) {
					legacyToken = APITokenFromContext(c)
					value, ok := c.Get(model.CtxKeyAPIToken)
					if ok {
						contextToken, _ = value.(*model.APIToken)
					}
				},
				listHandler(listDDNS),
			)

			request := httptest.NewRequest(http.MethodGet, "/api/v1/ddns", nil)
			request.Header.Set("Authorization", "Bearer "+plaintext)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.NotNil(t, legacyToken, "legacy PAT context key must be populated")
			require.NotNil(t, contextToken, "canonical PAT context key must be populated")
			require.Same(t, legacyToken, contextToken)

			var response model.CommonResponse[[]model.DDNSProfile]
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
			require.True(t, response.Success)
			require.Len(t, response.Data, 2)
			responseByID := make(map[uint64]model.DDNSProfile, len(response.Data))
			for _, profile := range response.Data {
				responseByID[profile.ID] = profile
			}
			for _, profile := range []model.DDNSProfile{own, foreign} {
				got, ok := responseByID[profile.ID]
				require.True(t, ok)
				require.Equal(t, profile.AccessID, got.AccessID)
				require.Empty(t, got.AccessSecret)
				require.Empty(t, got.WebhookHeaders)
			}
			body := recorder.Body.String()
			require.NotContains(t, body, "access_secret")
			require.NotContains(t, body, "webhook_headers")
			require.NotContains(t, body, own.AccessSecret)
			require.NotContains(t, body, foreign.AccessSecret)
			requireDDNSCredentialsUnchanged(t, own, foreign)
		})
	}
}

func TestListNotification_RedactsCredentials(t *testing.T) {
	defer setupTenancyTest(t)()

	n := model.Notification{
		Common:        model.Common{UserID: 10},
		Name:          "slack",
		URL:           "https://hooks.slack.com/services/T/B/secret",
		RequestHeader: `{"Authorization":"Bearer xxx"}`,
		RequestBody:   `{"text":"#NEZHA#"}`,
	}
	require.NoError(t, singleton.DB.Create(&n).Error)
	singleton.NotificationShared.InsertForTest(&n)

	c := ctxAs(10, model.RoleAdmin)
	out, err := listNotification(c)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Empty(t, out[0].URL, "url must be redacted in list response")
	require.Empty(t, out[0].RequestHeader, "request_header must be redacted in list response")
	require.Empty(t, out[0].RequestBody, "request_body must be redacted in list response")
	require.Equal(t, "slack", out[0].Name, "non-secret fields must be preserved")

	var stored model.Notification
	require.NoError(t, singleton.DB.First(&stored, n.ID).Error)
	require.Equal(t, "https://hooks.slack.com/services/T/B/secret", stored.URL,
		"redaction must not mutate stored data")
}

func TestUpdateDDNS_EmptySecretPreservesStored(t *testing.T) {
	defer setupTenancyTest(t)()

	existing := model.DDNSProfile{
		Common:         model.Common{UserID: 10},
		Name:           "cf",
		Provider:       "webhook",
		AccessID:       "id",
		AccessSecret:   "keep-me",
		WebhookURL:     "http://127.0.0.1/",
		WebhookMethod:  1,
		WebhookHeaders: `{"X-Token":"keep-header"}`,
	}
	require.NoError(t, singleton.DB.Create(&existing).Error)
	singleton.DDNSShared.InsertForTest(&existing)

	c := ctxAsMemberWithBody(10, map[string]any{
		"name":                 "cf-renamed",
		"provider":             "webhook",
		"access_id":            "id",
		"access_secret":        "",
		"webhook_url":          "http://127.0.0.1/",
		"webhook_method":       1,
		"webhook_request_type": 1,
		"webhook_headers":      "",
		"max_retries":          3,
	})
	c.Params = gin.Params{{Key: "id", Value: itoa(existing.ID)}}
	_, err := updateDDNS(c)
	require.NoError(t, err)

	var after model.DDNSProfile
	require.NoError(t, singleton.DB.First(&after, existing.ID).Error)
	require.Equal(t, "cf-renamed", after.Name, "non-secret edits must apply")
	require.Equal(t, "keep-me", after.AccessSecret, "empty submitted secret must preserve stored value")
	require.Equal(t, `{"X-Token":"keep-header"}`, after.WebhookHeaders,
		"empty submitted headers must preserve stored value")
}

func TestUpdateDDNS_NonEmptySecretOverwrites(t *testing.T) {
	defer setupTenancyTest(t)()

	existing := model.DDNSProfile{
		Common:        model.Common{UserID: 10},
		Name:          "cf",
		Provider:      "webhook",
		AccessSecret:  "old",
		WebhookURL:    "http://127.0.0.1/",
		WebhookMethod: 1,
	}
	require.NoError(t, singleton.DB.Create(&existing).Error)
	singleton.DDNSShared.InsertForTest(&existing)

	c := ctxAsMemberWithBody(10, map[string]any{
		"name":                 "cf",
		"provider":             "webhook",
		"access_secret":        "new-secret",
		"webhook_url":          "http://127.0.0.1/",
		"webhook_method":       1,
		"webhook_request_type": 1,
		"max_retries":          3,
	})
	c.Params = gin.Params{{Key: "id", Value: itoa(existing.ID)}}
	_, err := updateDDNS(c)
	require.NoError(t, err)

	var after model.DDNSProfile
	require.NoError(t, singleton.DB.First(&after, existing.ID).Error)
	require.Equal(t, "new-secret", after.AccessSecret, "non-empty submitted secret must overwrite")
}

func TestUpdateNotification_EmptyFieldsPreserveStored(t *testing.T) {
	defer setupTenancyTest(t)()

	existing := model.Notification{
		Common:        model.Common{UserID: 10},
		Name:          "slack",
		URL:           "https://hooks.slack.com/services/keep",
		RequestMethod: model.NotificationRequestMethodGET,
		RequestType:   model.NotificationRequestTypeJSON,
		RequestHeader: `{"Authorization":"keep"}`,
		RequestBody:   "",
	}
	require.NoError(t, singleton.DB.Create(&existing).Error)
	singleton.NotificationShared.InsertForTest(&existing)

	c := ctxAsMemberWithBody(10, map[string]any{
		"name":           "slack-renamed",
		"url":            "",
		"request_method": model.NotificationRequestMethodGET,
		"request_type":   model.NotificationRequestTypeJSON,
		"request_header": "",
		"request_body":   "",
		"skip_check":     true,
	})
	c.Params = gin.Params{{Key: "id", Value: itoa(existing.ID)}}
	_, err := updateNotification(c)
	require.NoError(t, err)

	var after model.Notification
	require.NoError(t, singleton.DB.First(&after, existing.ID).Error)
	require.Equal(t, "slack-renamed", after.Name, "non-secret edits must apply")
	require.Equal(t, "https://hooks.slack.com/services/keep", after.URL,
		"empty submitted url must preserve stored value")
	require.Equal(t, `{"Authorization":"keep"}`, after.RequestHeader,
		"empty submitted request_header must preserve stored value")
}
