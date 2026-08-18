package scimhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

type testHasher struct{}

func (testHasher) Hash(password string) (string, error) { return "hash:" + password, nil }
func (testHasher) Verify(hash, password string) (bool, bool, error) {
	return hash == "hash:"+password, false, nil
}

type testTOTP struct{}

func (testTOTP) Generate(string) (string, string, error) { return "secret", "otpauth://test", nil }
func (testTOTP) Validate(string, string, time.Time) (int64, bool) {
	return 1, true
}

type testPasskeys struct{}

func (testPasskeys) BeginRegistration(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (testPasskeys) FinishRegistration(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (testPasskeys) BeginAuthentication(context.Context, credbound.PasskeyUser) (json.RawMessage, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (testPasskeys) BeginDecoyAuthentication(context.Context, []byte) (json.RawMessage, []byte, error) {
	return nil, nil, errors.New("unused")
}
func (testPasskeys) FinishAuthentication(context.Context, credbound.PasskeyUser, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("unused")
}

type fixedReader struct{ value byte }

func (r *fixedReader) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = r.value
		r.value++
	}
	return len(target), nil
}

type httpFixture struct {
	handler *Handler
	manager *credbound.Manager
	token   string
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: testHasher{}, TOTP: testTOTP{}, Passkeys: testPasskeys{},
		SecretKey: bytes.Repeat([]byte{1}, 32), PATPepper: bytes.Repeat([]byte{2}, 32), RecoveryPepper: bytes.Repeat([]byte{3}, 32),
		Clock: func() time.Time { return now }, Random: &fixedReader{value: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, workspace, err := manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := manager.CreateSCIMConfiguration(context.Background(), credbound.Authentication{
		UserID: root.UserID, Method: credbound.MethodPasskey, Level: credbound.AAL2, AuthenticatedAt: now,
	}, workspace.ID, credbound.CreateSCIMConfigurationInput{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(manager)
	if err != nil {
		t.Fatal(err)
	}
	return &httpFixture{handler: handler, manager: manager, token: issued.Token}
}

func (f *httpFixture) request(t *testing.T, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+f.token)
	if body != "" {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func TestSCIMHTTPDiscoveryUsersGroupsAndPatch(t *testing.T) {
	f := newHTTPFixture(t)
	unauthorized := httptest.NewRecorder()
	f.handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/ServiceProviderConfig", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized response = %d %#v", unauthorized.Code, unauthorized.Header())
	}
	if response := f.request(t, http.MethodGet, "/ServiceProviderConfig", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"bulk":{"maxOperations":0`) {
		t.Fatalf("service provider config = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/ResourceTypes/User", ""); response.Code != http.StatusOK {
		t.Fatalf("resource type = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/ResourceTypes", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"totalResults":2`) {
		t.Fatalf("resource types = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Schemas/"+urlPath(coreUserSchema), ""); response.Code != http.StatusOK {
		t.Fatalf("schema = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Schemas", ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), coreGroupSchema) {
		t.Fatalf("schemas = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Schemas/missing", ""); response.Code != http.StatusNotFound {
		t.Fatalf("missing schema = %d %s", response.Code, response.Body.String())
	}

	createdResponse := f.request(t, http.MethodPost, "/Users", `{
        "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId":"directory-1","userName":"User@Example.com","displayName":"User",
        "emails":[{"value":"User@Example.com","primary":true}],"active":true,
        "title":"Engineer","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"R&D"}}`)
	if createdResponse.Code != http.StatusCreated || createdResponse.Header().Get("Location") == "" {
		t.Fatalf("create user = %d %s", createdResponse.Code, createdResponse.Body.String())
	}
	var created userResource
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &created); err != nil || created.ID == "" || created.Active == nil || !*created.Active {
		t.Fatalf("created user = %#v, %v", created, err)
	}
	if string(created.Attributes["title"]) != `"Engineer"` || !strings.Contains(string(created.Attributes["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]), "department") {
		t.Fatalf("profile attributes were not preserved: %#v", created.Attributes)
	}
	if response := f.request(t, http.MethodGet, "/Users/"+created.ID, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"title":"Engineer"`) {
		t.Fatalf("get user = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPut, "/Users/"+created.ID, `{"schemas":["`+coreUserSchema+`"],"userName":"user@example.com","password":"secret"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("replace user password = %d %s", response.Code, response.Body.String())
	}
	replaced := f.request(t, http.MethodPut, "/Users/"+created.ID, `{
        "schemas":["`+coreUserSchema+`"],"externalId":"directory-1","userName":"user@example.com",
        "displayName":"Replaced","emails":[{"value":"user@example.com","primary":true}],"active":true,"title":"Lead"}`)
	if replaced.Code != http.StatusOK || !strings.Contains(replaced.Body.String(), `"displayName":"Replaced"`) || !strings.Contains(replaced.Body.String(), `"title":"Lead"`) {
		t.Fatalf("replace user = %d %s", replaced.Code, replaced.Body.String())
	}
	profilePatch := f.request(t, http.MethodPatch, "/Users/"+created.ID, `{"schemas":["`+patchSchema+`"],"Operations":[
        {"op":"replace","path":"displayName","value":"Patched"},
        {"op":"add","path":"departmentCode","value":"ENG"},
        {"op":"remove","path":"title"}]}`)
	if profilePatch.Code != http.StatusOK || !strings.Contains(profilePatch.Body.String(), `"departmentCode":"ENG"`) || strings.Contains(profilePatch.Body.String(), `"title"`) {
		t.Fatalf("profile patch = %d %s", profilePatch.Code, profilePatch.Body.String())
	}

	list := f.request(t, http.MethodGet, `/Users?filter=userName%20eq%20%22user@example.com%22&count=1`, "")
	if list.Code != http.StatusOK || !json.Valid(list.Body.Bytes()) || !strings.Contains(list.Body.String(), created.ID) {
		t.Fatalf("user list = %d %s", list.Code, list.Body.String())
	}
	search := f.request(t, http.MethodPost, "/Users/.search", `{"schemas":["`+searchSchema+`"],"filter":"externalId eq \"directory-1\"","count":50}`)
	if search.Code != http.StatusOK || !strings.Contains(search.Body.String(), created.ID) {
		t.Fatalf("user search = %d %s", search.Code, search.Body.String())
	}

	patched := f.request(t, http.MethodPatch, "/Users/"+created.ID, `{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if patched.Code != http.StatusOK || !strings.Contains(patched.Body.String(), `"active":false`) {
		t.Fatalf("patch user = %d %s", patched.Code, patched.Body.String())
	}
	badPatch := f.request(t, http.MethodPatch, "/Users/"+created.ID, `{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","path":"password","value":"secret"}]}`)
	if badPatch.Code != http.StatusBadRequest || !strings.Contains(badPatch.Body.String(), `"scimType":"invalidValue"`) {
		t.Fatalf("unsupported patch = %d %s", badPatch.Code, badPatch.Body.String())
	}

	groupResponse := f.request(t, http.MethodPost, "/Groups", `{"schemas":["`+coreGroupSchema+`"],"externalId":"group-1","displayName":"Group","members":[{"value":"`+created.ID+`"}]}`)
	if groupResponse.Code != http.StatusCreated {
		t.Fatalf("create group = %d %s", groupResponse.Code, groupResponse.Body.String())
	}
	var group groupResource
	if err := json.Unmarshal(groupResponse.Body.Bytes(), &group); err != nil || group.ID == "" || len(group.Members) != 1 {
		t.Fatalf("created group = %#v, %v", group, err)
	}
	if response := f.request(t, http.MethodGet, "/Groups/"+group.ID, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), created.ID) {
		t.Fatalf("get group = %d %s", response.Code, response.Body.String())
	}
	replacedGroup := f.request(t, http.MethodPut, "/Groups/"+group.ID, `{"schemas":["`+coreGroupSchema+`"],"externalId":"group-1","displayName":"Replaced Group","members":[{"value":"`+created.ID+`"}]}`)
	if replacedGroup.Code != http.StatusOK || !strings.Contains(replacedGroup.Body.String(), "Replaced Group") {
		t.Fatalf("replace group = %d %s", replacedGroup.Code, replacedGroup.Body.String())
	}
	patchedGroup := f.request(t, http.MethodPatch, "/Groups/"+group.ID, `{"schemas":["`+patchSchema+`"],"Operations":[
        {"op":"replace","path":"displayName","value":"Patched Group"},
        {"op":"remove","path":"members[value eq \"`+created.ID+`\"]"}]}`)
	if patchedGroup.Code != http.StatusOK || !strings.Contains(patchedGroup.Body.String(), "Patched Group") || strings.Contains(patchedGroup.Body.String(), created.ID) {
		t.Fatalf("patch group remove member = %d %s", patchedGroup.Code, patchedGroup.Body.String())
	}
	patchedGroup = f.request(t, http.MethodPatch, "/Groups/"+group.ID, `{"schemas":["`+patchSchema+`"],"Operations":[{"op":"add","path":"members","value":[{"value":"`+created.ID+`"}]}]}`)
	if patchedGroup.Code != http.StatusOK || !strings.Contains(patchedGroup.Body.String(), created.ID) {
		t.Fatalf("patch group add member = %d %s", patchedGroup.Code, patchedGroup.Body.String())
	}
	groups := f.request(t, http.MethodGet, `/Groups?filter=externalId%20eq%20%22group-1%22`, "")
	if groups.Code != http.StatusOK || !strings.Contains(groups.Body.String(), group.ID) {
		t.Fatalf("group list = %d %s", groups.Code, groups.Body.String())
	}
	groupSearch := f.request(t, http.MethodPost, "/Groups/.search", `{"schemas":["`+searchSchema+`"],"filter":"displayName eq \"Patched Group\"","count":50}`)
	if groupSearch.Code != http.StatusOK || !strings.Contains(groupSearch.Body.String(), group.ID) {
		t.Fatalf("group search = %d %s", groupSearch.Code, groupSearch.Body.String())
	}
	if response := f.request(t, http.MethodDelete, "/Groups/"+group.ID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete group = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodDelete, "/Users/"+created.ID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete user = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Users/"+created.ID, ""); response.Code != http.StatusNotFound {
		t.Fatalf("deprovisioned user GET = %d %s", response.Code, response.Body.String())
	}
}

func TestSCIMHTTPValidationAndMethods(t *testing.T) {
	f := newHTTPFixture(t)
	principal, err := f.manager.AuthenticateSCIM(context.Background(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func(http.ResponseWriter){
		"empty_user": func(w http.ResponseWriter) {
			f.handler.user(w, httptest.NewRequest(http.MethodGet, "/Users/", nil), principal, "")
		},
		"empty_group": func(w http.ResponseWriter) {
			f.handler.group(w, httptest.NewRequest(http.MethodGet, "/Groups/", nil), principal, "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			call(response)
			if response.Code != http.StatusNotFound {
				t.Fatalf("empty id = %d", response.Code)
			}
		})
	}
	for name, call := range map[string]func(http.ResponseWriter){
		"delete_user_with_invalid_principal": func(w http.ResponseWriter) {
			f.handler.user(w, httptest.NewRequest(http.MethodDelete, "/Users/missing", nil), credbound.SCIMAuthentication{}, "missing")
		},
		"delete_group_with_invalid_principal": func(w http.ResponseWriter) {
			f.handler.group(w, httptest.NewRequest(http.MethodDelete, "/Groups/missing", nil), credbound.SCIMAuthentication{}, "missing")
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			call(response)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("invalid principal = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if response := f.request(t, http.MethodPost, "/Users", `{"schemas":["`+coreUserSchema+`"],"userName":"user@example.com","password":"do-not-store"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("password = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Users", `{}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid user = %d %s", response.Code, response.Body.String())
	}
	validUser := `{"schemas":["` + coreUserSchema + `"],"userName":"missing@example.com","emails":[{"value":"missing@example.com"}],"active":true}`
	if response := f.request(t, http.MethodPut, "/Users/missing", `{"userName":"missing@example.com","emails":[{"value":"missing@example.com"}]}`); response.Code != http.StatusBadRequest {
		t.Fatalf("replace user without schema = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPut, "/Users/missing", validUser); response.Code != http.StatusNotFound {
		t.Fatalf("replace missing user = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPatch, "/Users/missing", `{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","path":"active","value":true}]}`); response.Code != http.StatusNotFound {
		t.Fatalf("patch missing user = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Users/missing", `{}`); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("user item method = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Groups", `{}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid group = %d %s", response.Code, response.Body.String())
	}
	validGroup := `{"schemas":["` + coreGroupSchema + `"],"externalId":"missing","displayName":"Missing"}`
	if response := f.request(t, http.MethodPut, "/Groups/missing", `{"displayName":"Missing"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("replace group without schema = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPut, "/Groups/missing", validGroup); response.Code != http.StatusNotFound {
		t.Fatalf("replace missing group = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPatch, "/Groups/missing", `{"schemas":["`+patchSchema+`"],"Operations":[{"op":"replace","path":"displayName","value":"Missing"}]}`); response.Code != http.StatusNotFound {
		t.Fatalf("patch missing group = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Groups/missing", `{}`); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("group item method = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, `/Users?filter=title%20co%20%22x%22`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported filter = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, `/Users?filter=title%20eq%20%22x%22`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported user attribute = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, `/Groups?filter=active%20eq%20true`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported group attribute = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, `/Users?filter=active%20eq%20maybe`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("malformed filter = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, `/Users?count=101`, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid count = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Users/.search", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET search = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodGet, "/Groups/.search", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET group search = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Users/.search", `{"schemas":["wrong"],"count":50}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid search schema = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/Groups/.search", `{"schemas":["wrong"],"count":50}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid group search schema = %d %s", response.Code, response.Body.String())
	}
	for _, target := range []string{"/Users/.search", "/Groups/.search"} {
		if response := f.request(t, http.MethodPost, target, `{"schemas":["`+searchSchema+`"],"count":101}`); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid search count %s = %d %s", target, response.Code, response.Body.String())
		}
	}
	for _, target := range []string{"/Users/.search", "/Groups/.search"} {
		if response := f.request(t, http.MethodPost, target, `{`); response.Code != http.StatusBadRequest {
			t.Fatalf("malformed search %s = %d %s", target, response.Code, response.Body.String())
		}
	}
	if response := f.request(t, http.MethodPost, "/Users", `{} {}`); response.Code != http.StatusBadRequest {
		t.Fatalf("multiple JSON values = %d %s", response.Code, response.Body.String())
	}
	for _, target := range []string{"/Users/missing", "/Groups/missing"} {
		if response := f.request(t, http.MethodPut, target, `{`); response.Code != http.StatusBadRequest {
			t.Fatalf("malformed replacement %s = %d %s", target, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/Users", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("content type = %d %s", response.Code, response.Body.String())
	}
	if response := f.request(t, http.MethodPost, "/ServiceProviderConfig", `{}`); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method = %d %#v", response.Code, response.Header())
	}
	for _, request := range []struct {
		method string
		target string
	}{
		{http.MethodPost, "/ResourceTypes"},
		{http.MethodPost, "/Schemas"},
		{http.MethodDelete, "/Users"},
		{http.MethodDelete, "/Groups"},
	} {
		if response := f.request(t, request.method, request.target, `{}`); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("unsupported method %s %s = %d %s", request.method, request.target, response.Code, response.Body.String())
		}
	}
	request = httptest.NewRequest(http.MethodPost, "/Users", io.LimitReader(strings.NewReader(strings.Repeat("x", maxRequestBody+1)), maxRequestBody+1))
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "application/scim+json")
	response = httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d", response.Code)
	}
	if _, err := New(nil); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("nil manager = %v", err)
	}
	for name, err := range map[string]error{
		"forbidden": credbound.ErrForbidden, "not_found": credbound.ErrNotFound, "conflict": credbound.ErrConflict,
		"unsupported": credbound.ErrNotSupported, "internal": errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeError(response, err)
			if response.Code < 400 {
				t.Fatalf("error status = %d", response.Code)
			}
		})
	}
	for _, target := range []string{"/missing", "/ResourceTypes/missing", "/Users/missing", "/Groups/missing"} {
		if response := f.request(t, http.MethodGet, target, ""); response.Code != http.StatusNotFound {
			t.Fatalf("missing %s = %d", target, response.Code)
		}
	}
	malformedAuth := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Schemas", nil)
	req.Header.Set("Authorization", "Basic value")
	f.handler.ServeHTTP(malformedAuth, req)
	if malformedAuth.Code != http.StatusUnauthorized {
		t.Fatalf("malformed auth = %d", malformedAuth.Code)
	}
}

func TestStreamingListBranches(t *testing.T) {
	response := httptest.NewRecorder()
	writeList[int](response, func(yield func(credbound.PageEvent[int], error) bool) {
		yield(credbound.PageEvent[int]{}, errors.New("stream failed"))
	}, func(value int) any { return value })
	if response.Code != http.StatusInternalServerError || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("stream error status = %d", response.Code)
	}
	// A serialization failure surfaces as a real SCIM error, never a
	// truncated 200 the client would trust.
	response = httptest.NewRecorder()
	writeList[int](response, func(yield func(credbound.PageEvent[int], error) bool) {
		yield(credbound.ItemEvent(1), nil)
	}, func(int) any { return make(chan int) })
	if response.Code != http.StatusInternalServerError || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("marshal error = %d %s", response.Code, response.Body.String())
	}
	// So does a read failure in the middle of the page.
	response = httptest.NewRecorder()
	writeList[int](response, func(yield func(credbound.PageEvent[int], error) bool) {
		if !yield(credbound.ItemEvent(1), nil) {
			return
		}
		yield(credbound.PageEvent[int]{}, errors.New("stream failed mid-page"))
	}, func(value int) any { return value })
	if response.Code != http.StatusInternalServerError || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("mid-page error = %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	writeList[int](response, func(yield func(credbound.PageEvent[int], error) bool) {
		if !yield(credbound.ItemEvent(1), nil) {
			return
		}
		if !yield(credbound.ItemEvent(2), nil) {
			return
		}
		yield(credbound.EndEvent[int](credbound.PageEnd{HasMore: true, NextCursor: "next"}), nil)
	}, func(value int) any { return value })
	if !json.Valid(response.Body.Bytes()) || !strings.Contains(response.Body.String(), `"Resources":[1,2]`) || !strings.Contains(response.Body.String(), `"nextCursor":"next"`) {
		t.Fatalf("cursor list = %s", response.Body.String())
	}
}

func urlPath(value string) string {
	return strings.ReplaceAll(value, ":", "%3A")
}

func TestPatchAndFilterHelpers(t *testing.T) {
	active := true
	current := credbound.SCIMUser{
		ExternalID: "external", UserName: "user@example.com", DisplayName: "User", Active: true,
		Emails: []credbound.SCIMEmail{{Value: "user@example.com", Primary: true}}, Attributes: map[string]json.RawMessage{"title": json.RawMessage(`"Engineer"`)},
	}
	request := patchRequest{Schemas: []string{patchSchema}, Operations: []patchOperation{
		{Op: "replace", Path: "userName", Value: json.RawMessage(`"new@example.com"`)},
		{Op: "remove", Path: "displayName"}, {Op: "remove", Path: "externalId"}, {Op: "remove", Path: "emails"},
		{Op: "replace", Path: "active", Value: json.RawMessage(`false`)},
		{Op: "add", Value: mustJSON(t, userResource{DisplayName: "Object", Active: &active, Attributes: map[string]json.RawMessage{"locale": json.RawMessage(`"fr"`)}})},
	}}
	patched, err := patchUser(current, request)
	if err != nil || patched.UserName != "new@example.com" || patched.DisplayName != "Object" || !patched.Active || string(patched.Attributes["locale"]) != `"fr"` {
		t.Fatalf("patched user = %#v, %v", patched, err)
	}
	for name, request := range map[string]patchRequest{
		"schema":            {},
		"operation":         {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "move", Path: "active"}}},
		"remove object":     {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "remove"}}},
		"invalid object":    {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Value: json.RawMessage(`{`)}}},
		"password object":   {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Value: json.RawMessage(`{"password":"secret"}`)}}},
		"nested":            {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "name.givenName", Value: json.RawMessage(`"A"`)}}},
		"invalid active":    {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "active", Value: json.RawMessage(`"yes"`)}}},
		"invalid username":  {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "userName", Value: json.RawMessage(`{`)}}},
		"invalid display":   {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "displayName", Value: json.RawMessage(`{`)}}},
		"invalid external":  {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "externalId", Value: json.RawMessage(`{`)}}},
		"invalid emails":    {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "emails", Value: json.RawMessage(`{`)}}},
		"invalid attribute": {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "locale", Value: json.RawMessage(`{`)}}},
	} {
		t.Run("user_"+name, func(t *testing.T) {
			if _, err := patchUser(current, request); err == nil {
				t.Fatal("invalid user patch accepted")
			}
		})
	}

	group := credbound.SCIMGroup{ExternalID: "external", DisplayName: "Group", MemberIDs: []string{"one", "two"}}
	groupRequest := patchRequest{Schemas: []string{patchSchema}, Operations: []patchOperation{
		{Op: "replace", Path: "displayName", Value: json.RawMessage(`"Changed"`)},
		{Op: "remove", Path: "externalId"},
		{Op: "replace", Path: "members", Value: json.RawMessage(`[{"value":"three"}]`)},
		{Op: "remove", Path: "members"},
	}}
	patchedGroup, err := patchGroup(group, groupRequest)
	if err != nil || patchedGroup.DisplayName != "Changed" || patchedGroup.ExternalID != "" || len(patchedGroup.MemberIDs) != 0 {
		t.Fatalf("patched group = %#v, %v", patchedGroup, err)
	}
	for name, request := range map[string]patchRequest{
		"schema":              {},
		"operation":           {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "move", Path: "members"}}},
		"path":                {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "unknown", Value: json.RawMessage(`true`)}}},
		"members":             {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "members", Value: json.RawMessage(`{}`)}}},
		"remove display":      {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "remove", Path: "displayName"}}},
		"invalid display":     {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "displayName", Value: json.RawMessage(`{`)}}},
		"invalid external":    {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "replace", Path: "externalId", Value: json.RawMessage(`{`)}}},
		"malformed selection": {Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "remove", Path: `members[value eq broken]`}}},
	} {
		t.Run("group_"+name, func(t *testing.T) {
			if _, err := patchGroup(group, request); err == nil {
				t.Fatal("invalid group patch accepted")
			}
		})
	}
	if filter, err := parseFilter(`active eq true`); err != nil || filter.Value != "true" {
		t.Fatalf("boolean filter = %#v, %v", filter, err)
	}
	if _, err := parseFilter(`userName eq "unterminated`); err == nil {
		t.Fatal("malformed quoted filter accepted")
	}
	if schemas := userSchemas([]string{coreUserSchema, "", "urn:example"}); len(schemas) != 2 {
		t.Fatalf("user schemas = %#v", schemas)
	}
	withoutAttributes := current
	withoutAttributes.Attributes = nil
	patched, err = patchUser(withoutAttributes, patchRequest{Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "add", Path: "locale", Value: json.RawMessage(`"fr"`)}}})
	if err != nil || string(patched.Attributes["locale"]) != `"fr"` {
		t.Fatalf("initialized profile attributes = %#v, %v", patched.Attributes, err)
	}
	filtered, err := patchGroup(group, patchRequest{Schemas: []string{patchSchema}, Operations: []patchOperation{{Op: "remove", Path: `members[value eq "one"]`}}})
	if err != nil || len(filtered.MemberIDs) != 1 || filtered.MemberIDs[0] != "two" {
		t.Fatalf("filtered group members = %#v, %v", filtered.MemberIDs, err)
	}
	if payload, err := json.Marshal(userResource{Attributes: map[string]json.RawMessage{"broken": json.RawMessage(`{`)}}); err != nil || strings.Contains(string(payload), "broken") {
		t.Fatalf("invalid profile JSON was not ignored: %s, %v", payload, err)
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
