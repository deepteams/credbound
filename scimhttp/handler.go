// Package scimhttp exposes Credbound's optional SCIM 2.0 provisioning
// adapter (RFC 7643/7644): Users, Groups, /.search, PATCH, discovery
// endpoints and SCIM-shaped errors, all delegated to a Manager whose store
// implements credbound.SCIMStore.
//
// It does not start a server; hosts normally mount Handler below /scim/v2
// with http.StripPrefix:
//
//	scim, err := scimhttp.New(manager)
//	mux.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim))
//
// Every request must carry a SCIM bearer credential issued by Credbound;
// TLS and request throttling remain the host's responsibility.
package scimhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deepteams/credbound"
)

const (
	coreUserSchema   = "urn:ietf:params:scim:schemas:core:2.0:User"
	coreGroupSchema  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	listSchema       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema      = "urn:ietf:params:scim:api:messages:2.0:Error"
	patchSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	searchSchema     = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	maxRequestBody   = 1 << 20
	defaultPageLimit = 50
)

// Handler serves the SCIM 2.0 endpoints for identity-provider directory
// sync. Authentication, workspace scoping and audit are enforced by the
// Manager per request; the handler only speaks the protocol.
type Handler struct {
	manager *credbound.Manager
}

// New returns a Handler backed by manager, which is required and must have
// been built over a store with SCIM capability for requests to succeed.
func New(manager *credbound.Manager) (*Handler, error) {
	if manager == nil {
		return nil, fmt.Errorf("%w: SCIM manager is required", credbound.ErrInvalidInput)
	}
	return &Handler{manager: manager}, nil
}

// ServeHTTP authenticates the SCIM bearer token, then routes the request to
// the discovery, Users or Groups endpoints relative to the mount point.
// Failures are answered as application/scim+json error documents.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	principal, err := h.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		writeError(w, err)
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	switch {
	case path == "/ServiceProviderConfig":
		h.serviceProviderConfig(w, r)
	case path == "/ResourceTypes" || strings.HasPrefix(path, "/ResourceTypes/"):
		h.resourceTypes(w, r, path)
	case path == "/Schemas" || strings.HasPrefix(path, "/Schemas/"):
		h.schemas(w, r, path)
	case path == "/Users" || path == "/Users/.search":
		h.users(w, r, principal, path == "/Users/.search")
	case strings.HasPrefix(path, "/Users/"):
		h.resource(w, r, principal, strings.TrimPrefix(path, "/Users/"), h.user)
	case path == "/Groups" || path == "/Groups/.search":
		h.groups(w, r, principal, path == "/Groups/.search")
	case strings.HasPrefix(path, "/Groups/"):
		h.resource(w, r, principal, strings.TrimPrefix(path, "/Groups/"), h.group)
	default:
		writeError(w, credbound.ErrNotFound)
	}
}

func (h *Handler) authenticate(r *http.Request) (credbound.SCIMAuthentication, error) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return credbound.SCIMAuthentication{}, credbound.ErrInvalidCredentials
	}
	return h.manager.AuthenticateSCIM(r.Context(), strings.TrimSpace(token))
}

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]bool{"supported": true}, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter": map[string]any{"supported": true, "maxResults": 100}, "changePassword": map[string]bool{"supported": false},
		"sort": map[string]bool{"supported": false}, "etag": map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer Token", "description": "Credbound SCIM service credential", "primary": true}},
	})
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	resources := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": coreUserSchema},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": coreGroupSchema},
	}
	if path == "/ResourceTypes" {
		writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{listSchema}, "totalResults": len(resources), "Resources": resources})
		return
	}
	id, _ := url.PathUnescape(strings.TrimPrefix(path, "/ResourceTypes/"))
	for _, resource := range resources {
		if resource["id"] == id {
			writeJSON(w, http.StatusOK, resource)
			return
		}
	}
	writeError(w, credbound.ErrNotFound)
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	resources := []map[string]any{userSchema(), groupSchema()}
	if path == "/Schemas" {
		writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{listSchema}, "totalResults": len(resources), "Resources": resources})
		return
	}
	id, _ := url.PathUnescape(strings.TrimPrefix(path, "/Schemas/"))
	for _, resource := range resources {
		if resource["id"] == id {
			writeJSON(w, http.StatusOK, resource)
			return
		}
	}
	writeError(w, credbound.ErrNotFound)
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request, principal credbound.SCIMAuthentication, search bool) {
	switch r.Method {
	case http.MethodGet:
		if search {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		filter, page, err := listParameters(r.URL.Query().Get("filter"), r.URL.Query().Get("cursor"), r.URL.Query().Get("count"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeUserList(w, h.manager.SCIMUsers(r.Context(), principal, filter, page))
	case http.MethodPost:
		if search {
			var request searchRequest
			if err := decodeBody(w, r, &request); err != nil {
				writeError(w, err)
				return
			}
			if !hasSchema(request.Schemas, searchSchema) {
				writeError(w, fmt.Errorf("%w: invalid SearchRequest schema", credbound.ErrInvalidInput))
				return
			}
			filter, page, err := listParameters(request.Filter, request.Cursor, strconv.Itoa(request.Count))
			if err != nil {
				writeError(w, err)
				return
			}
			writeUserList(w, h.manager.SCIMUsers(r.Context(), principal, filter, page))
			return
		}
		var request userResource
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		if !hasSchema(request.Schemas, coreUserSchema) {
			writeError(w, fmt.Errorf("%w: core User schema is required", credbound.ErrInvalidInput))
			return
		}
		if request.Password != "" {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "password is not supported")
			return
		}
		created, err := h.manager.ProvisionSCIMUser(r.Context(), principal, request.input(true))
		if err != nil {
			writeError(w, err)
			return
		}
		resource := userFromDomain(created)
		w.Header().Set("Location", resource.Meta.Location)
		writeJSON(w, http.StatusCreated, resource)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request, principal credbound.SCIMAuthentication, id credbound.UUID) {
	if id == (credbound.UUID{}) {
		writeError(w, credbound.ErrNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, err := h.manager.SCIMUser(r.Context(), principal, id)
		if err == nil && value.DeprovisionedAt != nil {
			err = credbound.ErrNotFound
		}
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, userFromDomain(value))
	case http.MethodPut:
		var request userResource
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		if !hasSchema(request.Schemas, coreUserSchema) {
			writeError(w, fmt.Errorf("%w: core User schema is required", credbound.ErrInvalidInput))
			return
		}
		if request.Password != "" {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "password is not supported")
			return
		}
		value, err := h.manager.ReplaceSCIMUser(r.Context(), principal, id, request.input(true))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, userFromDomain(value))
	case http.MethodPatch:
		current, err := h.manager.SCIMUser(r.Context(), principal, id)
		if err != nil || current.DeprovisionedAt != nil {
			if err == nil {
				err = credbound.ErrNotFound
			}
			writeError(w, err)
			return
		}
		var request patchRequest
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		input, err := patchUser(current, request)
		if err != nil {
			writeError(w, err)
			return
		}
		value, err := h.manager.ReplaceSCIMUser(r.Context(), principal, id, input)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, userFromDomain(value))
	case http.MethodDelete:
		if err := h.manager.DeprovisionSCIMUser(r.Context(), principal, id); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

func (h *Handler) groups(w http.ResponseWriter, r *http.Request, principal credbound.SCIMAuthentication, search bool) {
	switch r.Method {
	case http.MethodGet:
		if search {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		filter, page, err := listParameters(r.URL.Query().Get("filter"), r.URL.Query().Get("cursor"), r.URL.Query().Get("count"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeGroupList(w, h.manager.SCIMGroups(r.Context(), principal, filter, page))
	case http.MethodPost:
		if search {
			var request searchRequest
			if err := decodeBody(w, r, &request); err != nil {
				writeError(w, err)
				return
			}
			if !hasSchema(request.Schemas, searchSchema) {
				writeError(w, fmt.Errorf("%w: invalid SearchRequest schema", credbound.ErrInvalidInput))
				return
			}
			filter, page, err := listParameters(request.Filter, request.Cursor, strconv.Itoa(request.Count))
			if err != nil {
				writeError(w, err)
				return
			}
			writeGroupList(w, h.manager.SCIMGroups(r.Context(), principal, filter, page))
			return
		}
		var request groupResource
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		if !hasSchema(request.Schemas, coreGroupSchema) {
			writeError(w, fmt.Errorf("%w: core Group schema is required", credbound.ErrInvalidInput))
			return
		}
		created, err := h.manager.UpsertSCIMGroup(r.Context(), principal, credbound.UUID{}, request.input())
		if err != nil {
			writeError(w, err)
			return
		}
		resource := groupFromDomain(created)
		w.Header().Set("Location", resource.Meta.Location)
		writeJSON(w, http.StatusCreated, resource)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// resource parses the identifier a request path addresses before handing it to
// the resource handler. A malformed one is "not found" rather than a protocol
// error: from a provisioning client's point of view, an identifier that cannot
// exist addresses nothing.
//
// The method is checked first, because being unsupported is a property of the
// resource rather than of the instance addressed: POST on an item answers 405
// whatever the identifier says.
func (h *Handler) resource(w http.ResponseWriter, r *http.Request, principal credbound.SCIMAuthentication, raw string,
	handle func(http.ResponseWriter, *http.Request, credbound.SCIMAuthentication, credbound.UUID)) {
	switch r.Method {
	case http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
		return
	}
	id, err := credbound.ParseUUID(raw)
	if err != nil {
		writeError(w, credbound.ErrNotFound)
		return
	}
	handle(w, r, principal, id)
}

func (h *Handler) group(w http.ResponseWriter, r *http.Request, principal credbound.SCIMAuthentication, id credbound.UUID) {
	if id == (credbound.UUID{}) {
		writeError(w, credbound.ErrNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		value, err := h.manager.SCIMGroup(r.Context(), principal, id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, groupFromDomain(value))
	case http.MethodPut:
		var request groupResource
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		if !hasSchema(request.Schemas, coreGroupSchema) {
			writeError(w, fmt.Errorf("%w: core Group schema is required", credbound.ErrInvalidInput))
			return
		}
		value, err := h.manager.UpsertSCIMGroup(r.Context(), principal, id, request.input())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, groupFromDomain(value))
	case http.MethodPatch:
		current, err := h.manager.SCIMGroup(r.Context(), principal, id)
		if err != nil {
			writeError(w, err)
			return
		}
		var request patchRequest
		if err := decodeBody(w, r, &request); err != nil {
			writeError(w, err)
			return
		}
		input, err := patchGroup(current, request)
		if err != nil {
			writeError(w, err)
			return
		}
		value, err := h.manager.UpsertSCIMGroup(r.Context(), principal, id, input)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, groupFromDomain(value))
	case http.MethodDelete:
		if err := h.manager.DeleteSCIMGroup(r.Context(), principal, id); err != nil {
			writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete)
	}
}

type meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

type userResource struct {
	Schemas     []string                   `json:"schemas"`
	ID          string                     `json:"id,omitempty"`
	ExternalID  string                     `json:"externalId,omitempty"`
	UserName    string                     `json:"userName"`
	DisplayName string                     `json:"displayName,omitempty"`
	Emails      []credbound.SCIMEmail      `json:"emails,omitempty"`
	Active      *bool                      `json:"active,omitempty"`
	Password    string                     `json:"password,omitempty"`
	Meta        meta                       `json:"meta,omitempty"`
	Attributes  map[string]json.RawMessage `json:"-"`
}

func (r userResource) input(defaultActive bool) credbound.SCIMUserInput {
	active := defaultActive
	if r.Active != nil {
		active = *r.Active
	}
	return credbound.SCIMUserInput{Schemas: r.Schemas, ExternalID: r.ExternalID, UserName: r.UserName, DisplayName: r.DisplayName, Emails: r.Emails, Attributes: r.Attributes, Active: active}
}

func (r *userResource) UnmarshalJSON(data []byte) error {
	type wire userResource
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = userResource(decoded)
	var attributes map[string]json.RawMessage
	if err := json.Unmarshal(data, &attributes); err != nil {
		return err
	}
	for key := range attributes {
		if reservedUserAttribute(key) {
			delete(attributes, key)
		}
	}
	if len(attributes) > 0 {
		r.Attributes = attributes
	}
	return nil
}

func (r userResource) MarshalJSON() ([]byte, error) {
	type wire userResource
	base, err := json.Marshal(wire(r))
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(base, &result); err != nil {
		return nil, err
	}
	for key, value := range r.Attributes {
		if !reservedUserAttribute(key) && json.Valid(value) {
			result[key] = value
		}
	}
	return json.Marshal(result)
}

func reservedUserAttribute(key string) bool {
	switch strings.ToLower(key) {
	case "schemas", "id", "externalid", "username", "displayname", "emails", "active", "password", "meta", "attributes":
		return true
	default:
		return false
	}
}

type groupMember struct {
	Value string `json:"value"`
	Ref   string `json:"$ref,omitempty"`
}

type groupResource struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id,omitempty"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []groupMember `json:"members,omitempty"`
	Meta        meta          `json:"meta,omitempty"`
}

func (r groupResource) input() credbound.SCIMGroupInput {
	// Member references arrive as text from the provisioning client; one that
	// is not an identifier is dropped rather than failing the whole group, and
	// the membership reconciliation then reports it as unknown.
	members := make([]credbound.UUID, 0, len(r.Members))
	for _, member := range r.Members {
		id, err := credbound.ParseUUID(member.Value)
		if err != nil {
			continue
		}
		members = append(members, id)
	}
	return credbound.SCIMGroupInput{ExternalID: r.ExternalID, DisplayName: r.DisplayName, MemberIDs: members}
}

func userFromDomain(value credbound.SCIMUser) userResource {
	active := value.Active
	return userResource{
		Schemas: userSchemas(value.Schemas), ID: value.ID.String(), ExternalID: value.ExternalID, UserName: value.UserName,
		DisplayName: value.DisplayName, Emails: value.Emails, Active: &active, Attributes: value.Attributes,
		Meta: meta{ResourceType: "User", Created: value.CreatedAt, LastModified: value.UpdatedAt, Location: "/Users/" + value.ID.String()},
	}
}

func userSchemas(values []string) []string {
	result := []string{coreUserSchema}
	for _, value := range values {
		if value != "" && value != coreUserSchema {
			result = append(result, value)
		}
	}
	return result
}

func groupFromDomain(value credbound.SCIMGroup) groupResource {
	members := make([]groupMember, len(value.MemberIDs))
	for index, id := range value.MemberIDs {
		members[index] = groupMember{Value: id.String(), Ref: "/Users/" + id.String()}
	}
	return groupResource{
		Schemas: []string{coreGroupSchema}, ID: value.ID.String(), ExternalID: value.ExternalID, DisplayName: value.DisplayName, Members: members,
		Meta: meta{ResourceType: "Group", Created: value.CreatedAt, LastModified: value.UpdatedAt, Location: "/Groups/" + value.ID.String()},
	}
}

type searchRequest struct {
	Schemas []string `json:"schemas"`
	Filter  string   `json:"filter"`
	Cursor  string   `json:"cursor"`
	Count   int      `json:"count"`
}

type patchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []patchOperation `json:"Operations"`
}

type patchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func patchUser(current credbound.SCIMUser, request patchRequest) (credbound.SCIMUserInput, error) {
	if !hasSchema(request.Schemas, patchSchema) || len(request.Operations) == 0 {
		return credbound.SCIMUserInput{}, fmt.Errorf("%w: invalid PatchOp", credbound.ErrInvalidInput)
	}
	input := credbound.SCIMUserInput{Schemas: current.Schemas, ExternalID: current.ExternalID, UserName: current.UserName, DisplayName: current.DisplayName, Emails: current.Emails, Attributes: current.Attributes, Active: current.Active}
	for _, operation := range request.Operations {
		op, path := strings.ToLower(operation.Op), strings.ToLower(strings.TrimSpace(operation.Path))
		if op != "add" && op != "replace" && op != "remove" {
			return input, unsupportedPatch()
		}
		if path == "" {
			if op == "remove" {
				return input, unsupportedPatch()
			}
			var value userResource
			if err := json.Unmarshal(operation.Value, &value); err != nil {
				return input, fmt.Errorf("%w: invalid user patch value", credbound.ErrInvalidInput)
			}
			if value.Password != "" {
				return input, unsupportedPatch()
			}
			if value.UserName != "" {
				input.UserName = value.UserName
			}
			if value.DisplayName != "" {
				input.DisplayName = value.DisplayName
			}
			if value.ExternalID != "" {
				input.ExternalID = value.ExternalID
			}
			if value.Emails != nil {
				input.Emails = value.Emails
			}
			if value.Active != nil {
				input.Active = *value.Active
			}
			if len(value.Schemas) > 0 {
				input.Schemas = value.Schemas
			}
			if input.Attributes == nil && len(value.Attributes) > 0 {
				input.Attributes = make(map[string]json.RawMessage)
			}
			for key, raw := range value.Attributes {
				input.Attributes[key] = raw
			}
			continue
		}
		switch path {
		case "active":
			if op == "remove" || json.Unmarshal(operation.Value, &input.Active) != nil {
				return input, unsupportedPatch()
			}
		case "username":
			if op == "remove" || json.Unmarshal(operation.Value, &input.UserName) != nil {
				return input, unsupportedPatch()
			}
		case "displayname":
			if op == "remove" {
				input.DisplayName = ""
			} else if json.Unmarshal(operation.Value, &input.DisplayName) != nil {
				return input, unsupportedPatch()
			}
		case "externalid":
			if op == "remove" {
				input.ExternalID = ""
			} else if json.Unmarshal(operation.Value, &input.ExternalID) != nil {
				return input, unsupportedPatch()
			}
		case "emails":
			if op == "remove" {
				input.Emails = nil
			} else if json.Unmarshal(operation.Value, &input.Emails) != nil {
				return input, unsupportedPatch()
			}
		default:
			if strings.Contains(path, ".") || reservedUserAttribute(path) {
				return input, unsupportedPatch()
			}
			if input.Attributes == nil {
				input.Attributes = make(map[string]json.RawMessage)
			}
			if op == "remove" {
				delete(input.Attributes, operation.Path)
			} else if !json.Valid(operation.Value) {
				return input, unsupportedPatch()
			} else {
				input.Attributes[operation.Path] = operation.Value
			}
		}
	}
	return input, nil
}

func patchGroup(current credbound.SCIMGroup, request patchRequest) (credbound.SCIMGroupInput, error) {
	if !hasSchema(request.Schemas, patchSchema) || len(request.Operations) == 0 {
		return credbound.SCIMGroupInput{}, fmt.Errorf("%w: invalid PatchOp", credbound.ErrInvalidInput)
	}
	input := credbound.SCIMGroupInput{ExternalID: current.ExternalID, DisplayName: current.DisplayName, MemberIDs: append([]credbound.UUID(nil), current.MemberIDs...)}
	for _, operation := range request.Operations {
		op, path := strings.ToLower(operation.Op), strings.TrimSpace(operation.Path)
		if op != "add" && op != "replace" && op != "remove" {
			return input, unsupportedPatch()
		}
		lowerPath := strings.ToLower(path)
		switch {
		case lowerPath == "displayname":
			if op == "remove" || json.Unmarshal(operation.Value, &input.DisplayName) != nil {
				return input, unsupportedPatch()
			}
		case lowerPath == "externalid":
			if op == "remove" {
				input.ExternalID = ""
			} else if json.Unmarshal(operation.Value, &input.ExternalID) != nil {
				return input, unsupportedPatch()
			}
		case lowerPath == "members":
			if op == "remove" {
				input.MemberIDs = nil
				continue
			}
			var members []groupMember
			if err := json.Unmarshal(operation.Value, &members); err != nil {
				return input, unsupportedPatch()
			}
			values := make([]credbound.UUID, 0, len(members))
			for _, member := range members {
				id, parseErr := credbound.ParseUUID(member.Value)
				if parseErr != nil {
					continue
				}
				values = append(values, id)
			}
			if op == "add" {
				input.MemberIDs = append(input.MemberIDs, values...)
			} else {
				input.MemberIDs = values
			}
		case op == "remove" && strings.HasPrefix(lowerPath, "members[value eq "):
			id, err := quotedFilterValue(path[strings.Index(path, " ")+1:])
			if err != nil {
				return input, unsupportedPatch()
			}
			filtered := input.MemberIDs[:0]
			for _, currentID := range input.MemberIDs {
				if currentID.String() != id {
					filtered = append(filtered, currentID)
				}
			}
			input.MemberIDs = filtered
		default:
			return input, unsupportedPatch()
		}
	}
	return input, nil
}

func listParameters(rawFilter, cursor, rawCount string) (credbound.SCIMFilter, credbound.PageRequest, error) {
	filter, err := parseFilter(rawFilter)
	if err != nil {
		return credbound.SCIMFilter{}, credbound.PageRequest{}, err
	}
	limit := defaultPageLimit
	if rawCount != "" && rawCount != "0" {
		limit, err = strconv.Atoi(rawCount)
		if err != nil || limit < 1 || limit > 100 {
			return credbound.SCIMFilter{}, credbound.PageRequest{}, fmt.Errorf("%w: count must be between 1 and 100", credbound.ErrInvalidInput)
		}
	}
	return filter, credbound.PageRequest{Cursor: cursor, Limit: limit}, nil
}

func parseFilter(raw string) (credbound.SCIMFilter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return credbound.SCIMFilter{}, nil
	}
	parts := strings.Fields(raw)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "eq") {
		return credbound.SCIMFilter{}, fmt.Errorf("%w: only the SCIM eq filter is supported", credbound.ErrInvalidInput)
	}
	valueRaw := strings.TrimSpace(raw[len(parts[0])+len(parts[1])+2:])
	value, err := quotedFilterValue(valueRaw)
	if err != nil {
		return credbound.SCIMFilter{}, err
	}
	return credbound.SCIMFilter{Attribute: parts[0], Value: value}, nil
}

func quotedFilterValue(raw string) (string, error) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "]"))
	if strings.HasPrefix(raw, "eq ") {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "eq "))
	}
	if strings.HasPrefix(raw, `"`) {
		var value string
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return "", fmt.Errorf("%w: malformed SCIM filter", credbound.ErrInvalidInput)
		}
		return value, nil
	}
	if raw == "true" || raw == "false" {
		return raw, nil
	}
	return "", fmt.Errorf("%w: malformed SCIM filter", credbound.ErrInvalidInput)
}

func writeUserList(w http.ResponseWriter, sequence func(func(credbound.PageEvent[credbound.SCIMUser], error) bool)) {
	writeList(w, sequence, func(value credbound.SCIMUser) any { return userFromDomain(value) })
}

func writeGroupList(w http.ResponseWriter, sequence func(func(credbound.PageEvent[credbound.SCIMGroup], error) bool)) {
	writeList(w, sequence, func(value credbound.SCIMGroup) any { return groupFromDomain(value) })
}

func writeList[T any](w http.ResponseWriter, sequence func(func(credbound.PageEvent[T], error) bool), resource func(T) any) {
	// The page is bounded (count caps at 100), so the whole list response is
	// assembled in memory before the status line goes out: a read or
	// serialization failure mid-page becomes a real SCIM error response
	// instead of truncated JSON under a 200 the client would trust.
	resources := make([]json.RawMessage, 0, defaultPageLimit)
	var end credbound.PageEnd
	for event, sequenceErr := range sequence {
		if sequenceErr != nil {
			writeError(w, sequenceErr)
			return
		}
		if event.Data != nil {
			payload, marshalErr := json.Marshal(resource(*event.Data))
			if marshalErr != nil {
				writeError(w, marshalErr)
				return
			}
			resources = append(resources, payload)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	var body strings.Builder
	body.WriteString(`{"schemas":["` + listSchema + `"],"Resources":[`)
	for index, payload := range resources {
		if index > 0 {
			body.WriteString(",")
		}
		body.Write(payload)
	}
	body.WriteString(`],"itemsPerPage":` + strconv.Itoa(len(resources)))
	if end.NextCursor != "" {
		cursor, _ := json.Marshal(end.NextCursor)
		body.WriteString(`,"nextCursor":` + string(cursor))
	}
	body.WriteString("}")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body.String())
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/scim+json") && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return fmt.Errorf("%w: Content-Type must be application/scim+json", credbound.ErrInvalidInput)
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid SCIM JSON", credbound.ErrInvalidInput)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: multiple JSON values", credbound.ErrInvalidInput)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credbound.ErrInvalidCredentials), errors.Is(err, credbound.ErrUnauthorized):
		writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing SCIM credential")
	case errors.Is(err, credbound.ErrForbidden):
		writeSCIMError(w, http.StatusForbidden, "", "access denied")
	case errors.Is(err, credbound.ErrNotFound):
		writeSCIMError(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, credbound.ErrConflict):
		writeSCIMError(w, http.StatusConflict, "uniqueness", "resource conflicts with existing data")
	case errors.Is(err, credbound.ErrInvalidInput):
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
	case errors.Is(err, credbound.ErrNotSupported):
		writeSCIMError(w, http.StatusNotImplemented, "", "SCIM is not supported by this store")
	default:
		writeSCIMError(w, http.StatusInternalServerError, "", "internal SCIM error")
	}
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	payload := map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		payload["scimType"] = scimType
	}
	writeJSON(w, status, payload)
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "method not allowed")
}

func unsupportedPatch() error {
	return fmt.Errorf("%w: unsupported SCIM PATCH path or operation", credbound.ErrInvalidInput)
}

func hasSchema(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func userSchema() map[string]any {
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": coreUserSchema, "name": "User", "description": "Credbound SCIM user",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "multiValued": false, "required": true, "uniqueness": "server"},
			{"name": "displayName", "type": "string", "multiValued": false, "required": false},
			{"name": "active", "type": "boolean", "multiValued": false, "required": false},
			{"name": "emails", "type": "complex", "multiValued": true, "required": false},
		},
	}
}

func groupSchema() map[string]any {
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": coreGroupSchema, "name": "Group", "description": "Credbound SCIM group",
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "multiValued": false, "required": true},
			{"name": "members", "type": "complex", "multiValued": true, "required": false},
		},
	}
}
