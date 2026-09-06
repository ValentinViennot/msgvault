package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"go.kenn.io/msgvault/internal/store"
)

// UserSummary is one user as administrators see them.
type UserSummary struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name,omitempty"`
	Role        string     `json:"role" enum:"viewer,member,admin"`
	Disabled    bool       `json:"disabled"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// SourceIDs are the sources the user may read. Administrators see every
	// source regardless of this list.
	SourceIDs []int64 `json:"source_ids"`
}

// UserListResponse lists every user.
type UserListResponse struct {
	Users []UserSummary `json:"users"`
}

// UserPatchRequest changes a user's standing.
type UserPatchRequest struct {
	Disabled *bool `json:"disabled,omitempty"`
}

// UserSourcesRequest replaces the sources a user may read.
type UserSourcesRequest struct {
	SourceIDs []int64 `json:"source_ids"`
}

func (s *Server) registerUserRoutes(apiV1 huma.API) {
	registerAPIV1RawHumaJSONRoute[UserListResponse](apiV1, "listUsers", http.MethodGet, "/users", "List users and their visible sources", s.handleListUsers)
	registerAPIV1RawHumaJSONRouteWithRequest[UserPatchRequest, UserSummary](apiV1, "patchUser", http.MethodPatch, "/users/{id}", "Disable or re-enable a user", s.handlePatchUser)
	registerAPIV1RawHumaJSONRouteWithRequest[UserSourcesRequest, UserSummary](apiV1, "setUserSources", http.MethodPut, "/users/{id}/sources", "Replace the sources a user may read", s.handleSetUserSources)
}

func (s *Server) userSummary(r *http.Request, user *store.User) (UserSummary, error) {
	sources, err := s.userStore.ListUserSourceIDs(r.Context(), user.ID)
	if err != nil {
		return UserSummary{}, err
	}
	return UserSummary{
		ID: user.ID, Email: user.Email, DisplayName: user.DisplayName, Role: user.Role,
		Disabled: user.Disabled, LastLoginAt: user.LastLoginAt, SourceIDs: sources,
	}, nil
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.userStore == nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "Database not available")
		return
	}
	users, err := s.userStore.ListUsers(r.Context())
	if err != nil {
		s.logger.Error("list users", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list users")
		return
	}
	response := UserListResponse{Users: make([]UserSummary, 0, len(users))}
	for i := range users {
		summary, err := s.userSummary(r, &users[i])
		if err != nil {
			s.logger.Error("list user sources", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list users")
			return
		}
		response.Users = append(response.Users, summary)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) userFromPath(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	if s.userStore == nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "Database not available")
		return nil, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "invalid_id", "User ID must be a positive number")
		return nil, false
	}
	user, err := s.userStore.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrUserNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return nil, false
	}
	if err != nil {
		s.logger.Error("get user", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to load user")
		return nil, false
	}
	return user, true
}

func decodeUserBody(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid request body")
		return false
	}
	return requireSingleJSONValue(w, decoder, "bad_request")
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userFromPath(w, r)
	if !ok {
		return
	}
	var input UserPatchRequest
	if !decodeUserBody(w, r, &input) {
		return
	}
	if input.Disabled != nil {
		if *input.Disabled && user.ID == s.requestPrincipal(r).UserID {
			writeError(w, http.StatusBadRequest, "self_disable", "You cannot disable your own account")
			return
		}
		if err := s.userStore.SetUserDisabled(r.Context(), user.ID, *input.Disabled); err != nil {
			s.logger.Error("set user disabled", "id", user.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to update user")
			return
		}
		user.Disabled = *input.Disabled
	}
	s.visibility.reset()
	s.writeUser(w, r, user)
}

func (s *Server) handleSetUserSources(w http.ResponseWriter, r *http.Request) {
	user, ok := s.userFromPath(w, r)
	if !ok {
		return
	}
	var input UserSourcesRequest
	if !decodeUserBody(w, r, &input) {
		return
	}
	for _, id := range input.SourceIDs {
		if id < 1 {
			writeError(w, http.StatusBadRequest, "invalid_source", "Source IDs must be positive")
			return
		}
	}
	err := s.userStore.SetUserSources(r.Context(), user.ID, input.SourceIDs)
	switch {
	case errors.Is(err, store.ErrSourceNotFound):
		writeError(w, http.StatusBadRequest, "unknown_source", err.Error())
		return
	case err != nil:
		s.logger.Error("set user sources", "id", user.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to update user sources")
		return
	}
	s.visibility.reset()
	s.writeUser(w, r, user)
}

func (s *Server) writeUser(w http.ResponseWriter, r *http.Request, user *store.User) {
	summary, err := s.userSummary(r, user)
	if err != nil {
		s.logger.Error("load user sources", "id", user.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to load user")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
