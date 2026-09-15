package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gear/engine/internal/service"
)

// PolicyHandler holds the PolicyServiceImpl and provides HTTP handlers for
// policy CRUD operations.
type PolicyHandler struct {
	service *service.PolicyServiceImpl
}

// NewPolicyHandler creates a new PolicyHandler with the given PolicyServiceImpl.
func NewPolicyHandler(svc *service.PolicyServiceImpl) *PolicyHandler {
	return &PolicyHandler{service: svc}
}

// permissionsFromPolicy converts model.Policy boolean fields to a string slice.
// e.g. CanRead=true, CanWrite=true → ["read", "write"]
func permissionsFromPolicy(canRead, canWrite, canDelete bool) []string {
	perms := make([]string, 0, 3)
	if canRead {
		perms = append(perms, "read")
	}
	if canWrite {
		perms = append(perms, "write")
	}
	if canDelete {
		perms = append(perms, "delete")
	}
	return perms
}

// createPolicyRequest is the JSON body for POST /v1/policy.
type createPolicyRequest struct {
	TokenID     int64    `json:"token_id"`
	PathPattern string   `json:"path_pattern"`
	Permissions []string `json:"permissions"`
}

// CreatePolicy handles POST /v1/policy.
// Parses the JSON body, validates fields, calls PolicyService.Create(), and returns 201.
//
// Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
func (h *PolicyHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.TokenID <= 0 {
		writeError(w, http.StatusBadRequest, "token_id must be a positive integer")
		return
	}
	if req.PathPattern == "" {
		writeError(w, http.StatusBadRequest, "path_pattern is required")
		return
	}
	if len(req.Permissions) == 0 {
		writeError(w, http.StatusBadRequest, "permissions must not be empty")
		return
	}

	if err := h.service.Create(r.Context(), req.TokenID, req.PathPattern, req.Permissions); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id":     req.TokenID,
		"path_pattern": req.PathPattern,
		"permissions":  req.Permissions,
	})
}

// ListPolicies handles GET /v1/policy.
// If the ?token_id= query param is present, lists policies for that token.
// Otherwise lists all policies. Returns 200 with {"policies": [...]}.
//
// Requirements: 5.1, 5.4
func (h *PolicyHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tokenIDStr := r.URL.Query().Get("token_id")

	type policyResponse struct {
		ID          int64    `json:"id"`
		TokenID     int64    `json:"token_id"`
		PathPattern string   `json:"path_pattern"`
		Permissions []string `json:"permissions"`
	}

	var responses []policyResponse

	if tokenIDStr != "" {
		tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
		if err != nil || tokenID <= 0 {
			writeError(w, http.StatusBadRequest, "token_id must be a positive integer")
			return
		}

		policies, err := h.service.ListByToken(r.Context(), tokenID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list policies")
			return
		}

		responses = make([]policyResponse, 0, len(policies))
		for _, p := range policies {
			responses = append(responses, policyResponse{
				ID:          p.ID,
				TokenID:     p.TokenID,
				PathPattern: p.PathPattern,
				Permissions: permissionsFromPolicy(p.CanRead, p.CanWrite, p.CanDelete),
			})
		}
	} else {
		policies, err := h.service.ListAll(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list policies")
			return
		}

		responses = make([]policyResponse, 0, len(policies))
		for _, p := range policies {
			responses = append(responses, policyResponse{
				ID:          p.ID,
				TokenID:     p.TokenID,
				PathPattern: p.PathPattern,
				Permissions: permissionsFromPolicy(p.CanRead, p.CanWrite, p.CanDelete),
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policies": responses,
	})
}

// DeletePolicy handles DELETE /v1/policy/{id}.
// Extracts the ID from the URL path, calls PolicyService.Delete(), and returns 204 or 404.
//
// Requirements: 5.1, 5.5
func (h *PolicyHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/v1/policy/")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "policy id is required")
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}

	if err := h.service.Delete(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
