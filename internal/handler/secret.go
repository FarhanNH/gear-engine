package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gear/engine/internal/service"
	"github.com/gear/engine/internal/validate"
)

// SecretHandler holds the SecretService and provides HTTP handlers for
// secret CRUD operations and prefix listing.
type SecretHandler struct {
	service service.SecretService
}

// NewSecretHandler creates a new SecretHandler with the given SecretService.
func NewSecretHandler(svc service.SecretService) *SecretHandler {
	return &SecretHandler{service: svc}
}

// writeJSON writes a JSON response with the given status code and body.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError writes a JSON error response with the given status code and message.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// PutSecret handles PUT /v1/secret/{path}.
// It validates the path, decodes the JSON body, and stores the secret.
// Returns 204 No Content on success.
//
// Requirements: 6.1, 6.6
func (h *SecretHandler) PutSecret(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	if err := validate.ValidatePath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	if err := h.service.Put(r.Context(), path, body.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store secret")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetSecret handles GET /v1/secret/{path}.
// Returns 200 with the secret JSON on success, or 404 if not found.
//
// Requirements: 6.2, 6.6
func (h *SecretHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	if err := validate.ValidatePath(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	value, err := h.service.Get(r.Context(), path)
	if err != nil {
		if errors.Is(err, service.ErrSecretNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to retrieve secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"path":  path,
		"value": value,
	})
}

// DeleteSecret handles DELETE /v1/secret/{path}.
// Returns 204 on success, or 404 if the secret does not exist.
//
// Requirements: 6.3, 6.5, 6.6
func (h *SecretHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/secret/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	if err := h.service.Delete(r.Context(), path); err != nil {
		if errors.Is(err, service.ErrSecretNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListSecrets handles GET /v1/list/{prefix}.
// Returns 200 with {"paths": [...]} on success, or 404 if no secrets are found under the prefix.
//
// Requirements: 6.4, 6.6
func (h *SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimPrefix(r.URL.Path, "/v1/list/")

	paths, err := h.service.List(r.Context(), prefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list secrets")
		return
	}

	if len(paths) == 0 {
		writeError(w, http.StatusNotFound, "no secrets found under prefix")
		return
	}

	writeJSON(w, http.StatusOK, map[string][]string{
		"paths": paths,
	})
}
