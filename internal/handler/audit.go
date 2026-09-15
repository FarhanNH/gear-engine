package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gear/engine/internal/model"
	"github.com/gear/engine/internal/service"
)

// AuditHandler menangani endpoint audit log.
type AuditHandler struct {
	service service.AuditService
}

// NewAuditHandler membuat instance baru AuditHandler.
func NewAuditHandler(svc service.AuditService) *AuditHandler {
	return &AuditHandler{service: svc}
}

// auditEntryResponse adalah representasi satu audit entry dalam response JSON.
// Pointer fields menggunakan omitempty agar tidak muncul dalam JSON jika nil.
type auditEntryResponse struct {
	ID        int64   `json:"id"`
	TokenName *string `json:"token_name,omitempty"`
	Path      *string `json:"path,omitempty"`
	Action    string  `json:"action"`
	Result    string  `json:"result"`
	ErrorCode *int    `json:"error_code,omitempty"`
	IPAddress string  `json:"ip_address"`
	Timestamp string  `json:"timestamp"`
}

// auditLogResponse adalah struktur response untuk GET /v1/audit.
type auditLogResponse struct {
	Entries []auditEntryResponse `json:"entries"`
	Total   int                  `json:"total"`
	Limit   int                  `json:"limit"`
	Offset  int                  `json:"offset"`
}

// GetAuditLog menangani GET /v1/audit.
// Parse query params opsional: token_id, path, since, until, result, limit, offset.
// Return 200 dengan entries + pagination metadata.
//
// Requirements: 7.3
func (h *AuditHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var filter model.AuditFilter

	// Parse token_id (int64, optional).
	if raw := q.Get("token_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid token_id: must be an integer")
			return
		}
		filter.TokenID = &id
	}

	// Parse path (string, optional).
	if raw := q.Get("path"); raw != "" {
		v := raw
		filter.Path = &v
	}

	// Parse since (RFC3339, optional).
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since: must be RFC3339 format (e.g. 2025-01-01T00:00:00Z)")
			return
		}
		filter.Since = &t
	}

	// Parse until (RFC3339, optional).
	if raw := q.Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until: must be RFC3339 format (e.g. 2025-12-31T23:59:59Z)")
			return
		}
		filter.Until = &t
	}

	// Parse result (string, optional) — validate allowed values.
	if raw := q.Get("result"); raw != "" {
		switch raw {
		case "success", "denied", "error", "attempt":
			filter.Result = &raw
		default:
			writeError(w, http.StatusBadRequest, "invalid result: must be one of success, denied, error, attempt")
			return
		}
	}

	// Parse limit (int, optional, default 100, max 1000).
	limit := 100
	if raw := q.Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			writeError(w, http.StatusBadRequest, "invalid limit: must be a positive integer")
			return
		}
		if v > 1000 {
			v = 1000
		}
		limit = v
	}
	filter.Limit = limit

	// Parse offset (int, optional, default 0).
	offset := 0
	if raw := q.Get("offset"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "invalid offset: must be a non-negative integer")
			return
		}
		offset = v
	}
	filter.Offset = offset

	// Query audit service.
	entries, err := h.service.Query(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}

	// Map model.AuditEntry ke auditEntryResponse.
	respEntries := make([]auditEntryResponse, 0, len(entries))
	for _, e := range entries {
		respEntries = append(respEntries, auditEntryResponse{
			ID:        e.ID,
			TokenName: e.TokenName,
			Path:      e.Path,
			Action:    e.Action,
			Result:    e.Result,
			ErrorCode: e.ErrorCode,
			IPAddress: e.IPAddress,
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
		})
	}

	// NOTE: total = len(entries) untuk MVP — full count query lebih kompleks.
	writeJSON(w, http.StatusOK, auditLogResponse{
		Entries: respEntries,
		Total:   len(respEntries),
		Limit:   limit,
		Offset:  offset,
	})
}
