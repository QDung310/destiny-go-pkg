// Package httpx — JSON response với error shape thống nhất.
//
// Port từ 14 định nghĩa writeJSON rải rác trong các package Go.
// Error shape lấy từ html-public/docs/architecture/api.md (đã có ADR + test riêng):
//
//	{"error":{"code":"INVALID","message":"...","details":{...},"request_id":"..."}}
package httpx

import (
	"encoding/json"
	"log"
	"net/http"
)

// ErrorBody — shape lỗi chuẩn.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorEnvelope — envelope bọc ErrorBody.
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// JSON ghi JSON với status code. Lỗi encode chỉ log — response đã gửi thì không sửa được.
func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("httpx: encode response: %v", err)
	}
}

// Error ghi error envelope chuẩn.
func Error(w http.ResponseWriter, status int, code, message string, details any) {
	JSON(w, status, ErrorEnvelope{Error: ErrorBody{
		Code: code, Message: message, Details: details,
	}})
}

// ErrorWithRequestID như Error nhưng kèm request id (để trace log).
func ErrorWithRequestID(w http.ResponseWriter, status int, code, message string, requestID string) {
	JSON(w, status, ErrorEnvelope{Error: ErrorBody{
		Code: code, Message: message, RequestID: requestID,
	}})
}

// OK — 200 với payload.
func OK(w http.ResponseWriter, payload any) { JSON(w, http.StatusOK, payload) }

// Created — 201.
func Created(w http.ResponseWriter, payload any) { JSON(w, http.StatusCreated, payload) }

// NoContent — 204, không body.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// BadRequest — 400.
func BadRequest(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusBadRequest, code, message, nil)
}

// Unauthorized — 401.
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// Forbidden — 403.
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, "FORBIDDEN", message, nil)
}

// NotFound — 404.
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, "NOT_FOUND", message, nil)
}

// Conflict — 409.
func Conflict(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusConflict, code, message, nil)
}

// Internal — 500. KHÔNG lộ chi tiết lỗi ra ngoài (chỉ log).
func Internal(w http.ResponseWriter, err error) {
	if err != nil {
		log.Printf("httpx: internal error: %v", err)
	}
	Error(w, http.StatusInternalServerError, "INTERNAL", "lỗi máy chủ", nil)
}