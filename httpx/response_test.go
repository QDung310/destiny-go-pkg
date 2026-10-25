package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// T1.14 — error shape thống nhất (khớp html-public/docs/architecture/api.md).
func TestErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, http.StatusBadRequest, "INVALID", "dữ liệu sai", map[string]any{"field": "email"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}

	var body ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error.Code != "INVALID" || body.Error.Message != "dữ liệu sai" {
		t.Fatalf("body sai: %+v", body.Error)
	}
}

// 204 không được có body.
func TestNoContent(t *testing.T) {
	rec := httptest.NewRecorder()
	NoContent(rec)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("204 phải rỗng body, có %d byte", rec.Body.Len())
	}
}

// T1.14b — Internal KHÔNG lộ chi tiết lỗi ra response.
func TestInternalDoesNotLeakError(t *testing.T) {
	rec := httptest.NewRecorder()
	Internal(rec, errors.New("db password=secret123 failed"))

	body := rec.Body.String()
	if contains(body, "secret123") {
		t.Fatalf("response lộ secret: %s", body)
	}
	if !contains(body, "INTERNAL") {
		t.Fatalf("thiếu code INTERNAL: %s", body)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}