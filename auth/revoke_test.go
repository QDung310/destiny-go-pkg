package auth_test

// Test T7.7 — RefreshRevocations phải parse được `revoked_at` dạng RFC3339.
//
// BUG ĐÃ TRÚNG: Identity trả `revoked_at` là STRING RFC3339
// ("2026-10-25T09:01:07.62Z"), struct khai `int64` → json.Decode fail →
// danh sách revoke RỖNG → /v1/sessions/revoke ghi DB nhưng token vẫn sống.
//
// Test này chốt shape thật của response để không tái diễn.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QDung310/destiny-go-pkg/auth"
)

func TestRevocationsParsesRFC3339(t *testing.T) {
	const jti = "abc123jti"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/revocations":
			// Shape THẬT của Identity: revoked_at là string RFC3339, now là epoch.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"now": time.Now().Unix(),
				"revocations": []map[string]any{
					{"jti": jti, "revoked_at": "2026-10-25T09:01:07.62Z", "user_id": "u1"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cl := auth.NewClient(srv.URL, "test-key")
	if err := cl.RefreshRevocations(context.Background()); err != nil {
		t.Fatalf("RefreshRevocations phải parse được RFC3339, lỗi: %v", err)
	}
	if !cl.IsRevokedForTest(jti) {
		t.Fatalf("jti %q phải nằm trong cache revoke sau khi nạp", jti)
	}
}