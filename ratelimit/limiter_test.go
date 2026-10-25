package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterAllowsUpToLimit(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("lần %d bị chặn sớm", i+1)
		}
	}
	if ok, retry := l.Allow("k"); ok {
		t.Fatal("lần 4 phải bị chặn")
	} else if retry <= 0 {
		t.Fatalf("retry-after = %d, muốn > 0", retry)
	}
}

func TestLimiterSeparateKeys(t *testing.T) {
	l := New(1, time.Minute)
	l.Allow("a")
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a phải bị chặn")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b phải được phép (key khác)")
	}
}

func TestLimiterWindowResets(t *testing.T) {
	l := New(1, 50*time.Millisecond)
	l.Allow("k")
	if ok, _ := l.Allow("k"); ok {
		t.Fatal("phải bị chặn trong window")
	}
	time.Sleep(70 * time.Millisecond)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("phải được phép sau khi window reset")
	}
}

func TestMiddlewareReturns429(t *testing.T) {
	l := New(1, time.Minute)
	h := l.Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("lần 1 = %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("lần 2 = %d, muốn 429", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Fatal("thiếu Retry-After header")
	}
}

func TestKeyByIPPreferForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	if got := KeyByIP(req); got != "203.0.113.5" {
		t.Fatalf("KeyByIP = %q, muốn 203.0.113.5", got)
	}
}