// Package ratelimit — limiter in-memory theo key (IP / user / jti).
//
// Port từ 3 bản copy (destiny, hitter, dashboard-api).
//
// GIỚI HẠN ĐÃ BIẾT: in-memory, KHÔNG chia sẻ giữa các instance.
// Với 1 container mỗi service (hiện trạng) là đủ; nếu scale ngang phải chuyển Redis.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter — fixed window theo key.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	count int
	reset time.Time
}

// New tạo Limiter: tối đa `limit` request mỗi `window` cho mỗi key.
func New(limit int, window time.Duration) *Limiter {
	if limit <= 0 {
		limit = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
		lastGC:  time.Now(),
	}
}

// Allow kiểm tra + tăng counter. Trả (cho_phép, số_giây_còn_lại_để_reset).
func (l *Limiter) Allow(key string) (bool, int) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// GC buckets hết hạn mỗi phút để map không phình
	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			if now.After(b.reset) {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(l.window)}
		return true, int(l.window.Seconds())
	}

	if b.count >= l.limit {
		return false, int(time.Until(b.reset).Seconds())
	}
	b.count++
	return true, int(time.Until(b.reset).Seconds())
}

// Middleware bọc http.Handler, key theo hàm keyFn (mặc định: IP).
func (l *Limiter) Middleware(keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	if keyFn == nil {
		keyFn = KeyByIP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, retry := l.Allow(keyFn(r)); !ok {
				w.Header().Set("Retry-After", itoa(retry))
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"quá nhiều request"}}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// KeyByIP lấy IP client, ưu tiên X-Forwarded-For (sau nginx).
func KeyByIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return real
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// KeyByHeader dùng giá trị header làm key (vd Authorization đã hash).
func KeyByHeader(header string) func(*http.Request) string {
	return func(r *http.Request) string { return r.Header.Get(header) }
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}