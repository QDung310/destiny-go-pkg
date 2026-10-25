// Package authverify — verify JWT OFFLINE qua JWKS (ADR-002).
//
// VÌ SAO CẦN: sau khi Identity thành auth tier, mỗi service phải verify token.
// Nếu introspection mỗi request:
//   - webtools (VPS B) gọi Identity (VPS A) qua WireGuard ~2-5ms MỖI request
//   - Identity chết = mọi service chết auth
//
// JWKS cache giải quyết cả hai: verify 0 network hop, và Identity chết thì
// token còn hạn vẫn verify được.
package authverify

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CacheTTL — thời gian cache JWKS. 15 phút theo ADR-002.
const CacheTTL = 15 * time.Minute

// RevokeTTL — chu kỳ poll danh sách jti đã thu hồi. ADR-002 §6 cam kết
// "revoke window <=30s"; 20s để chừa biên cho độ trễ mạng.
const RevokeTTL = 20 * time.Second

var (
	ErrNoKey       = errors.New("authverify: không tìm thấy key với kid")
	ErrFetchJWKS   = errors.New("authverify: không fetch được JWKS")
	ErrInvalidJWKS = errors.New("authverify: JWKS không hợp lệ")
	// ErrRevoked — token đã bị thu hồi qua /v1/sessions/revoke.
	ErrRevoked = errors.New("authverify: token đã bị thu hồi")
)

// Claims — payload token (giống package auth để dùng chung).
type Claims struct {
	UserID     string `json:"uid"`
	TelegramID string `json:"tg,omitempty"`
	Email      string `json:"email,omitempty"` // ADR-003 kind=password
	Username   string `json:"un,omitempty"`
	Name       string `json:"nm,omitempty"`
	// ADR-002: 1 user nhiều app; ADR-005: 2 loại principal
	App    string `json:"app,omitempty"`
	Source string `json:"source,omitempty"` // "project" | "shared"
	Kind string `json:"kind,omitempty"`
	Role string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// Verifier — cache JWKS, verify token offline.
type Verifier struct {
	jwksURL string
	http    *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration

	// ADR-002 §6: danh sách jti đã thu hồi, poll mỗi RevokeTTL.
	//
	// TRƯỚC ĐÂY KHÔNG CÓ: /v1/sessions/revoke ghi DB nhưng consumer không
	// bao giờ đọc → token bị revoke vẫn sống tới hết hạn (đã verify thật:
	// revoke 200 nhưng token vẫn 200 sau 35 giây).
	revokeURL    string
	internalKey  string // X-Internal-Key cho /v1/revocations
	revoked      map[string]struct{}
	revokedAt    time.Time
	revokeTTL    time.Duration
	revokeMu     sync.RWMutex
}

// New tạo Verifier. jwksURL thường là "https://identity.example/.well-known/jwks.json".
//
// Suy ra revokeURL từ jwksURL: "https://host/.well-known/jwks.json" →
// "https://host/v1/revocations".
func New(jwksURL string) *Verifier {
	return &Verifier{
		jwksURL:   jwksURL,
		http:      &http.Client{Timeout: 10 * time.Second},
		keys:      make(map[string]*rsa.PublicKey),
		ttl:       CacheTTL,
		revokeURL: deriveRevokeURL(jwksURL),
		revoked:   make(map[string]struct{}),
		revokeTTL: RevokeTTL,
	}
}

// warm đảm bảo có key trong cache, fetch nếu chưa/hết hạn.
func (v *Verifier) warm(ctx context.Context, force bool) error {
	v.mu.RLock()
	fresh := !force && len(v.keys) > 0 && time.Since(v.fetchedAt) < v.ttl
	v.mu.RUnlock()
	if fresh {
		return nil
	}
	return v.fetch(ctx)
}

func (v *Verifier) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFetchJWKS, err)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFetchJWKS, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrFetchJWKS, resp.StatusCode)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJWKS, err)
	}

	parsed := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		key, err := parseRSA(k.N, k.E)
		if err != nil {
			continue
		}
		parsed[k.Kid] = key
	}
	if len(parsed) == 0 {
		return fmt.Errorf("%w: không có key RSA nào", ErrInvalidJWKS)
	}

	v.mu.Lock()
	v.keys = parsed
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok {
		return key, nil
	}

	// T7.4: kid lạ -> refetch NGAY (rotation không làm sập consumer)
	if err := v.fetch(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoKey, kid)
	}
	return key, nil
}

// Verify parse token, verify chữ ký bằng JWKS. Hỗ trợ RS256.
//
// kid lạ -> tự refetch (T7.4). Key cache hết hạn -> tự refetch.
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (*Claims, error) {
	if err := v.warm(ctx, false); err != nil {
		return nil, err
	}

	c := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", jwt.ErrTokenSignatureInvalid, t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		return v.keyFor(ctx, kid)
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("authverify: token không hợp lệ")
	}

	// ADR-002 §6: kiểm jti đã thu hồi. Poll tối đa mỗi RevokeTTL (20s) nên
	// revoke có hiệu lực trong <=20s + độ trễ mạng.
	//
	// Đây là chỗ DUY NHẤT consumer biết token đã bị thu hồi. Thiếu bước này
	// thì /v1/sessions/revoke chỉ ghi DB mà không ai đọc.
	v.warmRevoked(ctx)
	if v.IsRevoked(c.ID) {
		return nil, ErrRevoked
	}
	return c, nil
}

// Refresh buộc fetch lại JWKS (dùng khi rotate key chủ động).
func (v *Verifier) Refresh(ctx context.Context) error { return v.fetch(ctx) }

// parseRSA dựng *rsa.PublicKey từ JWK (base64url n, e).
func parseRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("authverify: exponent 0")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
// deriveRevokeURL suy ra endpoint revocations từ JWKS URL.
//
// "https://identity.destiny-mmo.com/.well-known/jwks.json"
//   -> "https://identity.destiny-mmo.com/v1/revocations"
func deriveRevokeURL(jwksURL string) string {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return ""
	}
	u.Path = "/v1/revocations"
	u.RawQuery = ""
	return u.String()
}

// refreshRevoked tải danh sách jti đã thu hồi.
//
// Lỗi mạng KHÔNG làm verify fail — giữ danh sách cũ và để TTL hết hạn tự
// nhiên. Đánh đổi: nếu Identity chết lâu hơn RevokeTTL, token đã revoke có thể
// sống thêm. Chấp nhận được vì thà auth hoạt động còn hơn sập toàn bộ vì
// không poll được (availability > strictness cho auth read path).
func (v *Verifier) refreshRevoked(ctx context.Context) {
	if v.revokeURL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.revokeURL, nil)
	if err != nil {
		return
	}
	// /v1/* yêu cầu X-Internal-Key — thiếu key thì 401 và danh sách revoke
	// không bao giờ được nạp (đúng bug đã trúng).
	if v.internalKey != "" {
		req.Header.Set("X-Internal-Key", v.internalKey)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var doc struct {
		Revocations []struct {
			JTI string `json:"jti"`
		} `json:"revocations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return
	}

	next := make(map[string]struct{}, len(doc.Revocations))
	for _, r := range doc.Revocations {
		if r.JTI != "" {
			next[r.JTI] = struct{}{}
		}
	}

	v.revokeMu.Lock()
	v.revoked = next
	v.revokedAt = time.Now()
	v.revokeMu.Unlock()
}

// warmRevoked đảm bảo danh sách revoke còn tươi, fetch nếu hết hạn.
func (v *Verifier) warmRevoked(ctx context.Context) {
	v.revokeMu.RLock()
	fresh := !v.revokedAt.IsZero() && time.Since(v.revokedAt) < v.revokeTTL
	v.revokeMu.RUnlock()
	if fresh {
		return
	}
	v.refreshRevoked(ctx)
}

// IsRevoked kiểm jti có trong danh sách thu hồi không.
func (v *Verifier) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	v.revokeMu.RLock()
	defer v.revokeMu.RUnlock()
	_, ok := v.revoked[jti]
	return ok
}

// SetInternalKey đặt X-Internal-Key cho các call /v1/* (revocations).
//
// PHẢI gọi sau New() nếu không danh sách revoke sẽ 401 và revoke không có
// hiệu lực.
func (v *Verifier) SetInternalKey(key string) {
	v.revokeMu.Lock()
	v.internalKey = key
	v.revokeMu.Unlock()
}
