// Package auth — CLIENT của Identity Service (ADR-002).
//
// ⚠️ BẤT BIẾN KIẾN TRÚC:
//
//	Package này KHÔNG THỂ ký JWT. Không có Issue(), không có hàm ký nào.
//	Chỉ Identity Service giữ private key. Product gọi HTTP sang Identity để
//	login / issue token / refresh / revoke, và verify OFFLINE qua JWKS.
//
// Vì sao: nếu product giữ private key (hoặc secret HS256) thì 15 project = 15 chỗ
// có thể ký token ⇒ mất ý nghĩa "một nguồn auth duy nhất" (ADR-002 §1).
//
// API:
//
//	c := auth.NewClient("http://identity:8091", internalKey)
//	claims, err := c.Verify(ctx, token)     // offline qua JWKS, 0 network hop sau lần đầu
//	tokens, err := c.Refresh(ctx, refreshTok)
//	err = c.Revoke(ctx, jti)
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/QDung310/destiny-go-pkg/authverify"
)

// Claims — payload token do Identity ký.
//
// Alias sang authverify để consumer chỉ cần 1 loại Claims.
type Claims = authverify.Claims

// Tokens — cặp token Identity trả về.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// User — identity do Identity Service quản lý (cả 2 kind).
type User struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	TelegramID string `json:"telegram_id,omitempty"`
	Email      string `json:"email,omitempty"`
	Username   string `json:"username"`
	Name       string `json:"name"`
	PhotoURL   string `json:"photo_url,omitempty"`
	Role       string `json:"role"`
	Disabled   bool   `json:"disabled,omitempty"`
}

// Errors.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Client — gọi Identity (mutating) + verify offline (JWKS).
type Client struct {
	baseURL   string
	internal  string
	http      *http.Client
	verifier  *authverify.Verifier

	mu        sync.RWMutex
	revoked   map[string]time.Time // jti -> thời điểm revoke
	revSince  time.Time
	logger    *log.Logger
}

// NewClient tạo client. baseURL ví dụ "http://identity:8091".
func NewClient(baseURL, internalKey string) *Client {
	return &Client{
		baseURL:  baseURL,
		internal: internalKey,
		http:     &http.Client{Timeout: 15 * time.Second},
		verifier: authverify.New(baseURL + "/.well-known/jwks.json"),
		revoked:  make(map[string]time.Time),
	}
}

// Verify — verify OFFLINE bằng JWKS. 0 network hop sau lần fetch đầu (15 phút cache).
//
// Sau khi verify chữ ký, kiểm thêm danh sách revoke (cache 30s, ADR-002 §6).
func (c *Client) Verify(ctx context.Context, tokenStr string) (*Claims, error) {
	claims, err := c.verifier.Verify(ctx, tokenStr)
	if err != nil {
		return nil, err
	}

	// Nạp danh sách revoke nếu cache đã cũ (RevokeTTL = 20s).
	//
	// BUG ĐÃ SỬA: RefreshRevocations() được viết đúng nhưng KHÔNG AI GỌI.
	// Comment ghi "gọi định kỳ 30s" nhưng không có code nào làm — nên map
	// revoked luôn rỗng và isRevoked() luôn trả false.
	// Verify thật trước khi sửa: revoke trả 200 nhưng token vẫn 200 sau 35s.
	c.warmRevoked(ctx)

	if c.isRevoked(claims.ID) {
		return nil, fmt.Errorf("auth: token đã bị thu hồi (jti=%s)", claims.ID)
	}
	return claims, nil
}

// warmRevoked gọi RefreshRevocations nếu cache cũ hơn RevokeTTL.
//
// Lỗi mạng KHÔNG làm verify fail — giữ danh sách cũ. Availability > strictness
// trên auth read path: Identity chết thì token còn hạn vẫn dùng được.
func (c *Client) warmRevoked(ctx context.Context) {
	c.mu.RLock()
	fresh := !c.revSince.IsZero() && time.Since(c.revSince) < RevokeTTL
	c.mu.RUnlock()
	if fresh {
		return
	}
	// KHÔNG bỏ qua lỗi im lặng: chính chỗ này đã che bug `revoked_at` sai kiểu
	// suốt nhiều tháng, khiến revoke vô hiệu mà không ai biết.
	//
	// Không fail verify (availability > strictness), nhưng PHẢI thấy được.
	if err := c.RefreshRevocations(ctx); err != nil {
		c.logf("auth: nạp danh sách revoke thất bại (giữ cache cũ): %v", err)
	}
}

// logf ghi log qua logger tuỳ chỉnh, mặc định là log chuẩn.
func (c *Client) logf(format string, args ...any) {
	if c.logger != nil {
		c.logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// SetLogger thay logger mặc định (dùng slog/zap của service).
func (c *Client) SetLogger(l *log.Logger) {
	c.mu.Lock()
	c.logger = l
	c.mu.Unlock()
}

// Refresh — đổi refresh token lấy cặp mới. Gọi Identity (có network hop).
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	var out Tokens
	err := c.doJSON(ctx, http.MethodPost, "/v1/token/refresh",
		map[string]string{"refresh_token": refreshToken}, &out)
	return out, err
}

// Revoke — thu hồi session. Cửa sổ ≤30s cho consumer khác (ADR-002 §6).
func (c *Client) Revoke(ctx context.Context, jti, userID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/sessions/revoke",
		map[string]string{"jti": jti, "user_id": userID}, nil)
}

// LoginResult — kết quả login password.
type LoginResult struct {
	Tokens Tokens `json:"tokens"`
	User   struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
		Kind  string `json:"kind"`
	} `json:"user"`
}

// Login — đăng nhập email + password (ADR-003 kind=password).
//
// Dùng cho 3 dashboard. Product KHÔNG tự verify bcrypt nữa — hash thuộc Identity.
func (c *Client) Login(ctx context.Context, email, password, app string) (Tokens, error) {
	var out LoginResult
	if err := c.doJSON(ctx, http.MethodPost, "/v1/login", map[string]string{
		"email": email, "password": password, "app": app,
	}, &out); err != nil {
		return Tokens{}, err
	}
	return out.Tokens, nil
}

// LoginFull như Login nhưng trả cả thông tin user.
func (c *Client) LoginFull(ctx context.Context, email, password, app string) (LoginResult, error) {
	var out LoginResult
	err := c.doJSON(ctx, http.MethodPost, "/v1/login", map[string]string{
		"email": email, "password": password, "app": app,
	}, &out)
	return out, err
}

// IssueOTP — sinh OTP cho user. Product KHÔNG được tự sinh OTP (ADR-002 §1).
//
// Trả mã OTP để caller gửi cho user (qua Telegram/email). KHÔNG log mã.
func (c *Client) IssueOTP(ctx context.Context, userID, app string) (string, int, error) {
	var out struct {
		OTP       string `json:"otp"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/otp",
		map[string]string{"user_id": userID, "app": app}, &out); err != nil {
		return "", 0, err
	}
	return out.OTP, out.ExpiresIn, nil
}

// VerifyOTP — kiểm OTP (consume once). Thành công trả luôn cặp token.
func (c *Client) VerifyOTP(ctx context.Context, userID, app, code string) (Tokens, error) {
	var out Tokens
	err := c.doJSON(ctx, http.MethodPost, "/v1/otp/verify",
		map[string]string{"user_id": userID, "app": app, "code": code}, &out)
	return out, err
}

// UpsertUser — tạo/cập nhật account theo telegram_id (idempotent).
//
// ADR-004: `app` bắt buộc — ghi vào `accounts_<app>`, không phải 1 collection chung.
func (c *Client) UpsertUser(ctx context.Context, app, telegramID, username, name, photo string) (*User, bool, error) {
	var out struct {
		User User `json:"user"`
	}
	status, err := c.doJSONStatus(ctx, http.MethodPost, "/v1/users/upsert", map[string]string{
		"app": app, "telegram_id": telegramID, "username": username,
		"name": name, "photo_url": photo,
	}, &out)
	if err != nil {
		return nil, false, err
	}
	return &out.User, status == http.StatusCreated, nil
}

// GetUser — đọc account theo id (ADR-004: cần app để biết collection nào).
func (c *Client) GetUser(ctx context.Context, app, id string) (*User, error) {
	var out struct {
		User User `json:"user"`
	}
	path := "/v1/users/" + id
	if app != "" {
		path += "?app=" + app
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// GetUserByTelegram — tra account theo telegram_id trong `accounts_<app>`.
//
// Dùng upsert idempotent (Identity chưa có endpoint tra riêng) — an toàn vì
// upsert với username/name rỗng không ghi đè dữ liệu đã có (`$set` rỗng).
func (c *Client) GetUserByTelegram(ctx context.Context, app, telegramID string) (*User, error) {
	u, _, err := c.UpsertUser(ctx, app, telegramID, "", "", "")
	return u, err
}

// ── revoke cache ─────────────────────────────────────────────────────────

// RefreshRevocations tải danh sách revoke mới. Gọi định kỳ 30s.
func (c *Client) RefreshRevocations(ctx context.Context) error {
	since := c.revSince.Unix()
	if c.revSince.IsZero() {
		since = time.Now().Add(-5 * time.Minute).Unix()
	}

	// BUG ĐÃ SỬA: Identity trả `revoked_at` dạng RFC3339 STRING
	// ("2026-10-25T09:01:07.62Z"), KHÔNG phải epoch int64. Khai int64 làm
	// json.Decode fail toàn bộ payload → danh sách revoke luôn RỖNG → revoke
	// vô hiệu. Verify thật: revoke 200 nhưng token vẫn 200 sau 25s.
	var out struct {
		Revocations []struct {
			JTI       string `json:"jti"`
			RevokedAt string `json:"revoked_at"`
		} `json:"revocations"`
		Now int64 `json:"now"`
	}
	if err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/v1/revocations?since=%d", since), nil, &out); err != nil {
		return err
	}

	c.mu.Lock()
	for _, r := range out.Revocations {
		ts := time.Now() // fallback: coi như vừa revoke
		if r.RevokedAt != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, r.RevokedAt); err == nil {
				ts = parsed
			}
		}
		c.revoked[r.JTI] = ts
	}
	if out.Now > 0 {
		c.revSince = time.Unix(out.Now, 0)
	}
	c.mu.Unlock()
	return nil
}

// isRevoked kiểm jti có trong cache thu hồi không.
func (c *Client) isRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	c.mu.RLock()
	_, ok := c.revoked[jti]
	c.mu.RUnlock()
	return ok
}

// ── HTTP helper ──────────────────────────────────────────────────────────

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	_, err := c.doJSONStatus(ctx, method, path, body, out)
	return err
}

func (c *Client) doJSONStatus(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("auth: marshal: %w", err)
		}
		rdr = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return 0, fmt.Errorf("auth: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internal != "" {
		req.Header.Set("X-Internal-Key", c.internal)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("auth: gọi Identity: %w", err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 400 {
		var env struct {
			Error Error `json:"error"`
		}
		if json.Unmarshal(payload, &env) == nil && env.Error.Code != "" {
			return resp.StatusCode, &env.Error
		}
		return resp.StatusCode, fmt.Errorf("auth: Identity HTTP %d: %s", resp.StatusCode, string(payload))
	}

	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return resp.StatusCode, fmt.Errorf("auth: decode: %w", err)
		}
	}
	return resp.StatusCode, nil
}
// RevokeTTL — chu kỳ nạp lại danh sách jti đã thu hồi (ADR-002 §6: <=30s).
const RevokeTTL = 20 * time.Second

// IsRevokedForTest — chỉ dùng cho test.
func (c *Client) IsRevokedForTest(jti string) bool { return c.isRevoked(jti) }

// ── CRUD account (ADR-005) ───────────────────────────────────────────────

// Account — account trả về từ Identity.
type Account struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
	Disabled bool   `json:"disabled"`
}

// ListAccounts liệt kê account của app.
func (c *Client) ListAccounts(ctx context.Context, app string) ([]Account, error) {
	var out struct {
		Accounts []Account `json:"accounts"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/accounts?app="+app, nil, &out); err != nil {
		return nil, err
	}
	return out.Accounts, nil
}

// CreateAccount tạo account mới. Identity tự hash bcrypt (product KHÔNG hash).
func (c *Client) CreateAccount(ctx context.Context, app, identifier, password, role string) (*Account, error) {
	var out struct {
		Account Account `json:"account"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/accounts", map[string]string{
		"app": app, "identifier": identifier, "password": password, "role": role,
	}, &out); err != nil {
		return nil, err
	}
	return &out.Account, nil
}

// SetAccountDisabled bật/tắt khoá account.
func (c *Client) SetAccountDisabled(ctx context.Context, app, id string, disabled bool) error {
	return c.doJSON(ctx, http.MethodPatch, "/v1/accounts/"+id, map[string]any{
		"app": app, "disabled": disabled,
	}, nil)
}

// ResetAccountPassword đặt lại mật khẩu.
func (c *Client) ResetAccountPassword(ctx context.Context, app, id, password string) error {
	return c.doJSON(ctx, http.MethodPatch, "/v1/accounts/"+id, map[string]any{
		"app": app, "password": password,
	}, nil)
}

// DeleteAccount xoá account.
func (c *Client) DeleteAccount(ctx context.Context, app, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/accounts/"+id+"?app="+app, nil, nil)
}
