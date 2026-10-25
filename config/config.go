// Package config — load + validate env, fail-fast.
//
// Port từ destiny-backend/internal/config/config.go + dotenv.go (2 bản
// gần như giống hệt giữa destiny và hitter — diff đúng 1 dòng comment).
//
// KHÁC BIỆT CÓ CHỦ ĐÍCH so với bản cũ:
//   - bản cũ gọi log.Fatalf khi thiếu biến, package này trả error.
//     Lý do: package không được quyết định process sống hay chết; caller quyết.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Loader đọc env và cho phép khai báo biến bắt buộc.
type Loader struct {
	required []string
	loaded   bool
}

// New tạo Loader mới.
func New() *Loader { return &Loader{} }

// Require khai báo biến bắt buộc. Load() sẽ trả error nếu thiếu.
func (l *Loader) Require(keys ...string) *Loader {
	l.required = append(l.required, keys...)
	return l
}

// LoadDotEnv đọc file .env (nếu có) vào process env, KHÔNG ghi đè biến đã set.
// Tìm .env ở thư mục hiện tại rồi lên 2 cấp (giống bản gốc).
func (l *Loader) LoadDotEnv() *Loader {
	l.loaded = true
	file := findDotEnv()
	if file == "" {
		return l
	}
	f, err := os.Open(file)
	if err != nil {
		return l
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Bản gốc: strip CR vì file có thể tạo trên Windows.
		line = strings.TrimSuffix(line, "\r")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	return l
}

// Validate kiểm các biến đã Require. Trả error liệt kê TẤT CẢ biến thiếu (không chỉ cái đầu).
func (l *Loader) Validate() error {
	var missing []string
	for _, k := range l.required {
		if os.Getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: thiếu biến bắt buộc: %s", strings.Join(missing, ", "))
	}
	return nil
}

// ── helper đọc env ────────────────────────────────────────────────────────

// String đọc env với default.
func String(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Int đọc env int với default. Trả def nếu parse lỗi.
//
// KHÔNG chặn giá trị <= 0 — dùng IntPositive nếu cần (port, workers, TTL...).
// Lý do tách 2 hàm: 4 project dùng Int cho cả giá trị có thể = 0 (timeout tắt),
// trong khi dashboard-api cần chặn <= 0 (port 0 = bind random, TTL 0 = token
// hết hạn ngay). Gộp sẽ đổi hành vi của một bên.
func Int(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// IntPositive như Int nhưng chỉ nhận giá trị > 0; <= 0 hoặc parse lỗi -> def.
//
// Dùng cho: port (0 = bind random), TTL (0 = hết hạn ngay), số worker (0 = treo).
// Tương đương envInt() của dashboard-api-go và telegram_bot_platform.
func IntPositive(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Bool đọc env bool ("1"/"true"/"yes" = true).
func Bool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

// Duration đọc env duration. Chấp nhận 2 dạng (giống bản gốc):
//
//	"900"      -> 900 giây
//	"15m"      -> ParseDuration
//	"1h30m"    -> ParseDuration
func Duration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// CSV đọc env danh sách phân tách bằng dấu phẩy, đã trim.
func CSV(key, def string) []string {
	raw := String(key, def)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Bytes đọc env dạng []byte (cho secret).
func Bytes(key string) []byte { return []byte(os.Getenv(key)) }

func findDotEnv() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, ".env")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
