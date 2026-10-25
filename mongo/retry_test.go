package mongo

import (
	"testing"
	"time"
)

// Connect phai RETRY khi Mongo chua san sang. Khong retry => sau reboot
// container exit ngay (Docker start lai container cu TRUOC khi Mongo len,
// depends_on khong ap dung cho restart) => restart loop. Da trung that P35/P36.
//
// Test chot HANG SO de ai sua cung phai nghi lai:
//   10 lan x 3s = 30s, khop thoi gian Mongo can sau reboot (do thuc te ~30s).
func TestDefaultRetryBudget(t *testing.T) {
	// Gia lap default: Config{} voi URI/DBName hop le.
	cfg := Config{URI: "mongodb://x", DBName: "y"}
	applyDefaults(&cfg)

	if cfg.RetryAttempts != 10 {
		t.Errorf("RetryAttempts mac dinh = %d, want 10", cfg.RetryAttempts)
	}
	if cfg.RetryDelay != 3*time.Second {
		t.Errorf("RetryDelay mac dinh = %s, want 3s", cfg.RetryDelay)
	}

	total := time.Duration(cfg.RetryAttempts) * cfg.RetryDelay
	if total < 20*time.Second {
		t.Errorf("tong thoi gian cho = %s, can >=20s (Mongo init ~30s sau reboot)", total)
	}
}

// RetryAttempts=1 phai duoc chap nhan (tat retry) nhung khong am.
func TestRetryAttemptsFloor(t *testing.T) {
	for _, in := range []int{-5, 0, 1} {
		cfg := Config{URI: "mongodb://x", DBName: "y", RetryAttempts: in}
		applyDefaults(&cfg)
		if cfg.RetryAttempts < 1 {
			t.Errorf("RetryAttempts(%d) => %d, phai >=1", in, cfg.RetryAttempts)
		}
	}
}