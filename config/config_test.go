package config

import (
	"testing"
)

func TestIntAllowsNegative(t *testing.T) {
	t.Setenv("X_INT", "-5")
	if got := Int("X_INT", 10); got != -5 {
		t.Fatalf("Int = %d, muốn -5 (phải cho phép số âm)", got)
	}
}

func TestIntDefault(t *testing.T) {
	t.Setenv("X_INT", "abc")
	if got := Int("X_INT", 42); got != 42 {
		t.Fatalf("Int = %d, muốn 42", got)
	}
}

func TestIntPositiveRejectsZeroAndNegative(t *testing.T) {
	for _, v := range []string{"0", "-1", "abc", ""} {
		t.Setenv("X_POS", v)
		if got := IntPositive("X_POS", 8090); got != 8090 {
			t.Fatalf("IntPositive(%q) = %d, muốn fallback 8090", v, got)
		}
	}
	t.Setenv("X_POS", "3000")
	if got := IntPositive("X_POS", 8090); got != 3000 {
		t.Fatalf("IntPositive = %d, muốn 3000", got)
	}
}

func TestDurationAcceptsSecondsAndString(t *testing.T) {
	t.Setenv("X_DUR", "900")
	if got := Duration("X_DUR", 0).Seconds(); got != 900 {
		t.Fatalf("Duration(900) = %v giây", got)
	}
	t.Setenv("X_DUR", "15m")
	if got := Duration("X_DUR", 0).Minutes(); got != 15 {
		t.Fatalf("Duration(15m) = %v phút", got)
	}
}

func TestValidateListsAllMissing(t *testing.T) {
	t.Setenv("PRESENT", "x")
	l := New().Require("PRESENT", "ABSENT_A", "ABSENT_B")
	err := l.Validate()
	if err == nil {
		t.Fatal("muốn error khi thiếu 2 biến")
	}
	msg := err.Error()
	if !containsAll(msg, "ABSENT_A", "ABSENT_B") {
		t.Fatalf("error phải liệt kê CẢ 2 biến thiếu: %s", msg)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}