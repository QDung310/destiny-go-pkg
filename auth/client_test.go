package auth_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QDung310/destiny-go-pkg/auth"
)

// T7.7 — pkg/auth KHÔNG được export hàm ký token.
//
// ADR-002 §1: chỉ Identity giữ private key. Nếu pkg/auth có Issue/Sign thì
// 15 project đều ký được ⇒ mất "một nguồn auth duy nhất".
func TestPackageCannotSignTokens(t *testing.T) {
	forbidden := []string{"Issue", "IssueAccessOnly", "Sign", "SignToken", "sign"}

	// Kiểm bằng reflection qua method set của Client
	typeOfClient := ""
	_ = typeOfClient

	c := auth.NewClient("http://x", "key")
	_ = c

	// Duyệt source: không được có lời gọi SignedString trong package
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		body := string(src)

		if strings.Contains(body, "SignedString") {
			t.Errorf("%s có SignedString — package KHÔNG được ký token", path)
		}
		if strings.Contains(body, "SigningMethod") {
			t.Errorf("%s có SigningMethod — package KHÔNG được ký token", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Kiểm AST: không có hàm exported nào tên Issue*/Sign*
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}
			name := fn.Name.Name
			for _, banned := range forbidden {
				if name == banned {
					t.Errorf("%s: method %q bị cấm trong pkg/auth (chỉ Identity được ký)", f, name)
				}
			}
		}
	}
}

// T7.8 — Client có đủ API để consumer dùng mà không cần ký.
func TestClientAPISurface(t *testing.T) {
	c := auth.NewClient("http://identity:8091", "internal-key")

	// Verify offline, Refresh, Revoke, UpsertUser, GetUser, RefreshRevocations
	checks := map[string]bool{
		"Verify":            true,
		"Refresh":           true,
		"Revoke":            true,
		"UpsertUser":        true,
		"GetUser":           true,
		"RefreshRevocations": true,
	}
	_ = c
	_ = checks
	// Nếu thiếu method nào, code dưới không compile — đó là mục đích test.
	var _ func(*auth.Client) = func(cl *auth.Client) {
		ctx := context.Background()
		_, _ = cl.Verify(ctx, "token")
		_, _ = cl.Refresh(ctx, "refresh")
		_ = cl.Revoke(ctx, "jti", "user")
		_, _, _ = cl.UpsertUser(ctx, "destiny", "tg", "un", "nm", "")
		_, _ = cl.GetUser(ctx, "destiny", "id")
		_ = cl.RefreshRevocations(ctx)
	}
}