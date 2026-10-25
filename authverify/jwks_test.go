package authverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeJWKS dựng JWKS server từ 1 public key.
func fakeJWKS(t *testing.T, kid string, pub *rsa.PublicKey, hits *int) *httptest.Server {
	t.Helper()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

// T7.2 — verify OFFLINE: sau lần fetch đầu, không gọi server nữa.
func TestVerifyOfflineAfterFirstFetch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	hits := 0
	srv := fakeJWKS(t, "k1", &key.PublicKey, &hits)
	defer srv.Close()

	v := New(srv.URL)
	token := signRS(t, key, "k1", time.Hour)

	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("verify lần 1: %v", err)
	}
	firstHits := hits

	// verify 5 lần nữa: KHÔNG được tăng hits (cache 15 phút)
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Fatalf("verify lần %d: %v", i+2, err)
		}
	}
	if hits != firstHits {
		t.Fatalf("gọi JWKS %d lần sau khi cache — phải 0", hits-firstHits)
	}
}

// T7.4 — kid lạ -> refetch NGAY (rotation không làm sập consumer).
func TestUnknownKidTriggersRefetch(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)

	current := "kA"
	pubs := map[string]*rsa.PublicKey{"kA": &keyA.PublicKey, "kB": &keyB.PublicKey}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kid := current
		pub := pubs[kid]
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer srv.Close()

	v := New(srv.URL)
	if _, err := v.Verify(context.Background(), signRS(t, keyA, "kA", time.Hour)); err != nil {
		t.Fatalf("verify kA: %v", err)
	}

	// Rotate: server chỉ còn kB
	current = "kB"
	tokB := signRS(t, keyB, "kB", time.Hour)

	claims, err := v.Verify(context.Background(), tokB)
	if err != nil {
		t.Fatalf("verify kB sau rotate (phải refetch + thành công): %v", err)
	}
	if claims.UserID != "u1" {
		t.Fatalf("claims sai: %+v", claims)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := fakeJWKS(t, "k1", &key.PublicKey, nil)
	defer srv.Close()

	v := New(srv.URL)
	token := signRS(t, key, "k1", -time.Minute) // đã hết hạn
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("token hết hạn phải bị từ chối")
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	keyGood, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyEvil, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := fakeJWKS(t, "k1", &keyGood.PublicKey, nil)
	defer srv.Close()

	v := New(srv.URL)
	token := signRS(t, keyEvil, "k1", time.Hour) // ký bằng key khác
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("chữ ký sai phải bị từ chối")
	}
}

func signRS(t *testing.T, key *rsa.PrivateKey, kid string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := Claims{
		UserID: "u1",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u1",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}