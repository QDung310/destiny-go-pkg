module github.com/QDung310/destiny-go-pkg

// Go 1.22 là mức tối thiểu — cả 8 project đều >= 1.24.
//
// DRIVER v2 (quyết định 2026-10-25): 3 project đã ở v2, v1 đang bảo trì.
// 4 project còn ở v1 sẽ chỉ dùng 6 package khác (auth/config/telegram/httpx/ratelimit/authverify),
// riêng pkg/mongo chờ chúng nâng lên v2.
go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	go.mongodb.org/mongo-driver/v2 v2.8.0
)

require (
	github.com/klauspost/compress v1.17.6 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.2.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)
