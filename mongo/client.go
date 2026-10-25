// Package mongo — connect + index bootstrap idempotent (driver v2).
//
// Port từ 6 bản copy. Dùng driver **v2** (`go.mongodb.org/mongo-driver/v2`)
// vì 3 project đã ở v2 và v1 đang bảo trì (quyết định 2026-10-25).
//
// KHÁC BIỆT v1 -> v2:
//
//	mongo.Connect(opts)        thay vì  mongo.Connect(ctx, opts)
//	mongo.Disconnect(ctx)      không đổi
//	options.Client()           vẫn ở package options (v2/options)
package mongo

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Config — tham số kết nối.
type Config struct {
	URI            string
	DBName         string
	ConnectTimeout time.Duration
	PingTimeout    time.Duration

	// RetryAttempts — số lần ping tối đa khi khởi động (0 = dùng default 10).
	// LÝ DO: sau REBOOT, Docker start lại container CŨ (restart: unless-stopped)
	// TRƯỚC khi Mongo init xong — `depends_on:` của compose KHÔNG áp dụng cho
	// lần restart đó. Ping 1 lần rồi trả lỗi => main() log.Fatalf => container
	// exit => restart loop. Đã trúng thật ở platform-api (P35) và dashboard/
	// tempmail (P36). Đo thực tế: Mongo cần ~30s sau reboot.
	RetryAttempts int
	// RetryDelay — thời gian chờ giữa 2 lần ping (0 = 3s).
	// 10 × 3s = 30s, khớp thời gian Mongo cần sau reboot.
	RetryDelay time.Duration
}

// Client — wrapper giữ *mongo.Client + Database.
type Client struct {
	*mongo.Client
	DB *mongo.Database
}

// Hằng số retry mặc định — tách ra để test chốt được (retry_test.go).
const (
	defaultRetryAttempts = 10
	defaultRetryDelay    = 3 * time.Second
)

// applyDefaults điền giá trị mặc định cho các field bằng 0.
func applyDefaults(cfg *Config) {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = 5 * time.Second
	}
	if cfg.RetryAttempts == 0 {
		cfg.RetryAttempts = defaultRetryAttempts
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = defaultRetryDelay
	}
	if cfg.RetryAttempts < 1 {
		cfg.RetryAttempts = 1
	}
}

// Connect mở kết nối, ping (có RETRY), trả Client. Caller PHẢI gọi Disconnect.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("mongo: URI rỗng")
	}
	if cfg.DBName == "" {
		return nil, fmt.Errorf("mongo: DBName rỗng")
	}
	applyDefaults(&cfg)

	opts := options.Client().
		ApplyURI(cfg.URI).
		SetServerSelectionTimeout(cfg.ConnectTimeout)

	// v2: Connect KHÔNG nhận context
	mc, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("mongo: connect: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= cfg.RetryAttempts; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, cfg.PingTimeout)
		pingErr := mc.Ping(pingCtx, nil)
		cancel()
		if pingErr == nil {
			if attempt > 1 {
				log.Printf("[mongo] connected sau %d lan thu", attempt)
			}
			lastErr = nil
			break
		}
		lastErr = pingErr
		if attempt < cfg.RetryAttempts {
			log.Printf("[mongo] ping fail (lan %d/%d): %v — cho %s", attempt, cfg.RetryAttempts, pingErr, cfg.RetryDelay)
			select {
			case <-ctx.Done():
				_ = mc.Disconnect(context.Background())
				return nil, fmt.Errorf("mongo: ping bi huy: %w", ctx.Err())
			case <-time.After(cfg.RetryDelay):
			}
		}
	}
	if lastErr != nil {
		_ = mc.Disconnect(context.Background())
		return nil, fmt.Errorf("mongo: ping sau %d lan thu: %w", cfg.RetryAttempts, lastErr)
	}

	return &Client{Client: mc, DB: mc.Database(cfg.DBName)}, nil
}

// Disconnect đóng kết nối.
func (c *Client) Disconnect(ctx context.Context) error {
	if c == nil || c.Client == nil {
		return nil
	}
	return c.Client.Disconnect(ctx)
}

// IndexSpec — khai báo 1 index.
type IndexSpec struct {
	Collection string
	Keys       bson.D
	Unique     bool
	// TTL: >0 thì index có expireAfterSeconds.
	TTL *time.Duration
	// Name: rỗng thì Mongo tự đặt.
	Name string
}

// EnsureIndexes tạo index theo registry. IDEMPOTENT: chạy 2 lần không lỗi,
// không nhân đôi (Mongo tự bỏ qua index đã tồn tại cùng key+options).
func (c *Client) EnsureIndexes(ctx context.Context, specs []IndexSpec) error {
	for _, spec := range specs {
		opts := options.Index()
		if spec.Unique {
			opts.SetUnique(true)
		}
		if spec.TTL != nil && *spec.TTL > 0 {
			opts.SetExpireAfterSeconds(int32(spec.TTL.Seconds()))
		}
		if spec.Name != "" {
			opts.SetName(spec.Name)
		}

		model := mongo.IndexModel{Keys: spec.Keys, Options: opts}
		if _, err := c.DB.Collection(spec.Collection).Indexes().CreateOne(ctx, model); err != nil {
			return fmt.Errorf("mongo: index %s.%s: %w", spec.Collection, spec.Name, err)
		}
	}
	return nil
}