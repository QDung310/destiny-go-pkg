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
}

// Client — wrapper giữ *mongo.Client + Database.
type Client struct {
	*mongo.Client
	DB *mongo.Database
}

// Connect mở kết nối, ping, trả Client. Caller PHẢI gọi Disconnect.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.URI == "" {
		return nil, fmt.Errorf("mongo: URI rỗng")
	}
	if cfg.DBName == "" {
		return nil, fmt.Errorf("mongo: DBName rỗng")
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = 5 * time.Second
	}

	opts := options.Client().
		ApplyURI(cfg.URI).
		SetServerSelectionTimeout(cfg.ConnectTimeout)

	// v2: Connect KHÔNG nhận context
	mc, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("mongo: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.PingTimeout)
	defer cancel()
	if err := mc.Ping(pingCtx, nil); err != nil {
		_ = mc.Disconnect(context.Background())
		return nil, fmt.Errorf("mongo: ping: %w", err)
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