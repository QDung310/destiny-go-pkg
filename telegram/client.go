// Package telegram — client Bot API, best-effort.
//
// Port từ 9 nơi gọi sendMessage: destiny-backend, api-hitter, telegram-bot,
// Tempmail scanner, dashboard-api (relay + broadcast + emojipreview), mail-inbox,
// shop/bot, ops/health-alert.sh.
//
// NGUYÊN TẮC: best-effort — lỗi gửi KHÔNG được làm sập request chính.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBase = "https://api.telegram.org"

// Config — token bot + endpoint (đổi được để test).
type Config struct {
	Token   string
	BaseURL string // rỗng -> api.telegram.org
	Timeout time.Duration
	Retries int // 0 -> 2
}

// Client — gửi message/photo.
type Client struct {
	cfg  Config
	http *http.Client
}

// New tạo client. Token rỗng trả error (fail sớm).
func New(cfg Config) (*Client, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("telegram: Token rỗng")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBase
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.Retries == 0 {
		cfg.Retries = 2
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// SendText gửi text. Hỗ trợ HTML/Markdown. Tự cắt nếu > 4096 (giới hạn Telegram).
func (c *Client) SendText(ctx context.Context, chatID string, text string, opts ...Option) error {
	o := applyOptions(opts)
	if len(text) > 4096 {
		text = text[:4090] + "…"
	}
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": o.ParseMode,
	}
	if o.DisablePreview {
		payload["link_preview_options"] = map[string]any{"is_disabled": true}
	}
	if o.ThreadID != 0 {
		payload["message_thread_id"] = o.ThreadID
	}
	return c.call(ctx, "sendMessage", payload)
}

// SendPhoto gửi ảnh theo URL (không upload file để tránh multipart).
func (c *Client) SendPhoto(ctx context.Context, chatID, photoURL, caption string, opts ...Option) error {
	o := applyOptions(opts)
	payload := map[string]any{
		"chat_id": chatID,
		"photo":   photoURL,
	}
	if caption != "" {
		if len(caption) > 1024 {
			caption = caption[:1020] + "…"
		}
		payload["caption"] = caption
		payload["parse_mode"] = o.ParseMode
	}
	return c.call(ctx, "sendPhoto", payload)
}

// EditMessage sửa message đã gửi.
func (c *Client) EditMessage(ctx context.Context, chatID string, messageID int, text string, opts ...Option) error {
	o := applyOptions(opts)
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
		"parse_mode": o.ParseMode,
	}
	return c.call(ctx, "editMessageText", payload)
}

// call POST JSON, có retry. Trả error cuối cùng nếu mọi lần fail.
func (c *Client) call(ctx context.Context, method string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram: marshal: %w", err)
	}

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/bot" + c.cfg.Token + "/" + method
	var lastErr error

	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("telegram: new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("telegram: %s HTTP %d: %s", method, resp.StatusCode, string(respBody))
			// 4xx (trừ 429) là lỗi vĩnh viễn — retry vô ích
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
		}

		if attempt < c.cfg.Retries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			}
		}
	}
	return lastErr
}

// ── options ──────────────────────────────────────────────────────────────

// Option tùy chỉnh lời gọi.
type Option func(*options)

type options struct {
	ParseMode      string
	DisablePreview bool
	ThreadID       int
}

func applyOptions(opts []Option) options {
	o := options{ParseMode: "HTML"}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// ParseMode đặt parse mode (mặc định HTML; "" = text thuần).
func ParseMode(mode string) Option {
	return func(o *options) { o.ParseMode = mode }
}

// DisablePreview tắt preview link.
func DisablePreview() Option {
	return func(o *options) { o.DisablePreview = true }
}

// Thread gửi vào topic (forum group).
func Thread(messageThreadID int) Option {
	return func(o *options) { o.ThreadID = messageThreadID }
}