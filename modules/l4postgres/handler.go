// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package l4postgres allows the L4 multiplexing of Postgres connections
package l4postgres

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

const (
	plaintextReply   = 'N' // no - plaintext
	sslRequiredReply = 'S' // yes - SSL required
)

// Handler is a simple handler that writes what it reads.
type Handler struct {
	// Whether SSL is required for PostgreSQL connections
	SSLRequired bool `json:"ssl_required,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.postgres",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	return nil
}

// Handle handles the connection.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// 读取前8字节 (PostgreSQL SSLRequest 消息长度+代码)
	header := make([]byte, 8)
	if _, err := io.ReadFull(cx.Conn, header); err != nil {
		return err
	}

	// 检查是否为 SSLRequest (80877103)
	if binary.BigEndian.Uint32(header[4:]) == 80877103 {
		// 根据配置回复 'S' 或 'N'
		var response byte
		if h.SSLRequired {
			response = sslRequiredReply
		} else {
			response = plaintextReply
		}

		if _, err := cx.Conn.Write([]byte{response}); err != nil {
			return err
		}

		h.logger.Debug("PostgreSQL SSL request detected",
			zap.String("remote", cx.Conn.RemoteAddr().String()),
			zap.Bool("ssl_required", h.SSLRequired))
	} else {
		// 如果不是 SSLRequest，把读取的数据放回"连接"中
		h.logger.Debug("PostgreSQL SSL request not detected, passing through data",
			zap.String("remote", cx.Conn.RemoteAddr().String()),
			zap.Int("bytes", len(header)))
		cx.Conn = &bufferPrependConn{
			Conn:   cx.Conn,
			buffer: header,
		}
	}

	// 将连接传递给下一个处理程序
	return next.Handle(cx)
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	postgres {
//		ssl_required
//	}
//	postgres
//
// Note: according to the protocol documentation, SSL is not required by default, i.e. it depends on the client
// whether it will send the SSLRequest message or not.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	// Check for block options
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		option := d.Val()
		switch option {
		case "ssl_required":
			h.SSLRequired = true
		default:
			return d.Errf("unknown postgres option '%s'", option)
		}

		// No arguments are supported for options
		if d.NextArg() {
			return d.ArgErr()
		}

		// No nested blocks are supported
		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, option)
		}
	}

	return nil
}

// 实现一个能将数据预置到连接前端的包装器
type bufferPrependConn struct {
	net.Conn
	buffer    []byte
	bufferPos int
}

// 重写 Read 方法，先读取缓冲区中的数据
func (c *bufferPrependConn) Read(b []byte) (n int, err error) {
	// 先读取缓冲区中的数据
	if len(c.buffer) > c.bufferPos {
		n = copy(b, c.buffer[c.bufferPos:])
		c.bufferPos += n

		// 如果缓冲区已读完，清除它
		if c.bufferPos >= len(c.buffer) {
			c.buffer = nil
			c.bufferPos = 0
		}

		return n, nil
	}

	// 缓冲区为空，直接从连接读取
	return c.Conn.Read(b)
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ caddy.Provisioner     = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)
