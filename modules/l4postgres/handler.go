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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

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
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.postgres",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Handle handles the connection.
func (h *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// 根据 SSLRequired 设置发送响应字节
	var response byte
	if h.SSLRequired {
		response = sslRequiredReply // 'S'
	} else {
		response = plaintextReply // 'N'
	}

	// 向客户端写入响应字节
	if _, err := cx.Write([]byte{response}); err != nil {
		return err
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

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
)
