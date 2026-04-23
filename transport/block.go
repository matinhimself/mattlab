package transport

import (
	"context"
	"fmt"
	"net"
)

// BlockTransport immediately rejects all connections.
type BlockTransport struct{}

// NewBlock creates a new BlockTransport.
func NewBlock() *BlockTransport {
	return &BlockTransport{}
}

func (b *BlockTransport) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("blocked")
}

func (b *BlockTransport) Name() string { return "block" }

func (b *BlockTransport) Close() error { return nil }
