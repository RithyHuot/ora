package proxy_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/rithyhuot/ora/pkg/proxy"
)

func ExampleNewEgress() {
	e := proxy.NewEgress(proxy.EgressConfig{
		Allowed: []string{"api.openai.com"},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start: %v\n", err)
		return
	}
	_ = port // proxy is now listening; wire HTTPS_PROXY=http://127.0.0.1:port
	_ = e.Stop()
}
