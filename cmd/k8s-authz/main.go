package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/zcayou/k8s-authz/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.Execute(ctx, cli.NewCommand())
}
