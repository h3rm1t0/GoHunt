package main

import (
	"GoHunt/internal/hunt"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

//go:embed banner.txt
var banner string

func main() {
	hunt.PrintBanner(os.Stdout, banner)
	fmt.Fprintln(os.Stdout, "Criado por h3rm1t0 · reconhecimento e triagem")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := hunt.CLI(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "GoHunt:", err)
		os.Exit(1)
	}
}
