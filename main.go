package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/urfave/cli/v3"
)

var (
	ipt     *iptables.IPTables
	version = "dev"
	commit  = "HEAD"
	date    = ""
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	var err error
	ipt, err = iptables.New()
	if err != nil {
		slog.Error("failed to initialize iptables", slog.Any("err", err))
		os.Exit(1)
	}

	tool := cli.Command{
		Name:        "iptablesf",
		Description: "f up iptables",
		Version:     fmt.Sprintf("%s (%s, %s)", version, commit, date),
		Authors: []any{
			map[string]string{
				"name": "Till Klampaeckel",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "chain",
				Value: "DOCKER-USER",
			},
		},
		Before: before,
		Commands: []*cli.Command{
			{
				Name:  "clear",
				Usage: "reset/clear the chain",
				Action: func(ctx context.Context, c *cli.Command) error {
					chain := c.String("chain")
					if err := ipt.ClearChain("filter", chain); err != nil {
						return fmt.Errorf("clearing %s: %v", chain, err)
					}
					if err := ipt.Append("filter", chain, "-j", "RETURN"); err != nil {
						return fmt.Errorf("restoring RETURN rule in %s: %v", chain, err)
					}
					slog.Info("cleared all rules (RETURN rule restored)", slog.String("chain", chain))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list rules in a chain",
				Action: func(ctx context.Context, c *cli.Command) error {
					rules, err := ipt.List("filter", c.String("chain"))
					if err != nil {
						return fmt.Errorf("listing rules: %v", err)
					}

					for _, rule := range rules {
						fmt.Println(rule)
					}

					return nil
				},
			},
			{
				Name:  "add",
				Usage: "updates a chain to block (DROP) the IPs in --file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Required: true,
						Usage:    "path to file containing IP CIDRs (one per line)",
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					cidrs, err := readCIDRs(c.String("file"))
					if err != nil {
						return fmt.Errorf("reading CIDRs: %v", err)
					}

					if len(cidrs) == 0 {
						return fmt.Errorf("no valid CIDRs found in file")
					}

					chain := c.String("chain")
					for _, cidr := range cidrs {
						rule := []string{"-s", cidr, "-j", "DROP"}
						exists, err := ipt.Exists("filter", chain, rule...)
						if err != nil {
							slog.Error("failed to check rule", slog.String("cidr", cidr), slog.Any("err", err))
							continue
						}
						if exists {
							slog.Debug("already blocked", slog.String("cidr", cidr), slog.String("chain", chain))
							continue
						}
						if err := ipt.Insert("filter", chain, 1, rule...); err != nil {
							slog.Error("failed to add rule", slog.String("cidr", cidr), slog.Any("err", err))
							continue
						}
						slog.Info("added new block rule", slog.String("cidr", cidr), slog.String("chain", chain))
					}

					return nil
				},
			},
		},
	}

	if err := tool.Run(context.Background(), os.Args); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func before(ctx context.Context, c *cli.Command) (context.Context, error) {
	if c.String("chain") == "" {
		return ctx, fmt.Errorf("please add --chain")
	}

	exists, err := ipt.ChainExists("filter", c.String("chain"))
	if err != nil {
		return ctx, fmt.Errorf("checking %s chain: %v", c.String("chain"), err)
	}
	if !exists {
		return ctx, fmt.Errorf("%s chain does not exist — is Docker running?", c.String("chain"))
	}
	return ctx, nil
}

func readCIDRs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cidrs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.Trim(line, `"`)

		_, _, err := net.ParseCIDR(line)
		if err != nil {
			slog.Warn("skipping invalid CIDR", slog.String("cidr", line), slog.Any("err", err))
			continue
		}

		cidrs = append(cidrs, line)
	}

	return cidrs, scanner.Err()
}
