# iptablesf

[![CI](https://github.com/Luzilla/iptablesf/actions/workflows/ci.yml/badge.svg)](https://github.com/Luzilla/iptablesf/actions/workflows/ci.yml)
[![Release](https://github.com/Luzilla/iptablesf/actions/workflows/release.yml/badge.svg)](https://github.com/Luzilla/iptablesf/actions/workflows/release.yml)

Block IP CIDRs in the `DOCKER-USER` iptables chain. Rules are inserted before the default `RETURN` rule so they actually take effect.

Requires root (or `CAP_NET_ADMIN`). Requires Docker to be running (the `DOCKER-USER` chain must exist).

> [!IMPORTANT]
> Contributions are welcome! Please star this repository if you find it useful.
> For custom feature development or support, feel free to get in touch.

## Install

Download a binary from [Releases](https://github.com/Luzilla/iptablesf/releases).

| OS | Arch |
|----|------|
| linux | amd64 |
| darwin | arm64 |

Or build from source:

```
go install github.com/luzilla/iptablesf@latest
```

## Usage

### Add rules from a file

```
sudo iptablesf add --file blocklist.txt
```

The file contains one CIDR per line. Blank lines and `#` comments are skipped. Quoted entries (`"10.0.0.0/8"`) are handled.

```
# example blocklist.txt
"192.168.1.0/24"
10.0.0.0/8
```

### List rules

```
sudo iptablesf list
```

### Clear all rules

Flushes the chain and restores the default `-j RETURN` rule.

```
sudo iptablesf clear
```

### Custom chain

All commands accept `--chain` (default: `DOCKER-USER`):

```
sudo iptablesf --chain MY-CHAIN add --file blocklist.txt
```

## Build

```
make build
```

Uses goreleaser.
