# Vigil Security Scanner

Stop your AI agents from leaking secrets and hijacking ports in 30 seconds.

```bash
curl -sSL https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh | sh
```

**Join the red-team community:** https://discord.gg/7Mzcc2EY

## What is this?

Vigil is a sidecar security scanner for AI agents. It attaches to your MCP servers, Docker containers, or Kubernetes pods and auto-kills processes that leak secrets or get hijacked via prompt injection.

No config. No agents. Just a single binary that watches your back.

## Quick Start

### Install & Run

```bash
# Recommended: verify the installer before running
curl -sSL -o /tmp/vigil.sh https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh
curl -sSL -o /tmp/vigil.sh.sha256 https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh.sha256
curl -sSL -o /tmp/vigil_ed25519_pub.pem https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil_ed25519_pub.pem

# verify checksum
sha256sum -c /tmp/vigil.sh.sha256

# verify signature (OpenSSL with Ed25519)
openssl pkeyutl -verify -pubin -inkey /tmp/vigil_ed25519_pub.pem -in /tmp/vigil.sh -sigfile /tmp/vigil.sh.sig || echo "signature verify failed or not present"

# if verification succeeds, run installer
sh /tmp/vigil.sh

# Or build from source
git clone https://github.com/vigil-sec/vigil.git
cd vigil
make build
./build/vigil
```

### First Scan (Dry Run)

```bash
# See what would be blocked without killing anything
vigil-scan --dry-run

# Output:
# 🔍 Found 3 exposed secrets
# ⚠️  Process 12345 (node) has AWS key in env
# ⚠️  Port 11434 (Ollama) exposed to localhost
# 📊 Summary: 2 threats detected, 0 actions taken
```

### Enable Enforcement

```bash
# Actually kill rogue processes and block ports
export VIGIL_ENV=hard
vigil

# Output:
# 🚨 Killed process 12345 (node) - leaked AWS key
# 🚨 Blocked port 11434 - Ollama hijack risk
# ✅ Log signed: 0x4f3d... (saved to ~/.vigil/ledger.jsonl)
```

## How It Works

```
┌─────────────────────────────────┐
│  Your AI Agent (MCP/Docker/K8s) │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Vigil Sidecar (Go binary)      │
├─────────────────────────────────┤
│  🔍 Scanner                     │
│  ├─ Secret patterns (AWS, GH)   │
│  ├─ Port blacklist              │
│  └─ Process tree inspection     │
│                                 │
│  ⚔️  Enforcer                    │
│  ├─ kill -9 on threat           │
│  └─ iptables block              │
│                                 │
│  🔐 Attestation                 │
│  ├─ Ed25519 signing             │
│  └─ Immutable log               │
└─────────────────────────────────┘
```

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| Secret Detection | Finds AWS keys, GitHub tokens, API keys | ✅ |
| Port Hijack Block | Auto-kills processes on risky ports (11434, 8000, etc.) | ✅ |
| Env Hardening | Masks sensitive vars from child processes | ✅ |
| Immutable Logs | Every action cryptographically signed | ✅ |
| Real-Time Alerts | Slack & Discord webhooks | ✅ |
| eBPF Probes | Kernel-level syscall monitoring | 🚧 |
| Teams Dashboard | Multi-tenant SaaS platform | 🚧 |

## Real Usage Examples

### MCP Server (Claude Desktop)

```bash
# In your MCP server directory
vigil-scan --mcp --slack $SLACK_WEBHOOK

# Now if prompt injection tries to expose your env, Vigil kills it
```

### Docker Container

```bash
# Run inside container at startup
docker run -d my-ai-agent sh -c "curl -sSL https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh | sh && vigil-scan & my-agent"

# Or as a sidecar
docker-compose.yml:
  vigil:
    image: ghcr.io/vigil-sec/vigil:latest
    network_mode: "container:main-agent"
```

### Kubernetes Pod

```bash
# Add as init container
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
spec:
  initContainers:
  - name: vigil
    image: ghcr.io/vigil-sec/vigil:latest
    command: ["sh", "-c", "vigil-scan --k8s"]
EOF
```

## Community & Contributing

### 🎯 Mission

We're building the default security layer for the agentic economy. Whether you vibe-code your way to an MVP or handcraft every line—your AI agents need guardrails.

### 💬 Join Discord

https://discord.gg/7Mzcc2EY

- `#scan-support` - Get help in 5 minutes
- `#threat-feed` - See anonymized attacks blocked
- `#feature-requests` - Shape the roadmap

### 🤝 Contribute

```bash
# 1. Fork & clone
git clone https://github.com/vigil-sec/vigil.git

# 2. Make changes
cd vigil
make test  # Ensure all 20 tests pass

# 3. Submit PR
gh pr create --title "feat: my cool feature" --body "Closes #123"
```

**Star ⭐ the repo** if you want us to add:
- Kubernetes operator
- GitHub Actions marketplace listing
- React dashboard

## FAQ

**Q: Will this break my app?**
A: Use `--dry-run` first. We only kill processes that leak secrets or bind to hijack-risk ports.

**Q: Does it work with vibecoding tools?**
A: Yes. Vigil is tool-agnostic. It secures the runtime, not the code.

**Q: What about false positives?**
A: Edit the port blacklist or secret patterns in `pkg/scanner/`. Rebuild with `make build`.

**Q: Is telemetry enabled by default?**
A: No. We're privacy-first. Opt-in with `--telemetry` to help us track threats.

## Security Considerations

- Keys stored in `~/.vigil/key` (mode 0600)
- Signatures use Ed25519 (quantum-resistant upgrade coming)
- All logs signed before upload
- No outbound calls unless `--telemetry` or `--slack` is set
- eBPF probes run with least privilege

## License

MIT. Use it. Break it. Fix it. Share it.

## Final Ask

If you're building AI agents, you're already in the red team's crosshairs. Don't ship without guardrails.

```bash
curl -sSL https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh | sh
```

Then star ⭐ the repo and join the Discord. Let's make agentic AI safer. Together.
