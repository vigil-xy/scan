# Vigil Security Scanner

**Stop AI agents from leaking secrets and hijacking ports in 30 seconds.**

```bash
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh
```

**Join the red-team community:** https://discord.gg/7Mzcc2EY

---

## Quick Start

**Install:**
```bash
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh
```

**Scan:**
```bash
vigil-scan --dry-run
```

**Dashboard:** [Launch on Replit](https://replit.com)

---

## What It Scans

🔍 **Rogue agent ports** (11434, 8000, 5000, etc.)  
🔑 **Leaked secrets** (AWS keys, GitHub tokens, API keys)  
⚔️ **Suspicious processes** (eBPF monitoring)  
🔐 **Cryptographic attestation** (immutable logs)

---

## Community

**Discord:** https://discord.gg/7Mzcc2EY

- `#scan-support` - Get help in 5 minutes
- `#threat-feed` - See anonymized attacks blocked
- `#feature-requests` - Shape the roadmap

---

## For Security Teams (Optional Verification)

```bash
git clone https://github.com/vigil-xy/scan.git
cd scan
bash scripts/verify_installer.sh  # ✅ Shows Ed25519 signature verification
vigil-scan --json --slack $SLACK_WEBHOOK
```

---

## Replit Dashboard

Launch your own monitoring dashboard:

```bash
git clone https://github.com/vigil-xy/scan.git
cd scan/repl-dashboard
python server.py
# Visit: http://localhost:8080
```

Dashboard features:
- Real-time rogue port detection
- Secret leak tracking
- Process monitoring
- Immutable audit logs

---

## Platform Support

| Platform | Arch | Status |
|----------|------|--------|
| Linux | AMD64 | ✅ |
| Linux | ARM64 | ✅ |
| macOS | AMD64 | ✅ |
| macOS | ARM64 (Apple Silicon) | ✅ |

The installer automatically detects your platform and downloads the correct binary.

---

## Advanced Usage

### MCP Server (Claude Desktop)

```bash
vigil-scan --mcp --slack $SLACK_WEBHOOK
```

### Docker Container

```bash
docker run -d my-ai-agent sh -c "curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh && vigil-scan & my-agent"
```

### Kubernetes Pod

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
spec:
  initContainers:
  - name: vigil
    image: ghcr.io/vigil-xy/vigil:latest
    command: ["sh", "-c", "vigil-scan --k8s"]
