# Vigil Security Scanner

**Stop AI agents from leaking secrets and hijacking ports in 30 seconds.**

```bash
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh
```

**Launch your CRM dashboard:** `vigil-scan dashboard` → http://localhost:8080

**Join the community:** https://discord.gg/7Mzcc2EY

---

## 🎯 What It Does

🔍 **Scans your system for:**
- Rogue agent ports (Ollama, dev servers, Jupyter)
- Leaked secrets (AWS, GitHub tokens)
- Suspicious processes (eBPF monitoring)

⚔️ **Auto-kills threats** (when not in dry-run mode)

📊 **Shows everything in a local CRM-style dashboard**

🔐 **Proves all actions with cryptographic signatures**

---

## 🚀 Install & Use

**Install in one command:**
```bash
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh
```

**Launch dashboard (CRM-style UI):**
```bash
vigil-scan dashboard
```

**Run quick scan:**
```bash
vigil-scan --dry-run
```

---

## 📊 CRM Dashboard

Your personal security command center:

```bash
vigil-scan dashboard
```

Features:
- **Real-time Security Score** (0-100)
- **Rogue Ports** detection
- **Leaked Secrets** tracking
- **Immutable Audit Log**

**No cloud. No accounts. Fully local.**

Dashboard auto-opens in your browser at `http://localhost:8080`

---

## 🔍 Example Output

```
🔍 Vigil Security Scanner v0.2.0
📦 Downloading vigil-scan-darwin-arm64...
✅ Installed to /Users/you/.local/bin/vigil-scan

🚀 Running security scan...

🚨 Rogue agent port 11434 (Ollama) is OPEN
🚨 Process 12345 (node) has AWS key in env
📊 Summary: 2 threats detected, 2 actions taken
✅ Log signed: 0x4f3d...

Launch dashboard: vigil-scan dashboard
```

---

## 🔐 For Security Teams (Optional)

Verify before install:
```bash
git clone https://github.com/vigil-xy/scan.git
cd scan
bash scripts/verify_installer.sh  # ✅ Ed25519 signature verification
```

---

## 💬 Community

- **Discord:** https://discord.gg/7Mzcc2EY
- **GitHub:** https://github.com/vigil-xy/scan

---

## 📦 Platform Support

✅ **Linux** (AMD64, ARM64)  
✅ **macOS** (Intel, Apple Silicon)

Installer auto-detects your system.

---

## 🛠️ Development

```bash
# 1. Fork & clone
git clone https://github.com/vigil-xy/scan.git

# 2. Make changes
cd scan
make test

# 3. Build
make build

# 4. Test dashboard
./build/vigil-scan dashboard

# 5. Submit PR
gh pr create --title "feat: my cool feature"
```



---

## 🎯 Final Ask

If you're building AI agents, you're already in the red team's crosshairs. Don't ship without guardrails.

```bash
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh
vigil-scan dashboard
```

**Star ⭐ the repo** if you want Kubernetes operator next!

Then join the Discord: https://discord.gg/7Mzcc2EY

Let's make agentic AI safer. Together.
