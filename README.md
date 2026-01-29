# Spectre

![Spectre](https://img.shields.io/badge/Status-Production%20Ready-green)
![Rust](https://img.shields.io/badge/Language-Rust-orange)
![Waf-Bypass](https://img.shields.io/badge/Capability-WAF%20Bypass-red)
![License](https://img.shields.io/badge/License-MIT-blue)


**Spectre** is a high-performance, ethical security testing tool designed for authorized WAF resilience testing and vulnerability assessment. It combines a high-concurrency async engine with advanced evasion capabilities (TLS fingerprinting, browser masquerading) to simulate real-world traffic patterns.

> [!WARNING]
> **Authorization Required**: This tool is for authorized testing only. You must have explicit written permission to test the target. The `--authorized` flag is mandatory for all operations.

## Features

- **🚀 High Performance**: Async-driven engine (Tokio) capable of high concurrency.
- **🕵️ Advanced Evasion**: 
    - **TLS Fingerprinting**: Mimics Chrome, Firefox, Safari, and Edge to bypass fingerprint-based blockers.
    - **WAF Detection**: Identifies Cloudflare, Akamai, Azure, and others.
    - **Biometric Spoofing**: Solves JS challenges via headless browser automation.
- **💥 Payload Engine**: 
    - Load payloads from files (SecLists compatible).
    - **Tampering**: Apply encoding (URL, Base64) to bypass filters.
    - **Template Injection**: Fuzz headers, body, or URL parameters.
- **🛡️ Safety & Reporting**:
    - **PII Redaction**: Automatically masks sensitive data in logs.
    - **Time Limits**: Auto-stop scans for safety.
    - **Reporting**: Export results to JSON or HTML.
- **☁️ Scalability**:
    - **Docker**: Containerized for easy deployment.
    - **Kubernetes**: Ready-made manifests for cloud orchestration.
    - **REST API**: Control scans programmatically.

## Installation

### From Source
```bash
git clone https://github.com/spectre-sec/spectre
cd spectre
cargo build --release
./target/release/spectre --help
```

### Docker
```bash
docker build -t spectre .
docker run --rm spectre --help
```

## Usage Guide

### 1. Basic Scan
Run a basic GET request scan against a target using a list of payloads.
```bash
spectre --authorized \
  --target "http://example.com/search?q={payload}" \
  --payload-file payloads.txt \
  --concurrency 10
```

### 2. WAF Detection & Evasion
Detect the WAF first, then use a randomized browser profile to evade fingerprinting.
```bash
spectre --authorized \
  --target "http://protected-site.com" \
  --detect \
  --profile random \
  --payload-file SQLi.txt
```

### 3. Reporting & Safety
Generate an HTML report and limit the scan to 60 seconds.
```bash
spectre --authorized \
  --target "http://example.com" \
  --payload-file xss.txt \
  --report scan_results.html \
  --time-limit 60
```

### 4. Payload Tampering
Apply tamper techniques to your payloads to test WAF parsing rules.
```bash
# Apply URL encoding
spectre --authorized --target "http://example.com" --payload-file basic.txt --tamper url_encode

# Apply Base64 encoding
spectre --authorized --target "http://example.com" --payload-file basic.txt --tamper base64
```

### 5. API Mode
Start Spectre as a REST API server (useful for integration with other tools).

**Start Server:**
```bash
spectre --authorized --api
# Listening on 0.0.0.0:3000
```

**Trigger Scan:**
```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://example.com",
    "method": "GET",
    "concurrency": 5
  }'
```

**Get Status:**
```bash
curl http://localhost:3000/status
```

### 6. Kubernetes Deployment
Deploy Spectre to your K8s cluster.
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### 7. Tier-1 Evasion (Unicode & Sticky Sessions)
Bypass advanced WAF filters using Unicode overflow and maintain session persistence.

```bash
# Apply Unicode Overflow tampering (Full-width characters)
spectre --authorized \
  --target "http://example.com/search?q={payload}" \
  --payload-file xss_payloads.txt \
  --tamper unicode

# Scans automatically use Sticky Sessions to maintain cookies and trust scores.
# If a session is blocked, it is automatically discarded and a new one is created.
```

## Ethical Use Policy
Spectre is strictly for:
- Testing your own infrastructure.
- Authorizedtesting (with written consent).

**Do not use this tool for unauthorized access or disruption.**
