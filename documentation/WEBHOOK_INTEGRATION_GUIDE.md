# Epyon Webhook Integration Guide

## Overview

Epyon supports **real-time webhook notifications** during security scans, allowing management UIs (like Barbatos) to track scan progress without polling GitHub Actions or waiting for artifacts.

Webhooks are **completely optional** — if not configured, Epyon runs normally without any notifications.

## Features

- **Real-time progress updates** - Get notified when each security tool starts and completes
- **No workflow changes required** - Works with ANY workflow that runs Epyon
- **Graceful degradation** - If webhooks fail or aren't configured, the scan continues normally
- **Secure HMAC signatures** - Optional cryptographic validation of webhook payloads
- **Automatic retries** - Failed webhook calls are retried up to 3 times

## Configuration

Epyon reads three **environment variables** for webhook configuration:

| Environment Variable | Required | Description |
|---------------------|----------|-------------|
| `EPYON_CALLBACK_URL` | Yes | Full HTTPS URL where notifications will be POSTed |
| `EPYON_JOB_ID` | No | Unique identifier for this scan job (passed back in payloads) |
| `EPYON_WEBHOOK_SECRET` | No | Shared secret for HMAC-SHA256 signature generation |

### Setting Environment Variables

#### Option 1: GitHub Actions Workflow (Recommended)

The reusable workflow accepts webhook inputs that are automatically passed as environment variables to Epyon:

```yaml
jobs:
  security-scan:
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: full
      epyon_callback_url: https://srtm.dialtone.cc/api/security-scan-webhook
      epyon_job_id: ${{ github.run_id }}-${{ github.run_attempt }}
      epyon_webhook_secret: ${{ secrets.EPYON_WEBHOOK_SECRET }}
    secrets: inherit
```

**Workflow Inputs:**

| Input | Required | Description |
|-------|----------|-------------|
| `epyon_callback_url` | No | Webhook endpoint URL where notifications will be POSTed |
| `epyon_job_id` | No | Unique identifier for this scan job (passed back in payloads) |
| `epyon_webhook_secret` | No | Shared secret for HMAC-SHA256 signature generation |

**For workflow_dispatch events** (when Barbatos triggers scans):

```yaml
on:
  workflow_dispatch:
    inputs:
      scan_mode:
        type: string
        default: 'full'
      epyon_callback_url:
        description: 'Webhook URL for progress notifications'
        type: string
        required: false
      epyon_job_id:
        description: 'Job identifier'
        type: string
        required: false
      epyon_webhook_secret:
        description: 'Webhook HMAC secret'
        type: string
        required: false

jobs:
  security-scan:
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: ${{ inputs.scan_mode }}
      epyon_callback_url: ${{ inputs.epyon_callback_url }}
      epyon_job_id: ${{ inputs.epyon_job_id }}
      epyon_webhook_secret: ${{ inputs.epyon_webhook_secret }}
    secrets: inherit
```

Then Barbatos can dispatch with:

```bash
curl -X POST \
  "https://api.github.com/repos/org/repo/actions/workflows/security-scan.yml/dispatches" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ref": "main",
    "inputs": {
      "scan_mode": "full",
      "epyon_callback_url": "https://srtm.dialtone.cc/api/security-scan-webhook",
      "epyon_job_id": "scan-12345",
      "epyon_webhook_secret": "your-shared-secret"
    }
  }'
```

#### Option 2: Repository Secrets (Static Configuration)

Store webhook configuration as repository secrets and reference them in your workflow:

1. Go to **Settings > Secrets and variables > Actions** in your repository
2. Add secrets:
   - `EPYON_CALLBACK_URL` - Your webhook endpoint URL
   - `EPYON_WEBHOOK_SECRET` - Your shared secret (optional but recommended)
3. Reference in workflow:

```yaml
env:
  EPYON_CALLBACK_URL: ${{ secrets.EPYON_CALLBACK_URL }}
  EPYON_WEBHOOK_SECRET: ${{ secrets.EPYON_WEBHOOK_SECRET }}
  EPYON_JOB_ID: ${{ github.run_id }}-${{ github.run_attempt }}
```

#### Option 3: Direct Environment Variables

For local testing:

```bash
export EPYON_CALLBACK_URL="https://your-server.com/webhook/epyon"
export EPYON_JOB_ID="test-scan-$(date +%s)"
export EPYON_WEBHOOK_SECRET="your-shared-secret"

./epyon.sh --target /path/to/app --app-name myapp
```

#### Option 4: FastAPI Web UI

When triggering scans via the FastAPI backend (`POST /api/scans`), include webhook configuration in the request body:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "/path/to/app",
    "scan_type": "full",
    "webhook_url": "https://barbatos.example.com/api/webhooks/scans",
    "webhook_secret": "your-shared-secret"
  }'
```

**Request Body Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes | Path or Git URL to scan |
| `scan_type` | string | No | Scan mode: `quick`, `full`, `nightly`, `stig` (default: `full`) |
| `webhook_url` | string | No | Webhook endpoint URL |
| `webhook_secret` | string | No | Shared secret for HMAC signatures |
| `run_garak` | boolean | No | Enable Garak LLM security probing (default: `false`) |
| `run_stig` | boolean | No | Enable STIG assessment (default: `false` unless `scan_type == "stig"`) |

The API automatically sets `EPYON_JOB_ID` to the job's timestamp ID.

**JavaScript Example:**

```javascript
const response = await fetch('http://localhost:8000/api/scans', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '/path/to/app',
    scan_type: 'full',
    webhook_url: 'https://barbatos.example.com/api/webhooks/scans',
    webhook_secret: 'your-shared-secret'
  })
});

const { job_id, status } = await response.json();
console.log(`Scan started: ${job_id} (${status})`);
```

## Webhook Payload Format

Every webhook notification POSTs a JSON payload:

```json
{
  "event_type": "tool_start",
  "job_id": "12345-1",
  "app_name": "myapp",
  "scan_id": "myapp_2026-06-30_12-00-00",
  "message": "Starting Trivy scan",
  "status": "in_progress",
  "tool_name": "trivy",
  "timestamp": "2026-06-30T12:00:00Z"
}
```

### Event Types

| Event Type | Description | Status Values |
|-----------|-------------|---------------|
| `scan_start` | Scan has started | `in_progress` |
| `tool_start` | A security tool is starting | `in_progress` |
| `tool_complete` | A security tool finished successfully | `success` |
| `tool_error` | A security tool encountered an error | `error`, `warning` |
| `scan_complete` | Entire scan has completed | `success`, `warning` |

### Tool Names

Tool names are normalized slugs (lowercase, hyphenated):

- `trivy` - Trivy Security Analysis
- `grype` - Grype Vulnerability Scanning
- `trufflehog` - TruffleHog Secret Detection
- `checkov` - Checkov IaC Security
- `sonarqube` - SonarQube Code Quality
- `anchore` - Anchore Container Analysis
- `xeol` - Xeol End-of-Life Detection
- `clamav` - ClamAV Malware Detection
- `helm` - Helm Chart Build
- `garak` - Garak LLM Security Probing
- And more...

## Security - HMAC Signatures

When `EPYON_WEBHOOK_SECRET` is set, Epyon generates an **HMAC-SHA256 signature** of the payload and includes it in request headers:

```
X-Epyon-Signature: sha256=a1b2c3d4...
X-Epyon-Job-Id: 12345-1
```

### Validating Signatures (Server-Side)

Your webhook endpoint should validate the signature:

**Python (FastAPI example):**

```python
import hashlib
import hmac
from fastapi import Header, HTTPException

WEBHOOK_SECRET = "your-shared-secret"

@app.post("/webhook/epyon")
async def epyon_webhook(
    payload: dict,
    x_epyon_signature: str = Header(None)
):
    if x_epyon_signature:
        # Extract signature
        signature = x_epyon_signature.replace("sha256=", "")
        
        # Compute expected signature
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
        expected_sig = hmac.new(
            WEBHOOK_SECRET.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison
        if not hmac.compare_digest(signature, expected_sig):
            raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Process webhook...
    return {"status": "ok"}
```

**Node.js (Express example):**

```javascript
const crypto = require('crypto');

const WEBHOOK_SECRET = 'your-shared-secret';

app.post('/webhook/epyon', (req, res) => {
  const signature = req.headers['x-epyon-signature'];
  
  if (signature) {
    const expectedSig = 'sha256=' + crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest('hex');
    
    if (signature !== expectedSig) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  }
  
  // Process webhook...
  res.json({ status: 'ok' });
});
```

## Error Handling

Webhooks are designed to **never block** the security scan:

1. **Connection failures** - Retried 3 times with 2-second delays
2. **Timeouts** - 10-second max timeout, 5-second connect timeout
3. **HTTP errors** - Non-2xx responses are retried
4. **All failures** - Logged as warnings but scan continues

## Testing Webhooks

### 1. Use a webhook testing service

```bash
# Create a test endpoint at webhook.site
export EPYON_CALLBACK_URL="https://webhook.site/your-unique-id"

./epyon.sh --target . --app-name test
```

Visit your webhook.site URL to see the payloads.

### 2. Local testing with a simple server

```python
# webhook-test-server.py
from flask import Flask, request
app = Flask(__name__)

@app.post("/webhook/epyon")
def webhook():
    print("Received webhook:")
    print(request.json)
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(port=8000)
```

```bash
# Terminal 1
python webhook-test-server.py

# Terminal 2
export EPYON_CALLBACK_URL="http://localhost:8000/webhook/epyon"
./epyon.sh --target . --app-name test
```

## Integration with Barbatos

Barbatos (the Epyon management UI) automatically configures webhooks when triggering scans:

1. User clicks **"Run Security Scan"** in Barbatos
2. Barbatos creates a job ID and webhook endpoint
3. Dispatches GitHub Actions workflow with workflow inputs:
   - `epyon_callback_url`: `https://srtm.dialtone.cc/api/security-scan-webhook`
   - `epyon_job_id`: `scan-12345`
   - `epyon_webhook_secret`: Shared secret from Barbatos config
4. The target repository's workflow passes these inputs to the reusable Epyon workflow
5. Epyon automatically sends progress updates back to Barbatos during the scan
6. Barbatos updates the UI in real-time

**Example workflow_dispatch call from Barbatos:**

```bash
curl -X POST \
  "https://api.github.com/repos/org/repo/actions/workflows/security-scan.yml/dispatches" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ref": "main",
    "inputs": {
      "scan_mode": "full",
      "epyon_callback_url": "https://srtm.dialtone.cc/api/security-scan-webhook",
      "epyon_job_id": "scan-20260630-123456",
      "epyon_webhook_secret": "barbatos-shared-secret"
    }
  }'
```

**Target repository workflow** (needs these inputs defined and passed through):

```yaml
on:
  workflow_dispatch:
    inputs:
      scan_mode:
        type: string
        default: 'full'
      epyon_callback_url:
        type: string
        required: false
      epyon_job_id:
        type: string
        required: false
      epyon_webhook_secret:
        type: string
        required: false

jobs:
  security-scan:
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: ${{ inputs.scan_mode }}
      epyon_callback_url: ${{ inputs.epyon_callback_url }}
      epyon_job_id: ${{ inputs.epyon_job_id }}
      epyon_webhook_secret: ${{ inputs.epyon_webhook_secret }}
    secrets: inherit
```

**No other modifications needed** — the reusable workflow automatically propagates these inputs as environment variables to Epyon.

## Troubleshooting

### Webhooks not firing

Check that environment variables are set:

```bash
# In your workflow or terminal
echo "Callback URL: ${EPYON_CALLBACK_URL:-not set}"
echo "Job ID: ${EPYON_JOB_ID:-not set}"
echo "Secret: ${EPYON_WEBHOOK_SECRET:+configured}"
```

### Webhook endpoint not receiving requests

1. Verify the URL is accessible from GitHub Actions runners (public HTTPS)
2. Check firewall rules if self-hosted
3. Look for webhook warnings in scan logs: `⚠️ Webhook notification failed`

### Signature validation failing

1. Ensure the secret matches on both sides
2. Verify JSON serialization is consistent (no whitespace differences)
3. Use `hmac.compare_digest()` for constant-time comparison

### Scan takes too long

Webhooks add minimal overhead (~50ms per notification). If your webhook endpoint is slow:

1. Return `202 Accepted` immediately
2. Process the webhook payload asynchronously
3. Check webhook endpoint logs for slow DB queries or external API calls

## Disabling Webhooks

Simply don't set `EPYON_CALLBACK_URL` — Epyon will run normally without any webhook calls.

You can also disable specific notifications by modifying `send-webhook-notification.sh` or wrapping calls with skip conditions.

## API Reference

### `send-webhook-notification.sh`

**Usage:**
```bash
./send-webhook-notification.sh "event_type" "message" ["status"] ["tool_name"]
```

**Parameters:**
- `event_type` (required) - Event type (scan_start, tool_start, etc.)
- `message` (required) - Human-readable message
- `status` (optional) - Status indicator (in_progress, success, error, warning)
- `tool_name` (optional) - Normalized tool slug

**Environment Variables:**
- `EPYON_CALLBACK_URL` - Webhook endpoint (required for execution)
- `EPYON_JOB_ID` - Job identifier (optional, defaults to "unknown")
- `EPYON_WEBHOOK_SECRET` - Shared secret for HMAC (optional)
- `APP_NAME` - Application name (passed from scan context)
- `SCAN_ID` - Scan identifier (passed from scan context)

**Exit Codes:**
- `0` - Always (never fails, soft errors only)

## Best Practices

1. **Always use HTTPS** for webhook endpoints in production
2. **Validate HMAC signatures** to prevent spoofing
3. **Return 2xx quickly** - Process webhooks asynchronously
4. **Store webhook secret in GitHub Secrets** - Never commit to code
5. **Monitor webhook failure rates** - High failure rates indicate endpoint issues
6. **Use unique job IDs** - Helps correlate webhooks to specific scan runs
7. **Set reasonable timeouts** - Don't wait forever for slow endpoints

## See Also

- [Epyon Documentation](../README.md)
- [GitHub Actions Workflow Reference](../.github/workflows/epyon-scan.yml)
- [Barbatos Integration](https://github.com/MetroStar/barbatos)
