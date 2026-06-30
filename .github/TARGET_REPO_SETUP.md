# Target Repository Workflow Setup for Barbatos Webhooks

This guide explains how to configure your target repository's GitHub Actions workflow to receive webhook notifications from Epyon and forward them to Barbatos.

## Quick Start

Copy [security-scan-template.yml](security-scan-template.yml) to your target repository:

```bash
# In your target repository
mkdir -p .github/workflows
curl -o .github/workflows/security-scan.yml \
  https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/security-scan-template.yml
```

## Required Workflow Inputs

Your workflow **must** accept these inputs to receive webhooks from Barbatos:

```yaml
on:
  workflow_dispatch:
    inputs:
      epyon_callback_url:
        description: 'Webhook URL for progress notifications'
        required: false
        type: string
      epyon_job_id:
        description: 'Job identifier for webhook correlation'
        required: false
        type: string
      epyon_webhook_secret:
        description: 'Shared secret for webhook HMAC validation'
        required: false
        type: string
```

## Forward Inputs to Reusable Workflow

Pass the webhook inputs through to the Epyon reusable workflow:

```yaml
jobs:
  security-scan:
    uses: MetroStar/epyon/.github/workflows/epyon-scan.yml@main
    with:
      scan_mode: ${{ inputs.scan_mode || 'full' }}
      epyon_callback_url: ${{ inputs.epyon_callback_url || '' }}
      epyon_job_id: ${{ inputs.epyon_job_id || '' }}
      epyon_webhook_secret: ${{ inputs.epyon_webhook_secret || '' }}
    secrets: inherit
```

## Testing Webhook Integration

When Barbatos triggers your workflow, it will dispatch with these inputs:

```bash
curl -X POST \
  "https://api.github.com/repos/YOUR_ORG/YOUR_REPO/actions/workflows/security-scan.yml/dispatches" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ref": "main",
    "inputs": {
      "scan_mode": "full",
      "epyon_callback_url": "https://srtm.dialtone.cc/api/security-scan-webhook",
      "epyon_job_id": "scan-20260630-123456",
      "epyon_webhook_secret": "your-shared-secret"
    }
  }'
```

### Verify in GitHub Actions Logs

After triggering a scan, check the GitHub Actions logs for:

```
🔔 Webhook notifications enabled: https://srtm.dialtone.cc/api/security-scan-webhook
```

If you don't see this message, the webhook inputs are not being forwarded correctly.

### Verify in Barbatos Logs

Check Barbatos server logs for incoming webhooks:

```bash
# Docker
docker logs -f barbatos-app --tail=100 | grep security-scan-webhook

# PM2
pm2 logs barbatos | grep security-scan-webhook

# Systemd
journalctl -u barbatos -f | grep security-scan-webhook
```

Look for entries like:
```
[security-scan-webhook] POST /api/security-scan-webhook
[security-scan-webhook] Job ID: scan-20260630-123456
[security-scan-webhook] Event: tool_start
```

## Common Issues

### Issue: Webhooks not arriving at Barbatos

**Check 1: Workflow accepts inputs**

```bash
# In your target repository
grep -A 10 "epyon_callback_url:" .github/workflows/security-scan.yml
```

Should show:
```yaml
epyon_callback_url:
  description: 'Webhook URL for progress notifications'
  required: false
  type: string
```

**Check 2: Workflow forwards inputs**

```bash
grep -A 5 "uses: MetroStar/epyon" .github/workflows/security-scan.yml
```

Should show:
```yaml
with:
  epyon_callback_url: ${{ inputs.epyon_callback_url || '' }}
  epyon_job_id: ${{ inputs.epyon_job_id || '' }}
  epyon_webhook_secret: ${{ inputs.epyon_webhook_secret || '' }}
```

**Check 3: GitHub Actions logs show webhook config**

In the GitHub Actions run logs, search for "Webhook notifications enabled". If not found, the inputs are not being passed correctly.

### Issue: HTTP 401 errors

Barbatos webhook endpoint requires the correct job ID. Check:
1. Job ID matches between Barbatos and GitHub Actions
2. Webhook secret matches (if configured)
3. Request headers include `X-Epyon-Job-Id`

### Issue: Webhooks worked before, stopped working

**Most common causes:**
1. Workflow file was updated and webhook inputs removed
2. Target repository switched from custom workflow to different template
3. Reusable workflow reference changed (e.g., `@main` → `@v1.0.0` and old version doesn't support webhooks)

**Resolution:**
Re-copy the template and commit:
```bash
curl -o .github/workflows/security-scan.yml \
  https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/security-scan-template.yml
git add .github/workflows/security-scan.yml
git commit -m "fix: restore webhook support in security scan workflow"
git push
```

## Manual Testing

Test webhook delivery manually from GitHub Actions:

```yaml
# Add to your workflow for debugging
- name: Test Webhook Delivery
  env:
    EPYON_CALLBACK_URL: ${{ inputs.epyon_callback_url }}
    EPYON_JOB_ID: ${{ inputs.epyon_job_id }}
    EPYON_WEBHOOK_SECRET: ${{ inputs.epyon_webhook_secret }}
  run: |
    if [[ -n "$EPYON_CALLBACK_URL" ]]; then
      echo "Testing webhook delivery to: $EPYON_CALLBACK_URL"
      curl -X POST "$EPYON_CALLBACK_URL" \
        -H "Content-Type: application/json" \
        -H "X-Epyon-Job-Id: $EPYON_JOB_ID" \
        -d '{"event_type":"test","message":"Webhook test from GitHub Actions","status":"info"}'
      echo "Test webhook sent"
    else
      echo "No webhook URL configured"
    fi
```

## See Also

- [Webhook Integration Guide](../../documentation/WEBHOOK_INTEGRATION_GUIDE.md)
- [Reusable Workflow Reference](./epyon-scan.yml)
- [Barbatos Documentation](https://github.com/MetroStar/barbatos)
