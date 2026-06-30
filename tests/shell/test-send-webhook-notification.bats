#!/usr/bin/env bats

# ══════════════════════════════════════════════════════════════════════════════
# send-webhook-notification.sh Tests
# ══════════════════════════════════════════════════════════════════════════════
# Tests for the webhook notification helper script
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/send-webhook-notification.sh"

# Setup
setup() {
    # Clean up env vars for isolation
    unset EPYON_CALLBACK_URL
    unset EPYON_JOB_ID
    unset EPYON_WEBHOOK_SECRET
    unset APP_NAME
    unset SCAN_ID
}

# Teardown
teardown() {
    unset EPYON_CALLBACK_URL
    unset EPYON_JOB_ID
    unset EPYON_WEBHOOK_SECRET
    unset APP_NAME
    unset SCAN_ID
}

# ══════════════════════════════════════════════════════════════════════════════
# Silent Skip Tests (No Webhook Configured)
# ══════════════════════════════════════════════════════════════════════════════

@test "send-webhook-notification.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "send-webhook-notification: silently exits when EPYON_CALLBACK_URL not set" {
    run bash "$SCRIPT_PATH" "test_event" "Test message"
    
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "send-webhook-notification: accepts all required arguments" {
    run bash "$SCRIPT_PATH" "tool_start" "Starting Trivy" "in_progress" "trivy"
    
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: works with minimal arguments" {
    run bash "$SCRIPT_PATH" "scan_complete" "Scan finished"
    
    [ "$status" -eq 0 ]
}

# ══════════════════════════════════════════════════════════════════════════════
# URL Validation Tests
# ══════════════════════════════════════════════════════════════════════════════

@test "send-webhook-notification: rejects invalid URL format (soft fail)" {
    export EPYON_CALLBACK_URL="not-a-url"
    
    run bash "$SCRIPT_PATH" "test_event" "Test message"
    
    [ "$status" -eq 0 ]  # Soft fail
    [[ "$output" =~ "Invalid webhook URL format" ]]
}

@test "send-webhook-notification: accepts http URLs" {
    export EPYON_CALLBACK_URL="http://localhost:8000/webhook"
    
    # This will fail to connect but should not reject the URL format
    run bash "$SCRIPT_PATH" "test_event" "Test message"
    
    # Expect failure but graceful (retries then soft-fails)
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: accepts https URLs" {
    export EPYON_CALLBACK_URL="https://example.com/webhook"
    
    # This will fail to connect but should not reject the URL format
    run bash "$SCRIPT_PATH" "test_event" "Test message"
    
    # Expect failure but graceful (retries then soft-fails)
    [ "$status" -eq 0 ]
}

# ══════════════════════════════════════════════════════════════════════════════
# Event Type Coverage
# ══════════════════════════════════════════════════════════════════════════════

@test "send-webhook-notification: supports scan_start event" {
    run bash "$SCRIPT_PATH" "scan_start" "Scan started" "in_progress"
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: supports tool_start event" {
    run bash "$SCRIPT_PATH" "tool_start" "Trivy starting" "in_progress" "trivy"
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: supports tool_complete event" {
    run bash "$SCRIPT_PATH" "tool_complete" "Trivy finished" "success" "trivy"
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: supports tool_error event" {
    run bash "$SCRIPT_PATH" "tool_error" "Trivy failed" "error" "trivy"
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: supports scan_complete event" {
    run bash "$SCRIPT_PATH" "scan_complete" "Scan completed" "success"
    [ "$status" -eq 0 ]
}

@test "send-webhook-notification: exits 0 on unreachable URL (soft fail)" {
    # Unreachable URL (TEST-NET-1 from RFC 5737)
    export EPYON_CALLBACK_URL="http://192.0.2.1:9999/webhook"
    run bash "$SCRIPT_PATH" "test" "message"
    [ "$status" -eq 0 ]
}
