#!/usr/bin/env python3
"""
Extract API endpoint information from Python source files.
Handles multi-line decorators and complex patterns.
"""

import re
import sys
import os
from pathlib import Path

def extract_fastapi_endpoints(file_path):
    """Extract FastAPI endpoints from a Python file."""
    endpoints = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match FastAPI decorators (handles multi-line)
        # Matches: @router.get("/path", ...) or @app.post("/path", ...)
        pattern = r'@(app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        
        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            decorator_type = match.group(1)  # app or router
            method = match.group(2).upper()  # GET, POST, etc.
            path = match.group(3)            # /api/path
            
            endpoints.append({
                'framework': 'FastAPI',
                'method': method,
                'path': path,
                'file': str(file_path)
            })
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return endpoints

def extract_flask_routes(file_path):
    """Extract Flask routes from a Python file."""
    endpoints = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match Flask decorators
        # Matches: @app.route("/path", methods=["GET", "POST"])
        route_pattern = r'@(app|api|blueprint)\.route\s*\(\s*["\']([^"\']+)["\']'
        
        for match in re.finditer(route_pattern, content, re.MULTILINE):
            path = match.group(2)
            
            # Try to find methods parameter on same or next line
            # Look for methods=['GET', 'POST'] pattern
            methods_match = re.search(
                r'methods\s*=\s*\[([^\]]+)\]',
                content[match.start():match.start()+200]
            )
            
            if methods_match:
                # Extract methods from list
                methods_str = methods_match.group(1)
                methods = re.findall(r'["\']([A-Z]+)["\']', methods_str)
            else:
                # Default to GET if no methods specified
                methods = ['GET']
            
            for method in methods:
                endpoints.append({
                    'framework': 'Flask',
                    'method': method,
                    'path': path,
                    'file': str(file_path)
                })
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return endpoints

def extract_django_patterns(file_path):
    """Extract Django URL patterns from urls.py files."""
    endpoints = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match Django path() or re_path()
        pattern = r'(?:path|re_path)\s*\(\s*["\']([^"\']+)["\']'
        
        for match in re.finditer(pattern, content, re.MULTILINE):
            path = match.group(1)
            
            endpoints.append({
                'framework': 'Django',
                'method': 'ANY',  # Django doesn't specify method in URL conf
                'path': f"/{path}",
                'file': str(file_path)
            })
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return endpoints

def scan_directory(target_dir):
    """Scan directory for Python API files."""
    all_endpoints = []
    
    target_path = Path(target_dir)
    
    # Find all Python files
    for py_file in target_path.rglob('*.py'):
        # Skip virtual environments and build directories
        if any(part in str(py_file) for part in ['venv', '.venv', 'env', 'site-packages', '__pycache__', '.tox', 'build', 'dist']):
            continue
        
        # Extract FastAPI endpoints
        all_endpoints.extend(extract_fastapi_endpoints(py_file))
        
        # Extract Flask routes
        all_endpoints.extend(extract_flask_routes(py_file))
        
        # Extract Django patterns (only from urls.py files)
        if py_file.name == 'urls.py':
            all_endpoints.extend(extract_django_patterns(py_file))
    
    return all_endpoints

def main():
    if len(sys.argv) < 2:
        print("Usage: extract-python-apis.py <target_directory>", file=sys.stderr)
        sys.exit(1)
    
    target_dir = sys.argv[1]
    
    if not os.path.isdir(target_dir):
        print(f"Error: {target_dir} is not a directory", file=sys.stderr)
        sys.exit(1)
    
    endpoints = scan_directory(target_dir)
    
    # Output in pipe-delimited format for shell consumption
    for ep in endpoints:
        print(f"{ep['framework']}|{ep['method']}|{ep['path']}|{ep['file']}")

if __name__ == '__main__':
    main()
