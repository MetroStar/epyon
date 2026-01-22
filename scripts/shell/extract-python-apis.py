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
            lines = f.readlines()
        
        # Process line by line looking for decorators
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Check if line has FastAPI/router decorator
            decorator_match = re.match(r'@(app|router)\.(get|post|put|delete|patch)', line)
            if decorator_match:
                decorator_type = decorator_match.group(1)
                method = decorator_match.group(2).upper()
                
                # Collect full decorator (may span multiple lines)
                decorator_text = line
                j = i + 1
                while j < len(lines) and 'def ' not in lines[j]:
                    decorator_text += ' ' + lines[j].strip()
                    j += 1
                
                # Extract path from decorator
                path_match = re.search(r'["\']([^"\']*)["\']', decorator_text)
                if path_match:
                    path = path_match.group(1)
                    
                    # Find function name (handle both 'def' and 'async def')
                    function_name = ''
                    if j < len(lines):
                        func_match = re.match(r'\s*(?:async\s+)?def\s+(\w+)', lines[j])
                        if func_match:
                            function_name = func_match.group(1)
                    
                    # Extract authentication requirements
                    auth = extract_auth_info(decorator_text, '\n'.join(lines), i)
                    
                    # Extract endpoint name/description
                    name = extract_endpoint_name(decorator_text, function_name)
                    
                    # Extract tags for categorization
                    tags = extract_tags(decorator_text)
                    
                    endpoints.append({
                        'framework': 'FastAPI',
                        'method': method,
                        'path': path,
                        'function': function_name,
                        'name': name,
                        'auth': auth,
                        'tags': tags,
                        'file': str(file_path)
                    })
                
                i = j
            else:
                i += 1
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return endpoints

def extract_auth_info(decorator_params, content, position):
    """Extract authentication information from decorator parameters."""
    auth_types = []
    
    # Look for common FastAPI auth patterns
    if 'Depends(' in decorator_params:
        # Extract dependency functions
        depends_pattern = r'Depends\(([^)]+)\)'
        for match in re.finditer(depends_pattern, decorator_params):
            dep_func = match.group(1).strip()
            # Common auth function names
            if any(auth_term in dep_func.lower() for auth_term in ['auth', 'user', 'token', 'api_key', 'bearer', 'jwt']):
                auth_types.append(dep_func)
    
    if 'Security(' in decorator_params:
        # OAuth2/Security scheme
        security_pattern = r'Security\(([^,)]+)'
        for match in re.finditer(security_pattern, decorator_params):
            auth_types.append(f"Security: {match.group(1).strip()}")
    
    # Check for explicit dependencies parameter
    if 'dependencies=' in decorator_params:
        auth_types.append("Custom Dependencies")
    
    return ', '.join(auth_types) if auth_types else 'None'

def extract_endpoint_name(decorator_params, function_name):
    """Extract endpoint name from decorator parameters or function name."""
    # Look for summary parameter
    summary_match = re.search(r'summary\s*=\s*["\']([^"\']+)["\']', decorator_params)
    if summary_match:
        return summary_match.group(1)
    
    # Look for name parameter
    name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', decorator_params)
    if name_match:
        return name_match.group(1)
    
    # Convert function name to readable format
    # e.g., get_user_profile -> Get User Profile
    readable_name = function_name.replace('_', ' ').title()
    return readable_name

def extract_tags(decorator_params):
    """Extract tags from decorator parameters."""
    tags_match = re.search(r'tags\s*=\s*\[([^\]]+)\]', decorator_params)
    if tags_match:
        # Extract tag strings
        tags_content = tags_match.group(1)
        tags = re.findall(r'["\']([^"\']+)["\']', tags_content)
        return ', '.join(tags)
    return ''

def extract_flask_routes(file_path):
    """Extract Flask routes from a Python file."""
    endpoints = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match Flask decorators with function
        # Matches: @app.route("/path", methods=["GET"]) followed by def function_name
        route_pattern = r'@(app|api|blueprint)\.route\s*\([^\)]*?["\']([^"\']+)["\'][^\)]*?\)([^\n]*\n(?:[^\n]*\n)*?)def\s+(\w+)'
        
        for match in re.finditer(route_pattern, content, re.MULTILINE | re.DOTALL):
            decorator_type = match.group(1)
            path = match.group(2)
            decorator_params = match.group(3)
            function_name = match.group(4)
            
            # Try to find methods parameter
            methods_match = re.search(r'methods\s*=\s*\[([^\]]+)\]', decorator_params)
            
            if methods_match:
                # Extract methods from list
                methods_str = methods_match.group(1)
                methods = re.findall(r'["\']([A-Z]+)["\']', methods_str)
            else:
                # Default to GET if no methods specified
                methods = ['GET']
            
            # Extract auth info (Flask typically uses decorators)
            auth = extract_flask_auth(content, match.start())
            
            # Convert function name to readable
            name = function_name.replace('_', ' ').title()
            
            for method in methods:
                endpoints.append({
                    'framework': 'Flask',
                    'method': method,
                    'path': path,
                    'function': function_name,
                    'name': name,
                    'auth': auth,
                    'tags': '',
                    'file': str(file_path)
                })
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}", file=sys.stderr)
    
    return endpoints

def extract_flask_auth(content, position):
    """Extract Flask authentication decorators."""
    # Look backwards from position for auth decorators
    lines_before = content[max(0, position-500):position].split('\n')
    auth_decorators = []
    
    for line in reversed(lines_before[-5:]):  # Check last 5 lines
        if '@login_required' in line:
            auth_decorators.append('Login Required')
        elif '@jwt_required' in line:
            auth_decorators.append('JWT Required')
        elif '@auth' in line.lower() and '@' in line:
            auth_decorators.append('Auth Required')
        elif 'def ' in line:
            break  # Reached function definition, stop looking
    
    return ', '.join(auth_decorators) if auth_decorators else 'None'

def extract_django_patterns(file_path):
    """Extract Django URL patterns from urls.py files."""
    endpoints = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to match Django path() or re_path() with view reference
        pattern = r'(?:path|re_path)\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^,\)]+)'
        
        for match in re.finditer(pattern, content, re.MULTILINE):
            path = match.group(1)
            view_ref = match.group(2).strip()
            
            # Extract view name
            view_name = view_ref.split('.')[-1] if '.' in view_ref else view_ref
            view_name = view_name.replace('as_view()', '').strip()
            
            # Extract name parameter if present
            name_match = re.search(
                r'name\s*=\s*["\']([^"\']+)["\']',
                content[match.start():match.start()+200]
            )
            
            display_name = name_match.group(1).replace('_', ' ').title() if name_match else view_name.replace('_', ' ').title()
            
            endpoints.append({
                'framework': 'Django',
                'method': 'ANY',  # Django doesn't specify method in URL conf
                'path': f"/{path}",
                'function': view_name,
                'name': display_name,
                'auth': 'View-dependent',  # Django auth is typically in view
                'tags': '',
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
    # Format: framework|method|path|function|name|auth|tags|file
    for ep in endpoints:
        print(f"{ep['framework']}|{ep['method']}|{ep['path']}|{ep.get('function', '')}|{ep.get('name', '')}|{ep.get('auth', 'None')}|{ep.get('tags', '')}|{ep['file']}")

if __name__ == '__main__':
    main()
