#!/bin/bash

# ███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
# ██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
# █████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
# ██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
# ███████╗██║        ██║   ╚██████╔╝██║ ╚████║
# ╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
#
# API Discovery Scanner
# Discovers API specifications, endpoints, and documentation
# 
# Usage:
#   ./run-api-discovery.sh [target_directory]
#
# Purpose:
#   Discovers APIs in applications to prepare for security scanning (Waypoint 6)
#   - Finds OpenAPI/Swagger specifications
#   - Extracts API routes from code
#   - Identifies API documentation endpoints
#   - Generates comprehensive API inventory

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${TARGET_DIR:-${1:-.}}"
SCAN_DIR="${SCAN_DIR:-}"
OUTPUT_FILE="api-discovery.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝

API Discovery Scanner - Waypoint 6 Foundation
EOF
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}✅${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1" >&2
}

print_error() {
    echo -e "${RED}❌${NC} $1" >&2
}

print_section() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}$1${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
}

# Show help
show_help() {
    cat << EOF
API Discovery Scanner - Discover APIs in applications

USAGE:
    ./run-api-discovery.sh [TARGET_DIR]

ARGUMENTS:
    TARGET_DIR    Directory to scan for APIs (default: current directory)

ENVIRONMENT VARIABLES:
    TARGET_DIR    Target directory to scan
    SCAN_DIR      Output directory for results (optional)

EXAMPLES:
    # Scan current directory
    ./run-api-discovery.sh

    # Scan specific application
    ./run-api-discovery.sh /path/to/application

    # With environment variables
    TARGET_DIR="/path/to/app" ./run-api-discovery.sh

DISCOVERY METHODS:
    1. OpenAPI/Swagger specification files
    2. API routes in Python code (Flask, FastAPI, Django)
    3. API routes in Node.js code (Express, Fastify, Koa)
    4. API routes in Java code (Spring Boot)
    5. Common API documentation endpoints

OUTPUT:
    - JSON report with discovered APIs
    - Specification files list
    - Extracted endpoint routes
    - Recommendations for security scanning

EOF
}

# Initialize discovery data structure
init_discovery_data() {
    cat > "${OUTPUT_PATH}" << 'EOF'
{
  "scan_date": "",
  "target_directory": "",
  "discovery_methods": {
    "openapi_specs": [],
    "code_routes": {
      "python": [],
      "nodejs": [],
      "java": [],
      "other": []
    },
    "documentation_endpoints": [],
    "graphql_schemas": []
  },
  "summary": {
    "total_specs_found": 0,
    "total_routes_found": 0,
    "total_endpoints_discovered": 0,
    "frameworks_detected": []
  },
  "recommendations": []
}
EOF
}

# Find OpenAPI/Swagger specification files
find_openapi_specs() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}🔍 Searching for OpenAPI/Swagger Specifications${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local specs_found=0
    local spec_files=()
    
    # Common OpenAPI/Swagger file patterns
    local patterns=(
        "openapi.json"
        "openapi.yaml"
        "openapi.yml"
        "swagger.json"
        "swagger.yaml"
        "swagger.yml"
        "api-spec.json"
        "api-spec.yaml"
    )
    
    for pattern in "${patterns[@]}"; do
        while IFS= read -r -d '' file; do
            specs_found=$((specs_found + 1))
            spec_files+=("$file")
            print_success "Found: $file"
            
            # Try to extract API info
            if [[ "$file" == *.json ]]; then
                if command -v jq &> /dev/null; then
                    local api_title=$(jq -r '.info.title // "N/A"' "$file" 2>/dev/null || echo "N/A")
                    local api_version=$(jq -r '.info.version // "N/A"' "$file" 2>/dev/null || echo "N/A")
                    echo "    Title: $api_title"
                    echo "    Version: $api_version"
                fi
            fi
        done < <(find "${TARGET_DIR}" -type f -name "$pattern" -print0 2>/dev/null)
    done
    
    if [ $specs_found -eq 0 ]; then
        print_warning "No OpenAPI/Swagger specifications found"
    else
        print_success "Found $specs_found specification file(s)"
    fi
    
    echo "$specs_found"
}

# Extract API routes from Python code
find_python_routes() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}🐍 Extracting API Routes from Python Code${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local temp_routes="${OUTPUT_DIR}/temp_python_routes.txt"
    > "$temp_routes"
    
    # Use Python script for robust multi-line decorator parsing
    local script_dir=$(dirname "${BASH_SOURCE[0]}")
    local extractor="${script_dir}/extract-python-apis.py"
    
    if [ ! -f "$extractor" ]; then
        print_error "Python API extractor script not found: $extractor" >&2
        return 0
    fi
    
    print_info "Scanning Python files for API endpoints..." >&2
    
    # Run Python extractor and save to temp file
    if python3 "$extractor" "${TARGET_DIR}" > "$temp_routes" 2>/dev/null; then
        local routes_found=$(wc -l < "$temp_routes" | tr -d ' ')
        
        if [ "$routes_found" -gt 0 ]; then
            print_success "Found $routes_found Python API endpoint(s)" >&2
            
            # Show breakdown by framework
            local fastapi_count=$(grep -c "^FastAPI|" "$temp_routes" 2>/dev/null | tr -d ' \n' || echo "0")
            local flask_count=$(grep -c "^Flask|" "$temp_routes" 2>/dev/null | tr -d ' \n' || echo "0")
            local django_count=$(grep -c "^Django|" "$temp_routes" 2>/dev/null | tr -d ' \n' || echo "0")
            
            if [ "$fastapi_count" -gt 0 ]; then
                print_info "  • FastAPI: $fastapi_count endpoint(s)" >&2
            fi
            if [ "$flask_count" -gt 0 ]; then
                print_info "  • Flask: $flask_count endpoint(s)" >&2
            fi
            if [ "$django_count" -gt 0 ]; then
                print_info "  • Django: $django_count endpoint(s)" >&2
            fi
            
            # Show sample endpoints
            echo "" >&2
            print_info "Sample endpoints:" >&2
            head -5 "$temp_routes" | while IFS='|' read -r framework method path file; do
                echo "    $method $path ($framework)" >&2
            done
        else
            print_warning "No Python API routes found" >&2
        fi
    else
        print_error "Failed to run Python API extractor" >&2
        return 0
    fi
    
    echo "$routes_found"
}

# Extract API routes from Node.js code
find_nodejs_routes() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}📦 Extracting API Routes from Node.js Code${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local routes_found=0
    local temp_nodejs_routes="${OUTPUT_DIR}/temp_nodejs_routes.txt"
    rm -f "$temp_nodejs_routes"
    
    # Express patterns
    print_info "Searching for Express routes..."
    local express_routes=$(grep -r "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\|patch\)" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$express_routes" -gt 0 ]; then
        print_success "Found $express_routes Express route(s)"
        routes_found=$((routes_found + express_routes))
        
        # Show sample routes
        echo "    Sample routes:"
        grep -r "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\|patch\)" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null | head -3 | sed 's/^/      /'
    fi
    
    # Fastify patterns
    print_info "Searching for Fastify routes..."
    local fastify_routes=$(grep -r "fastify\.\(get\|post\|put\|delete\|patch\)" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$fastify_routes" -gt 0 ]; then
        print_success "Found $fastify_routes Fastify route(s)"
        routes_found=$((routes_found + fastify_routes))
    fi
    
    # Koa patterns
    print_info "Searching for Koa routes..."
    local koa_routes=$(grep -r "router\.\(get\|post\|put\|delete\|patch\)" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$koa_routes" -gt 0 ]; then
        print_success "Found $koa_routes Koa route(s)"
        routes_found=$((routes_found + koa_routes))
    fi
    
    # Next.js API Routes (App Router - Next.js 13+)
    print_info "Searching for Next.js App Router API routes..."
    local nextjs_app_routes=$(find "${TARGET_DIR}" -type f \( -name "route.js" -o -name "route.ts" \) 2>/dev/null | wc -l | tr -d ' ')
    if [ "$nextjs_app_routes" -gt 0 ]; then
        print_success "Found $nextjs_app_routes Next.js App Router route file(s)"
        
        # Extract HTTP method exports and save to temp file
        local nextjs_methods=0
        while IFS= read -r route_file; do
            # Get the API path from the directory structure
            local api_path=$(echo "$route_file" | sed "s|${TARGET_DIR}||" | sed 's|/route\.[jt]s$||')
            
            # Generate a readable name from the path (e.g., /app/api/import-stig -> Import STIG)
            local endpoint_name=$(echo "$api_path" | sed 's|.*/||' | sed 's|-| |g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1')
            
            # Check for authentication patterns in the file
            local auth_type="None"
            if grep -q "requireAuth\|withAuth\|authenticate\|authMiddleware\|NextAuth\|getServerSession\|jwt\|bearer" "$route_file" 2>/dev/null; then
                if grep -q "NextAuth\|getServerSession" "$route_file" 2>/dev/null; then
                    auth_type="NextAuth"
                elif grep -q "jwt\|JWT" "$route_file" 2>/dev/null; then
                    auth_type="JWT"
                elif grep -q "bearer\|Bearer" "$route_file" 2>/dev/null; then
                    auth_type="Bearer"
                else
                    auth_type="Required"
                fi
            fi
            
            # Find all HTTP method exports in this route file
            while IFS= read -r method_line; do
                local method=$(echo "$method_line" | sed -n 's/.*export async function \([A-Z]*\).*/\1/p')
                if [ -n "$method" ]; then
                    # Save route details: framework|method|path|name|auth|file
                    echo "Next.js|$method|$api_path|$endpoint_name|$auth_type|$(basename $route_file)" >> "$temp_nodejs_routes"
                    nextjs_methods=$((nextjs_methods + 1))
                fi
            done < <(grep "export async function \(GET\|POST\|PUT\|DELETE\|PATCH\|HEAD\|OPTIONS\)" "$route_file" 2>/dev/null)
        done < <(find "${TARGET_DIR}" -type f \( -name "route.js" -o -name "route.ts" \) 2>/dev/null)
        
        if [ "$nextjs_methods" -gt 0 ]; then
            print_success "Found $nextjs_methods Next.js App Router HTTP method(s)"
            routes_found=$((routes_found + nextjs_methods))
            
            # Show sample routes
            echo "    Sample Next.js routes:" >&2
            find "${TARGET_DIR}" -type f \( -name "route.js" -o -name "route.ts" \) 2>/dev/null | head -3 | while read -r file; do
                echo "      $file" >&2
                grep "export async function \(GET\|POST\|PUT\|DELETE\|PATCH\|HEAD\|OPTIONS\)" "$file" 2>/dev/null | head -2 | sed 's/^/        /' >&2
            done
        fi
    fi
    
    # Next.js Pages Router API routes (pages/api/)
    print_info "Searching for Next.js Pages Router API routes..."
    local nextjs_pages_routes=0
    if [ -d "${TARGET_DIR}/pages/api" ]; then
        nextjs_pages_routes=$(find "${TARGET_DIR}/pages/api" -type f \( -name "*.js" -o -name "*.ts" \) 2>/dev/null | wc -l | tr -d ' ')
        if [ "$nextjs_pages_routes" -gt 0 ]; then
            print_success "Found $nextjs_pages_routes Next.js Pages Router API route(s)"
            routes_found=$((routes_found + nextjs_pages_routes))
            
            # Show sample routes
            echo "    Sample Pages API routes:" >&2
            find "${TARGET_DIR}/pages/api" -type f \( -name "*.js" -o -name "*.ts" \) 2>/dev/null | head -3 | sed 's/^/      /' >&2
        fi
    fi
    
    if [ $routes_found -eq 0 ]; then
        print_warning "No Node.js API routes found"
    else
        print_success "Total Node.js routes found: $routes_found"
    fi
    
    echo "$routes_found"
}

# Extract API routes from Java code
find_java_routes() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}☕ Extracting API Routes from Java Code${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local routes_found=0
    
    # Spring Boot REST annotations
    print_info "Searching for Spring Boot REST endpoints..."
    local spring_routes=$(grep -r "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping\|@RequestMapping" "${TARGET_DIR}" --include="*.java" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$spring_routes" -gt 0 ]; then
        print_success "Found $spring_routes Spring Boot endpoint(s)"
        routes_found=$((routes_found + spring_routes))
        
        # Show sample routes
        echo "    Sample endpoints:"
        grep -r "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@PatchMapping\|@RequestMapping" "${TARGET_DIR}" --include="*.java" 2>/dev/null | head -3 | sed 's/^/      /'
    fi
    
    # JAX-RS annotations
    print_info "Searching for JAX-RS endpoints..."
    local jaxrs_routes=$(grep -r "@Path\|@GET\|@POST\|@PUT\|@DELETE" "${TARGET_DIR}" --include="*.java" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$jaxrs_routes" -gt 0 ]; then
        print_success "Found $jaxrs_routes JAX-RS endpoint(s)"
        routes_found=$((routes_found + jaxrs_routes))
    fi
    
    if [ $routes_found -eq 0 ]; then
        print_warning "No Java API routes found"
    else
        print_success "Total Java routes found: $routes_found"
    fi
    
    echo "$routes_found"
}

# Look for GraphQL schemas
find_graphql_schemas() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}🔷 Searching for GraphQL Schemas${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local schemas_found=0
    
    # GraphQL schema files
    local patterns=(
        "schema.graphql"
        "schema.gql"
        "*.graphql"
        "*.gql"
    )
    
    for pattern in "${patterns[@]}"; do
        while IFS= read -r -d '' file; do
            schemas_found=$((schemas_found + 1))
            print_success "Found: $file"
        done < <(find "${TARGET_DIR}" -type f -name "$pattern" -print0 2>/dev/null)
    done
    
    # GraphQL in code
    local graphql_code=$(grep -r "type Query\|type Mutation\|type Subscription" "${TARGET_DIR}" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$graphql_code" -gt 0 ]; then
        print_info "Found GraphQL definitions in code: $graphql_code"
        schemas_found=$((schemas_found + graphql_code))
    fi
    
    if [ $schemas_found -eq 0 ]; then
        print_warning "No GraphQL schemas found"
    else
        print_success "Found $schemas_found GraphQL schema(s)"
    fi
    
    echo "$schemas_found"
}

# Identify common API documentation patterns
find_api_documentation() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}📖 Identifying API Documentation Patterns${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local doc_patterns_found=0
    
    # Common documentation file patterns
    print_info "Searching for API documentation files..."
    local doc_files=(
        "API.md"
        "api-docs.md"
        "REST.md"
        "endpoints.md"
    )
    
    for doc_file in "${doc_files[@]}"; do
        if [ -f "${TARGET_DIR}/${doc_file}" ]; then
            print_success "Found: ${doc_file}"
            doc_patterns_found=$((doc_patterns_found + 1))
        fi
    done
    
    # Postman collections
    print_info "Searching for Postman collections..."
    local postman_collections=$(find "${TARGET_DIR}" -type f -name "*.postman_collection.json" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$postman_collections" -gt 0 ]; then
        print_success "Found $postman_collections Postman collection(s)"
        doc_patterns_found=$((doc_patterns_found + postman_collections))
    fi
    
    # Common documentation endpoint patterns
    print_info "Common API documentation endpoints to check:" >&2
    local common_endpoints=(
        "/swagger-ui.html"
        "/swagger-ui/"
        "/api-docs"
        "/api/docs"
        "/docs"
        "/redoc"
        "/graphql"
        "/playground"
    )
    
    echo "    Suggested endpoints to test (if application is running):" >&2
    for endpoint in "${common_endpoints[@]}"; do
        echo "      - http://localhost:8080${endpoint}" >&2
    done
    
    if [ $doc_patterns_found -eq 0 ]; then
        print_warning "No API documentation files found"
    else
        print_success "Found $doc_patterns_found documentation pattern(s)"
    fi
    
    echo "$doc_patterns_found"
}

# Generate summary report
generate_summary() {
    local specs_count=$1
    local python_routes=$2
    local nodejs_routes=$3
    local java_routes=$4
    local graphql_schemas=$5
    local doc_patterns=$6
    
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}📊 API Discovery Summary${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    
    local total_routes=$((python_routes + nodejs_routes + java_routes))
    local total_discovered=$((specs_count + total_routes + graphql_schemas))
    
    echo ""
    echo -e "${CYAN}Target Directory:${NC} ${TARGET_DIR}"
    echo ""
    echo -e "${CYAN}Specifications:${NC}"
    echo "  OpenAPI/Swagger:     $specs_count"
    echo "  GraphQL Schemas:     $graphql_schemas"
    echo ""
    echo -e "${CYAN}Code-Based Routes:${NC}"
    echo "  Python (Flask/FastAPI/Django): $python_routes"
    echo "  Node.js (Express/Fastify/Koa): $nodejs_routes"
    echo "  Java (Spring Boot/JAX-RS):     $java_routes"
    echo "  Total Routes:                  $total_routes"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "  Patterns Found:      $doc_patterns"
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Total API Components Discovered: $total_discovered${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Recommendations
    if [ $total_discovered -gt 0 ]; then
        echo ""
        echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${MAGENTA}💡 Recommendations${NC}"
        echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if [ $specs_count -gt 0 ]; then
            echo "  ✓ OpenAPI specs found - Ready for Spectral validation"
            echo "    Command: docker run --rm -v \"\${TARGET_DIR}:/workspace\" stoplight/spectral lint /workspace/openapi.yaml"
        fi
        
        if [ $total_routes -gt 0 ]; then
            echo "  ✓ API routes detected - Consider generating OpenAPI spec from code"
        fi
        
        if [ $graphql_schemas -gt 0 ]; then
            echo "  ✓ GraphQL schemas found - Ready for GraphQL security scanning"
        fi
        
        echo ""
        echo "  📚 Next Steps:"
        echo "    1. Validate OpenAPI specifications with Spectral"
        echo "    2. Run OWASP ZAP API security scan"
        echo "    3. Test authentication and authorization"
        echo "    4. Check for rate limiting"
        echo "    5. Verify API documentation completeness"
    else
        print_warning "No APIs discovered in target directory"
        echo ""
        echo "  Possible reasons:"
        echo "    - Application may not expose REST/GraphQL APIs"
        echo "    - API definitions may use non-standard patterns"
        echo "    - Target directory may not contain API code"
    fi
    
    echo ""
}

# Main execution
main() {
    # Parse arguments
    if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    print_banner
    
    # Validate target directory
    if [ ! -d "${TARGET_DIR}" ]; then
        print_error "Target directory not found: ${TARGET_DIR}"
        exit 1
    fi
    
    # Set output path
    if [ -n "${SCAN_DIR}" ]; then
        OUTPUT_PATH="${SCAN_DIR}/${OUTPUT_FILE}"
        OUTPUT_DIR="${SCAN_DIR}"
        mkdir -p "${SCAN_DIR}"
    else
        OUTPUT_PATH="${TARGET_DIR}/${OUTPUT_FILE}"
        OUTPUT_DIR="${TARGET_DIR}"
    fi
    
    print_info "Target Directory: ${TARGET_DIR}"
    print_info "Output File: ${OUTPUT_PATH}"
    echo ""
    
    # Run discovery methods FIRST to collect data
    specs_count=$(find_openapi_specs) || specs_count=0
    python_routes=$(find_python_routes) || python_routes=0
    nodejs_routes=$(find_nodejs_routes) || nodejs_routes=0
    java_routes=$(find_java_routes) || java_routes=0
    graphql_schemas=$(find_graphql_schemas) || graphql_schemas=0
    doc_patterns=$(find_api_documentation) || doc_patterns=0
    
    # Generate summary AFTER collecting all data
    generate_summary "$specs_count" "$python_routes" "$nodejs_routes" "$java_routes" "$graphql_schemas" "$doc_patterns"
    
    # Update JSON with actual counts
    local total_routes=$((python_routes + nodejs_routes + java_routes))
    local total_discovered=$((specs_count + total_routes + graphql_schemas))
    local scan_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Detect frameworks based on what we found
    local frameworks_detected="[]"
    local framework_list=()
    
    # Check for Next.js (App Router or Pages Router)
    if [ -d "${TARGET_DIR}/app/api" ] || [ -d "${TARGET_DIR}/pages/api" ]; then
        framework_list+=("Next.js")
    fi
    
    # Check for Express
    if grep -rq "require.*express\|import.*express\|from.*express" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null; then
        framework_list+=("Express")
    fi
    
    # Check for Fastify
    if grep -rq "require.*fastify\|import.*fastify\|from.*fastify" "${TARGET_DIR}" --include="*.js" --include="*.ts" 2>/dev/null; then
        framework_list+=("Fastify")
    fi
    
    # Check for FastAPI
    if grep -rq "from fastapi import\|import fastapi" "${TARGET_DIR}" --include="*.py" 2>/dev/null; then
        framework_list+=("FastAPI")
    fi
    
    # Check for Flask
    if grep -rq "from flask import\|import flask" "${TARGET_DIR}" --include="*.py" 2>/dev/null; then
        framework_list+=("Flask")
    fi
    
    # Check for Django
    if [ -f "${TARGET_DIR}/manage.py" ] || grep -rq "from django" "${TARGET_DIR}" --include="*.py" 2>/dev/null; then
        framework_list+=("Django")
    fi
    
    # Check for Spring Boot
    if grep -rq "@SpringBootApplication\|@RestController" "${TARGET_DIR}" --include="*.java" 2>/dev/null; then
        framework_list+=("Spring Boot")
    fi
    
    # Build JSON array for frameworks
    if [ ${#framework_list[@]} -gt 0 ]; then
        frameworks_detected="[\"$(IFS='","'; echo "${framework_list[*]}")\"]"
    fi
    
    # Parse discovered routes from temp file and build JSON
    local temp_routes="${OUTPUT_DIR}/temp_python_routes.txt"
    local temp_nodejs_routes="${OUTPUT_DIR}/temp_nodejs_routes.txt"
    
    print_info "Building JSON output from discovered routes..." >&2
    print_info "Python routes file: $temp_routes" >&2
    print_info "Node.js routes file: $temp_nodejs_routes" >&2
    
    if [ -f "$temp_routes" ]; then
        local python_lines=$(wc -l < "$temp_routes" | tr -d ' ')
        print_info "Python routes file has $python_lines lines" >&2
    else
        print_warning "Python routes temp file not found" >&2
    fi
    
    # Start building JSON
    cat > "${OUTPUT_PATH}" << 'EOF_HEADER'
{
  "scan_date": "TIMESTAMP_PLACEHOLDER",
  "target_directory": "TARGET_PLACEHOLDER",
  "discovery_methods": {
    "openapi_specs": [],
    "code_routes": {
      "python": [
EOF_HEADER
    
    # Add Python routes from temp file
    if [ -f "$temp_routes" ] && [ -s "$temp_routes" ]; then
        print_info "Processing $(wc -l < "$temp_routes" | tr -d ' ') Python routes..." >&2
        awk -F'|' 'BEGIN{first=1} {
            # Escape backslashes and quotes in all fields
            for(i=1; i<=NF; i++) {
                gsub(/\\/, "\\\\", $i);
                gsub(/"/, "\\\"", $i);
            }
            if (!first) printf ",\n";
            printf "        {\"framework\": \"%s\", \"method\": \"%s\", \"path\": \"%s\", \"function\": \"%s\", \"name\": \"%s\", \"auth\": \"%s\", \"tags\": \"%s\", \"file\": \"%s\"}", 
                $1, $2, $3, $4, $5, $6, $7, $8;
            first=0;
        }' "$temp_routes" >> "${OUTPUT_PATH}" 2>&1
        local awk_status=$?
        if [ $awk_status -ne 0 ]; then
            print_error "Failed to process Python routes (awk exit code: $awk_status)" >&2
        else
            print_success "Python routes added to JSON" >&2
        fi
        echo "" >> "${OUTPUT_PATH}"
    else
        print_info "No Python routes to add" >&2
    fi
    
    # Add closing bracket for Python, open Node.js array
    cat >> "${OUTPUT_PATH}" << 'EOF_NODEJS'
      ],
      "nodejs": [
EOF_NODEJS
    
    # Add Node.js routes from temp file
    if [ -f "$temp_nodejs_routes" ] && [ -s "$temp_nodejs_routes" ]; then
        print_info "Processing $(wc -l < "$temp_nodejs_routes" | tr -d ' ') Node.js routes..." >&2
        awk -F'|' 'BEGIN{first=1} {
            # Escape backslashes and quotes in all fields
            for(i=1; i<=NF; i++) {
                gsub(/\\/, "\\\\", $i);
                gsub(/"/, "\\\"", $i);
            }
            if (!first) printf ",\n";
            printf "        {\"framework\": \"%s\", \"method\": \"%s\", \"path\": \"%s\", \"name\": \"%s\", \"auth\": \"%s\", \"file\": \"%s\"}", 
                $1, $2, $3, $4, $5, $6;
            first=0;
        }' "$temp_nodejs_routes" >> "${OUTPUT_PATH}" 2>&1
        local awk_status=$?
        if [ $awk_status -ne 0 ]; then
            print_error "Failed to process Node.js routes (awk exit code: $awk_status)" >&2
        else
            print_success "Node.js routes added to JSON" >&2
        fi
        echo "" >> "${OUTPUT_PATH}"
    else
        print_info "No Node.js routes to add" >&2
    fi
    
    # Complete the JSON structure
    cat >> "${OUTPUT_PATH}" << EOF
      ],
      "java": [],
      "other": []
    },
    "documentation_endpoints": [],
    "graphql_schemas": []
  },
  "summary": {
    "total_specs_found": ${specs_count},
    "total_routes_found": ${total_routes},
    "total_endpoints_discovered": ${total_discovered},
    "python_routes": ${python_routes},
    "nodejs_routes": ${nodejs_routes},
    "java_routes": ${java_routes},
    "graphql_schemas": ${graphql_schemas},
    "documentation_patterns": ${doc_patterns},
    "frameworks_detected": ${frameworks_detected}
  },
  "recommendations": []
}
EOF
    
    # Replace placeholders
    sed -i.bak "s|TIMESTAMP_PLACEHOLDER|${scan_timestamp}|g" "${OUTPUT_PATH}"
    sed -i.bak "s|TARGET_PLACEHOLDER|${TARGET_DIR}|g" "${OUTPUT_PATH}"
    rm -f "${OUTPUT_PATH}.bak"

    # Cleanup temp files AFTER JSON is generated
    rm -f "$temp_routes"
    rm -f "$temp_nodejs_routes"
    
    # Save results
    print_info "Results saved to: ${OUTPUT_PATH}"
    
    print_success "API discovery complete!"
    echo ""
}

# Execute main function
main "$@"
