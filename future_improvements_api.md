# API Security Scanning - Future Improvements

**Status**: Planning Phase (Waypoint 6)  
**Date**: January 22, 2026  
**Goal**: Comprehensive API security analysis with Swagger/OpenAPI validation, endpoint testing, and REST/GraphQL security scanning

---

## 🔍 API Information Discovery Methods

### 1. **Static Analysis - OpenAPI/Swagger Specification Files**

Most modern APIs have specification files you can discover:

```bash
# Common OpenAPI/Swagger file locations
find /path/to/app -name "openapi.json" -o -name "openapi.yaml" -o -name "swagger.json" -o -name "swagger.yaml"

# Common API documentation endpoints
curl http://localhost:8080/swagger.json
curl http://localhost:8080/api-docs
curl http://localhost:8080/openapi.json
curl http://localhost:3000/api/v1/swagger
```

**Tools for this:**
- **Spectral** - OpenAPI/Swagger linter and validator
- **openapi-validator** - Schema validation
- **swagger-parser** - Parse and validate specs

### 2. **Code-Based API Discovery**

Parse application code to extract API endpoints:

**Python (Flask/FastAPI):**
```python
# Flask routes
@app.route('/api/users', methods=['GET', 'POST'])
@app.route('/api/users/<int:id>', methods=['GET', 'PUT', 'DELETE'])

# FastAPI endpoints
@app.get("/api/users")
@app.post("/api/users")
```

**Node.js (Express):**
```javascript
app.get('/api/users', ...)
app.post('/api/users', ...)
app.put('/api/users/:id', ...)
```

**Discovery script patterns:**
```bash
# Find Flask routes
grep -r "@app.route\|@api.route\|@blueprint.route" /path/to/app --include="*.py"

# Find Express routes
grep -r "app\.\(get\|post\|put\|delete\|patch\)" /path/to/app --include="*.js"

# Find FastAPI endpoints
grep -r "@app\.\(get\|post\|put\|delete\|patch\)" /path/to/app --include="*.py"
```

### 3. **Runtime/Dynamic Discovery**

Intercept and analyze live API traffic:

**Using Proxy Tools:**
```bash
# OWASP ZAP (Web Application Scanner)
docker run -u zap -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon \
  -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true

# Burp Suite (commercial)
# mitmproxy (open source)
mitmdump -p 8080 --mode reverse:http://localhost:3000
```

**Tools for runtime discovery:**
- **OWASP ZAP** - Spider/crawler for API endpoints
- **Burp Suite** - HTTP proxy and scanner
- **mitmproxy** - Python-based HTTP/HTTPS proxy
- **Fiddler** - Web debugging proxy

### 4. **GraphQL Introspection**

For GraphQL APIs:

```bash
# GraphQL introspection query
curl -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# Using graphql-introspection tool
npx get-graphql-schema http://localhost:4000/graphql > schema.graphql
```

**Tools:**
- **GraphQL Voyager** - Visualize GraphQL schema
- **graphql-introspection** - Extract schema
- **InQL** - Burp Suite extension for GraphQL

### 5. **Container/Image Analysis**

If scanning containerized apps:

```bash
# Extract and analyze environment variables, configs
docker inspect <container_id> | jq '.[0].Config.Env'

# Find API documentation in container
docker run --rm <image> find / -name "swagger.json" -o -name "openapi.yaml"

# Check exposed ports (common API ports)
docker inspect <container_id> | jq '.[0].Config.ExposedPorts'
```

### 6. **Common API Discovery Patterns**

**Check standard locations:**
```bash
# Swagger UI
curl http://localhost:8080/swagger-ui.html
curl http://localhost:8080/swagger-ui/

# API documentation endpoints
curl http://localhost:8080/docs
curl http://localhost:8080/api/docs
curl http://localhost:8080/redoc

# Health/status endpoints (may reveal API info)
curl http://localhost:8080/health
curl http://localhost:8080/actuator
curl http://localhost:8080/metrics
```

---

## 🛠️ Recommended Tools for Epyon Integration

### Tier 1 - Essential (Immediate Implementation)
1. **Spectral** - OpenAPI/Swagger linting and security rules
   - Docker: `stoplight/spectral`
   - Purpose: Validate OpenAPI specs against security rules
   - Output: JSON report of spec violations

2. **OWASP ZAP** - Comprehensive API security testing
   - Docker: `owasp/zap2docker-stable`
   - Purpose: Active and passive API security scanning
   - Output: XML/JSON/HTML reports

3. **Postman/Newman** - API testing and collection execution
   - Docker: `postman/newman`
   - Purpose: Execute API test collections
   - Output: JSON/HTML test results

### Tier 2 - Advanced (Future Enhancement)
4. **APISec** - Automated API security testing
   - Purpose: Security test case generation
   - Integration: REST API scanning

5. **42Crunch** - OpenAPI security audit
   - Purpose: Deep security analysis of OpenAPI specs
   - Integration: Static analysis of API definitions

6. **Astra** - API penetration testing
   - Purpose: Automated penetration testing
   - Integration: Active security testing

### Tier 3 - Specialized (Advanced Use Cases)
7. **GraphQL Cop** - GraphQL security auditing
   - Purpose: GraphQL-specific security checks
   - Integration: GraphQL endpoint testing

8. **RESTler** - REST API fuzzing (Microsoft)
   - Purpose: Intelligent REST API fuzzing
   - Integration: Automated input generation

9. **Burp Suite Professional** - Web/API security testing
   - Purpose: Manual and automated security testing
   - Integration: Advanced vulnerability discovery

---

## 📋 Implementation Strategy for Epyon

### Phase 1: Discovery & Validation (Current)

**Script: `run-api-discovery.sh`**
- Find OpenAPI/Swagger specifications
- Extract routes from code (Python, Node.js, Java)
- Validate discovered specs with Spectral
- Generate API inventory report

### Phase 2: Static Security Analysis

**Script: `run-api-security-scan.sh`**
- Spectral security linting
- OpenAPI spec validation
- Security rule enforcement
- Authentication/authorization checks

### Phase 3: Dynamic Testing

**Script: `run-api-dynamic-scan.sh`**
- OWASP ZAP active scanning
- Endpoint fuzzing
- Authentication bypass testing
- Rate limiting validation

### Phase 4: GraphQL Support

**Script: `run-graphql-security-scan.sh`**
- GraphQL introspection
- Schema validation
- Query complexity analysis
- Authorization testing

---

## 🎯 Immediate Action Items

### 1. Create API Discovery Script

**File**: `scripts/shell/run-api-discovery.sh`

**Features:**
- Search for OpenAPI/Swagger files
- Extract API routes from code
- Analyze common API patterns
- Generate API inventory JSON

### 2. Integrate Spectral for OpenAPI Validation

**Docker Command:**
```bash
docker run --rm -v "${TARGET_DIR}:/workspace" \
    stoplight/spectral lint "/workspace/openapi.yaml" \
    --format json \
    --output "/workspace/spectral-results.json"
```

### 3. Add OWASP ZAP API Scanning

**Docker Command:**
```bash
docker run --rm -v "${SCAN_DIR}:/zap/wrk:rw" \
    owasp/zap2docker-stable zap-api-scan.py \
    -t "/zap/wrk/openapi.yaml" \
    -f openapi \
    -J "/zap/wrk/zap-api-results.json"
```

### 4. Update Dashboard with API Section

**New Dashboard Section:**
- API Specifications Found
- Endpoints Discovered
- Security Issues Detected
- Authentication Methods
- Rate Limiting Status

---

## 📊 Success Metrics (Waypoint 6)

### Coverage Metrics
- ✅ OpenAPI/Swagger specification validation
- ✅ API endpoint security analysis
- ✅ Authentication/authorization checks
- ✅ Rate limiting validation
- ✅ GraphQL security scanning

### Integration Goals
- **3+ Tools**: Spectral, OWASP ZAP, Newman
- **Multi-Format**: REST, GraphQL, SOAP
- **Automated**: No manual intervention required
- **Consolidated**: Unified dashboard reporting

### Quality Gates
- **Critical**: No unprotected sensitive endpoints
- **High**: Authentication required on all non-public APIs
- **Medium**: Rate limiting implemented
- **Low**: API documentation complete

---

## 🔮 Future Enhancements

### Advanced Features
1. **API Contract Testing** - Validate API responses against specs
2. **Performance Testing** - API load and stress testing
3. **Mock Server Generation** - Auto-generate mock servers from specs
4. **API Versioning Analysis** - Track API version compatibility
5. **Security Policy Enforcement** - Custom security rule definitions

### Integration Opportunities
1. **CI/CD Pipeline** - Pre-deployment API security checks
2. **API Gateway Integration** - Real-time security monitoring
3. **Service Mesh** - Kubernetes service-to-service security
4. **API Management Platforms** - Integration with Kong, Apigee, etc.

---

## 📚 Reference Documentation

### Standards & Specifications
- [OpenAPI Specification 3.1](https://spec.openapis.org/oas/v3.1.0)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [REST API Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [GraphQL Security Best Practices](https://graphql.org/learn/authorization/)

### Tool Documentation
- [Spectral Documentation](https://meta.stoplight.io/docs/spectral/)
- [OWASP ZAP API Scan](https://www.zaproxy.org/docs/docker/api-scan/)
- [Newman (Postman CLI)](https://learning.postman.com/docs/running-collections/using-newman-cli/command-line-integration-with-newman/)
- [GraphQL Voyager](https://github.com/graphql-kit/graphql-voyager)

---

**Next Steps:**
1. Create `run-api-discovery.sh` script
2. Implement OpenAPI/Swagger file detection
3. Add code-based route extraction
4. Test with sample applications
5. Integrate into `run-target-security-scan.sh`

**Timeline**: Target Q1 2026 for initial implementation
**Dependencies**: Docker, jq, grep/awk for parsing
**Testing**: Use MetroStar/comet-starter as baseline application
