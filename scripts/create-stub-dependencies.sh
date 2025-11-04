#!/bin/bash

# Create Stub Helm Dependencies Script
# Creates minimal stub charts for missing private dependencies

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CHART_DIR="${TARGET_DIR:-$(pwd)}/chart"

echo "============================================"
echo -e "${BLUE}🔧 Helm Dependency Stubbing Tool${NC}"
echo "============================================"
echo "Chart Directory: $CHART_DIR"
echo ""

# Create charts directory if it doesn't exist
mkdir -p "$CHART_DIR/charts"

# Create stub advana-library chart
STUB_CHART_DIR="$CHART_DIR/charts/advana-library"
mkdir -p "$STUB_CHART_DIR/templates"

echo -e "${CYAN}📦 Creating stub advana-library chart...${NC}"

# Create minimal Chart.yaml for stub
cat > "$STUB_CHART_DIR/Chart.yaml" << EOF
apiVersion: v2
name: advana-library
description: Stub chart for advana-library dependency
type: library
version: 2.0.4
appVersion: "2.0.4"
EOF

# Create minimal values.yaml for stub
cat > "$STUB_CHART_DIR/values.yaml" << EOF
# Stub values for advana-library
global: {}
EOF

# Create stub templates that provide the common functions
mkdir -p "$STUB_CHART_DIR/templates"

cat > "$STUB_CHART_DIR/templates/_helpers.tpl" << 'EOF'
{{/*
Stub implementations of common template functions
*/}}
{{- define "common.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  namespace: {{ .Release.Namespace }}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}
    spec:
      containers:
      - name: app
        image: nginx:alpine
        ports:
        - containerPort: 8080
{{- end }}

{{- define "common.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}
  namespace: {{ .Release.Namespace }}
spec:
  selector:
    app: {{ .Release.Name }}
  ports:
  - port: 80
    targetPort: 8080
{{- end }}

{{- define "common.env.secret" -}}
# Stub: Environment secrets would be defined here
{{- end }}

{{- define "common.volume.secret" -}}
# Stub: Volume secrets would be defined here  
{{- end }}

{{- define "common.tls.secret" -}}
# Stub: TLS secrets would be defined here
{{- end }}

{{- define "common.dockerconfigjson.secret" -}}
# Stub: Docker registry secrets would be defined here
{{- end }}
EOF

echo -e "${GREEN}✅ Stub advana-library chart created${NC}"

# Test template rendering with stub
echo -e "${CYAN}🧪 Testing template rendering with stub...${NC}"
cd "$CHART_DIR"

if command -v helm &> /dev/null; then
    if helm template test-stub . > "../helm-dependency-resolution/stub-test-render.yaml" 2>&1; then
        RESOURCE_COUNT=$(grep -c "^kind:" "../helm-dependency-resolution/stub-test-render.yaml" 2>/dev/null || echo "0")
        echo -e "${GREEN}✅ Template rendering successful with stub${NC}"
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        
        echo ""
        echo "Rendered resource types:"
        grep "^kind:" "../helm-dependency-resolution/stub-test-render.yaml" | sort | uniq -c
    else
        echo -e "${YELLOW}⚠️  Template rendering still failed${NC}"
        echo "Check ../helm-dependency-resolution/stub-test-render.yaml for errors"
    fi
else
    echo "Testing with Docker Helm..."
    docker run --rm -v "$(pwd):/apps" -w /apps alpine/helm:latest \
        template test-stub . > "../helm-dependency-resolution/stub-test-render.yaml" 2>&1
    
    if [ $? -eq 0 ]; then
        RESOURCE_COUNT=$(grep -c "^kind:" "../helm-dependency-resolution/stub-test-render.yaml" 2>/dev/null || echo "0")
        echo -e "${GREEN}✅ Template rendering successful with stub${NC}"
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
    fi
fi

cd - > /dev/null

echo ""
echo -e "${CYAN}📊 Stub Chart Summary${NC}"
echo "========================"
echo "Stub chart location: $STUB_CHART_DIR"
echo "This stub provides basic implementations of common template functions"
echo "You can now run Checkov security scans on the rendered templates"
echo ""
echo -e "${GREEN}🎯 Stub dependencies created successfully!${NC}"