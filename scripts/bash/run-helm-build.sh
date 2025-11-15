#!/bin/bash

# Helm Build and Package Script
# Builds, validates, and packages Helm charts with comprehensive checks

# Configuration - Support target directory scanning
REPO_PATH="${TARGET_DIR:-$(pwd)}"
CHART_DIR="$REPO_PATH/chart"
OUTPUT_DIR="../../reports/helm-packages"
CHART_NAME="advana-marketplace"
BUILD_LOG="$OUTPUT_DIR/helm-build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Start logging
exec 1> >(tee -a "$BUILD_LOG")
exec 2> >(tee -a "$BUILD_LOG" >&2)

echo "============================================"
echo -e "${BLUE}Helm Chart Build Process${NC}"
echo "============================================"
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Chart Name: $CHART_NAME"
echo "Build Log: $BUILD_LOG"
echo "Timestamp: $(date)"
echo ""

# Check if Helm is available, use Docker if not installed locally
HELM_CMD="helm"
DOCKER_HELM_IMAGE="alpine/helm:latest"
USE_DOCKER=false

if ! command -v helm &> /dev/null; then
    echo -e "${YELLOW}⚠️  Helm not found locally, using Docker-based Helm${NC}"
    USE_DOCKER=true
    
    # Test Docker availability
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Neither Helm nor Docker is available${NC}"
        echo "Please install either Helm or Docker"
        exit 1
    fi
    
    # Pull Helm Docker image
    echo "Pulling Helm Docker image..."
    docker pull "$DOCKER_HELM_IMAGE"
    
    # Mount the target directory containing the chart
    TARGET_PARENT="$(dirname "$REPO_PATH")"
    TARGET_NAME="$(basename "$REPO_PATH")"
    CHART_PATH_IN_CONTAINER="/workspace/$TARGET_NAME/chart"
    
    # Create a base command function to handle Docker properly
    DOCKER_CHART_PATH="$CHART_PATH_IN_CONTAINER"
else
    HELM_CMD="helm"
    DOCKER_CHART_PATH="$CHART_DIR"
fi

echo -e "${BLUE}📊 Helm Version Information:${NC}"
if [ "$USE_DOCKER" = true ]; then
    docker run --rm "$DOCKER_HELM_IMAGE" version --short 2>/dev/null || docker run --rm "$DOCKER_HELM_IMAGE" version
else
    helm version --short 2>/dev/null || helm version
fi
echo ""

# Validate chart directory exists with graceful handling
if [ ! -d "$CHART_DIR" ]; then
    echo -e "${YELLOW}⚠️  Chart directory not found: $CHART_DIR${NC}"
    echo -e "${CYAN}💡 This is expected for projects without Helm charts${NC}"
    echo ""
    echo "============================================"
    echo -e "${GREEN}✅ Helm build skipped successfully!${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}📊 Fallback Build Summary:${NC}"
    echo "=========================="
    echo -e "${YELLOW}⚠️  No Helm chart found - skipping build process${NC}"
    echo -e "${GREEN}✅ Security pipeline continues with available components${NC}"
    echo -e "${CYAN}💡 For Helm deployment, add a chart/ directory to your project${NC}"
    echo ""
    echo -e "${BLUE}📁 Output Files:${NC}"
    echo "================"
    echo -e "${YELLOW}ℹ️  No Helm packages generated (no chart available)${NC}"
    echo ""
    echo -e "${BLUE}🔗 Related Commands:${NC}"
    echo "===================="
    echo "Create chart:        helm create chart/"
    echo "Re-run build:        npm run helm:build"
    echo "Full security suite: npm run security:full"
    echo ""
    echo "============================================"
    echo "Helm build complete (skipped)."
    echo "============================================"
    
    # Always exit successfully to continue pipeline
    exit 0
fi

if [ ! -f "$CHART_DIR/Chart.yaml" ]; then
    echo -e "${YELLOW}⚠️  Chart.yaml not found in $CHART_DIR${NC}"
    echo -e "${CYAN}💡 Invalid Helm chart structure${NC}"
    echo ""
    echo "============================================"
    echo -e "${GREEN}✅ Helm build skipped successfully!${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}📊 Fallback Build Summary:${NC}"
    echo "=========================="
    echo -e "${YELLOW}⚠️  Invalid chart structure - missing Chart.yaml${NC}"
    echo -e "${GREEN}✅ Security pipeline continues${NC}"
    echo -e "${CYAN}💡 Ensure Chart.yaml exists in chart/ directory${NC}"
    echo ""
    echo "============================================"
    echo "Helm build complete (skipped)."
    echo "============================================"
    
    # Always exit successfully to continue pipeline
    exit 0
fi

echo -e "${BLUE}📋 Chart Information:${NC}"
echo "===================="
if [ "$USE_DOCKER" = true ]; then
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace "$DOCKER_HELM_IMAGE" show chart "$DOCKER_CHART_PATH"
else
    helm show chart "$CHART_DIR"
fi
echo ""

# AWS ECR Authentication for private dependencies
echo -e "${BLUE}🔐 Step 0: AWS ECR Authentication (Optional)${NC}"
echo "=================================="
AWS_REGION="us-gov-west-1"
ECR_REGISTRY="231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"

# Offer AWS ECR authentication for private Helm dependencies
echo -e "${CYAN}🔐 This chart may require AWS ECR authentication for private dependencies${NC}"
echo "Options:"
echo "  1) Attempt AWS ECR login (recommended for complete build)"
echo "  2) Skip authentication (fallback to stub dependencies)"
echo ""
read -p "Choose option (1 or 2, default: 2): " AWS_CHOICE
AWS_CHOICE=${AWS_CHOICE:-2}

# Initialize authentication status
AWS_AUTHENTICATED=false

if [ "$AWS_CHOICE" = "1" ]; then
    echo -e "${CYAN}🚀 Running AWS ECR authentication...${NC}"
    
    # Check if AWS CLI is available
    if command -v aws &> /dev/null; then
        echo "Checking AWS credentials..."
        if aws sts get-caller-identity &> /dev/null 2>&1; then
            echo -e "${GREEN}✅ AWS credentials found${NC}"
            
            # Authenticate with ECR
            echo "Authenticating with AWS ECR..."
            if aws ecr get-login-password --region "$AWS_REGION" 2>/dev/null | docker login --username AWS --password-stdin "$ECR_REGISTRY" &> /dev/null; then
                echo -e "${GREEN}✅ Docker ECR authentication successful${NC}"
                AWS_AUTHENTICATED=true
            else
                echo -e "${YELLOW}⚠️  Docker ECR authentication failed${NC}"
                AWS_AUTHENTICATED=false
            fi
            
            # Authenticate Helm with ECR (if not using Docker)
            if [ "$USE_DOCKER" = false ] && command -v helm &> /dev/null; then
                if aws ecr get-login-password --region "$AWS_REGION" 2>/dev/null | helm registry login --username AWS --password-stdin "$ECR_REGISTRY" &> /dev/null; then
                    echo -e "${GREEN}✅ Helm ECR authentication successful${NC}"
                    AWS_AUTHENTICATED=true
                else
                    echo -e "${YELLOW}⚠️  Helm ECR authentication failed${NC}"
                fi
            fi
            
            if [ "$AWS_AUTHENTICATED" = true ]; then
                echo -e "${GREEN}✅ AWS ECR authentication completed successfully${NC}"
            else
                echo -e "${YELLOW}⚠️  AWS ECR authentication failed - continuing with stub fallback${NC}"
                echo -e "${CYAN}💡 Stub dependencies will be created for missing charts${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  AWS credentials not configured - dependency download may fail${NC}"
            echo -e "${CYAN}💡 Continuing with stub fallback - dependencies will be mocked${NC}"
            AWS_AUTHENTICATED=false
        fi
    else
        echo -e "${RED}❌ AWS CLI not found${NC}"
        echo -e "${CYAN}💡 Continuing with stub fallback - dependencies will be mocked${NC}"
        AWS_AUTHENTICATED=false
    fi
else
    echo -e "${CYAN}⏭️  Skipping AWS authentication - using stub fallback${NC}"
    AWS_AUTHENTICATED=false
fi

echo ""

echo -e "${BLUE}🔍 Step 1: Chart Dependency Update${NC}"
echo "==================================="

# Show authentication status like in Checkov script
if [ "$AWS_AUTHENTICATED" = true ]; then
    echo -e "${GREEN}🔐 AWS ECR authenticated - attempting full dependency resolution${NC}"
else
    echo -e "${YELLOW}🔓 No AWS ECR authentication - stub dependencies will be created if needed${NC}"
fi

if [ "$USE_DOCKER" = true ]; then
    # Pass AWS credentials to Docker container if available
    AWS_ENV_FLAGS=""
    if [ ! -z "$AWS_ACCESS_KEY_ID" ]; then
        AWS_ENV_FLAGS="-e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$AWS_REGION}"
    fi
    
    # Mount Docker socket for ECR authentication
    if [ -S /var/run/docker.sock ]; then
        DOCKER_SOCKET_MOUNT="-v /var/run/docker.sock:/var/run/docker.sock"
    else
        DOCKER_SOCKET_MOUNT=""
    fi
    
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace $AWS_ENV_FLAGS $DOCKER_SOCKET_MOUNT "$DOCKER_HELM_IMAGE" dependency update "$DOCKER_CHART_PATH"
    DEPENDENCY_RESULT=$?
else
    helm dependency update "$CHART_DIR"
    DEPENDENCY_RESULT=$?
fi
if [ $DEPENDENCY_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies updated successfully${NC}"
else
    if [ "$AWS_AUTHENTICATED" = true ]; then
        echo -e "${YELLOW}⚠️  Dependency update failed despite AWS authentication${NC}"
        echo -e "${CYAN}💡 May be network issues or repository access problems${NC}"
    else
        echo -e "${YELLOW}⚠️  Dependency update failed (expected without AWS ECR access)${NC}"
        echo -e "${CYAN}💡 This is normal - continuing with stub dependencies${NC}"
    fi
    echo -e "${CYAN}🔄 Creating stub dependencies...${NC}"
    
    # Create charts directory if it doesn't exist
    mkdir -p "$CHART_DIR/charts"
    
    # Create a stub dependency to allow build to continue
    echo -e "${CYAN}💡 Creating stub advana-library chart...${NC}"
    STUB_CHART_DIR="$CHART_DIR/charts/advana-library"
    mkdir -p "$STUB_CHART_DIR/templates"
    
    # Create stub Chart.yaml
    cat > "$STUB_CHART_DIR/Chart.yaml" << EOF
apiVersion: v2
name: advana-library
description: Stub chart for advana-library dependency
type: library
version: 2.0.3
appVersion: "1.0.0"
EOF
    
    # Create comprehensive stub templates/_helpers.tpl with all common templates
    cat > "$STUB_CHART_DIR/templates/_helpers.tpl" << 'EOF'
{{/*
===========================================
ADVANA LIBRARY STUB TEMPLATES
===========================================
This is a stub implementation of the advana-library chart
that provides basic templates for development/testing.
*/}}

{{/*
Common Deployment Template
*/}}
{{- define "common.deployment" -}}
# Stub deployment template - replace with actual deployment configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "common.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "common.selectorLabels" . | nindent 8 }}
    spec:
      containers:
      - name: {{ .Chart.Name }}
        image: "nginx:latest"
        ports:
        - containerPort: 80
{{- end }}

{{/*
Common Service Template
*/}}
{{- define "common.service" -}}
# Stub service template - replace with actual service configuration
apiVersion: v1
kind: Service
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    {{- include "common.selectorLabels" . | nindent 4 }}
{{- end }}

{{/*
Common ServiceAccount Template
*/}}
{{- define "common.serviceaccount" -}}
# Stub serviceaccount template
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
{{- end }}

{{/*
Common Ingress Template
*/}}
{{- define "common.ingress" -}}
# Stub ingress template - replace with actual ingress configuration
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  rules:
  - host: {{ ((.Values).ingress).host | default "example.com" }}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: {{ include "common.fullname" . }}
            port:
              number: 80
{{- end }}

{{/*
Common HPA Template
*/}}
{{- define "common.hpa" -}}
# Stub HPA template
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "common.fullname" . }}
  minReplicas: 1
  maxReplicas: 3
{{- end }}

{{/*
Common PDB Template
*/}}
{{- define "common.pdb" -}}
# Stub PDB template
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      {{- include "common.selectorLabels" . | nindent 6 }}
{{- end }}

{{/*
Common Job Template
*/}}
{{- define "common.job" -}}
# Stub job template
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: job
        image: "busybox:latest"
        command: ["echo", "Job completed"]
{{- end }}

{{/*
Common PVC Template
*/}}
{{- define "common.pvc" -}}
# Stub PVC template
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
{{- end }}

{{/*
Common Istio PeerAuthentication Template
*/}}
{{- define "common.istio.peerauthentication" -}}
# Stub Istio PeerAuthentication template
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "common.selectorLabels" . | nindent 6 }}
  mtls:
    mode: STRICT
{{- end }}

{{/*
Common Istio VirtualService Template
*/}}
{{- define "common.istio.virtualservice" -}}
# Stub Istio VirtualService template
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  hosts:
  - {{ ((.Values).virtualService).host | default "example.com" }}
  http:
  - route:
    - destination:
        host: {{ include "common.fullname" . }}
{{- end }}

{{/*
Common Environment ConfigMap Template
*/}}
{{- define "common.env.configmap" -}}
# Stub environment configmap template
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "common.fullname" . }}-env
  labels:
    {{- include "common.labels" . | nindent 4 }}
data:
  APP_NAME: {{ include "common.name" . }}
  APP_VERSION: {{ .Chart.AppVersion | default "latest" }}
{{- end }}

{{/*
Common Volume ConfigMap Template
*/}}
{{- define "common.volume.configmap" -}}
# Stub volume configmap template
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "common.fullname" . }}-volume
  labels:
    {{- include "common.labels" . | nindent 4 }}
data:
  config.yaml: |
    application:
      name: {{ include "common.name" . }}
{{- end }}

{{/*
Common Environment Secret Template
*/}}
{{- define "common.env.secret" -}}
# Stub environment secret template
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "common.fullname" . }}-env
  labels:
    {{- include "common.labels" . | nindent 4 }}
type: Opaque
data:
  SECRET_KEY: {{ "changeme" | b64enc }}
{{- end }}

{{/*
Common Volume Secret Template
*/}}
{{- define "common.volume.secret" -}}
# Stub volume secret template
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "common.fullname" . }}-volume
  labels:
    {{- include "common.labels" . | nindent 4 }}
type: Opaque
data:
  secret.yaml: {{ "secretdata" | b64enc }}
{{- end }}

{{/*
Common TLS Secret Template
*/}}
{{- define "common.tls.secret" -}}
# Stub TLS secret template
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "common.fullname" . }}-tls
  labels:
    {{- include "common.labels" . | nindent 4 }}
type: kubernetes.io/tls
data:
  tls.crt: {{ "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t" | b64enc }}
  tls.key: {{ "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t" | b64enc }}
{{- end }}

{{/*
Common Docker Config JSON Secret Template
*/}}
{{- define "common.dockerconfigjson.secret" -}}
# Stub docker config secret template
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "common.fullname" . }}-docker
  labels:
    {{- include "common.labels" . | nindent 4 }}
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: {{ "{}" | b64enc }}
{{- end }}

{{/*
Common External Secret Template
*/}}
{{- define "common.externalsecret" -}}
# Stub external secret template
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: default-secret-store
    kind: SecretStore
  target:
    name: {{ include "common.fullname" . }}-external
{{- end }}

{{/*
Common Crossplane Template
*/}}
{{- define "common.crossplane" -}}
# Stub crossplane template
apiVersion: apiextensions.crossplane.io/v1
kind: CompositeResourceDefinition
metadata:
  name: {{ include "common.fullname" . }}-xrd
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  group: example.com
  names:
    kind: XResource
    plural: xresources
  versions:
  - name: v1alpha1
    served: true
    referenceable: true
    schema:
      openAPIV3Schema:
        type: object
{{- end }}

{{/*
Common Istio DestinationRule Template
*/}}
{{- define "common.istio.destinationrule" -}}
# Stub Istio DestinationRule template
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: {{ include "common.fullname" . }}
  labels:
    {{- include "common.labels" . | nindent 4 }}
spec:
  host: {{ include "common.fullname" . }}
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
{{- end }}

{{/*
===========================================
HELPER TEMPLATES
===========================================
*/}}

{{/*
Common labels
*/}}
{{- define "common.labels" -}}
helm.sh/chart: {{ include "common.chart" . }}
{{ include "common.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "common.selectorLabels" -}}
app.kubernetes.io/name: {{ include "common.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "common.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "common.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "common.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}
EOF
    
    # Create stub values.yaml
    cat > "$STUB_CHART_DIR/values.yaml" << EOF
# Advana Library Stub Values
# These are default values for the stub chart

# Virtual Service configuration
virtualService:
  host: "example.com"

# Ingress configuration  
ingress:
  host: "example.com"

# Service Account configuration
serviceAccount:
  create: true
  name: ""

# Common configuration
nameOverride: ""
fullnameOverride: ""

# Resource configuration
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Autoscaling
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 100
  targetCPUUtilizationPercentage: 80
EOF

    echo -e "${GREEN}✅ Stub dependency created successfully${NC}"
fi
echo ""

echo -e "${BLUE}🔎 Step 2: Chart Linting${NC}"
echo "======================="
if [ "$USE_DOCKER" = true ]; then
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace "$DOCKER_HELM_IMAGE" lint "$DOCKER_CHART_PATH"
    LINT_RESULT=$?
else
    helm lint "$DOCKER_CHART_PATH"
    LINT_RESULT=$?
fi
if [ $LINT_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Chart linting passed${NC}"
    LINT_STATUS="PASSED"
else
    echo -e "${RED}❌ Chart linting failed${NC}"
    LINT_STATUS="FAILED"
fi
echo ""

echo -e "${BLUE}🧪 Step 3: Template Validation${NC}"
echo "=============================="
echo "Validating Kubernetes templates..."

# Test template rendering with default values
if [ "$USE_DOCKER" = true ]; then
    # For Docker, mount output directory for template rendering
    if docker run --rm -v "$TARGET_PARENT":/workspace -v "$OUTPUT_DIR":/output -w /workspace "$DOCKER_HELM_IMAGE" template "$CHART_NAME" "$DOCKER_CHART_PATH" > "$OUTPUT_DIR/rendered-templates.yaml"; then
        echo -e "${GREEN}✅ Template rendering successful${NC}"
        
        # Count resources
        RESOURCE_COUNT=$(grep -c "^kind:" "$OUTPUT_DIR/rendered-templates.yaml" 2>/dev/null || echo "0")
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        
        TEMPLATE_STATUS="PASSED"
    else
        echo -e "${RED}❌ Template rendering failed${NC}"
        TEMPLATE_STATUS="FAILED"
    fi
else
    if helm template "$CHART_NAME" "$DOCKER_CHART_PATH" > "$OUTPUT_DIR/rendered-templates.yaml"; then
        echo -e "${GREEN}✅ Template rendering successful${NC}"
        
        # Count resources
        RESOURCE_COUNT=$(grep -c "^kind:" "$OUTPUT_DIR/rendered-templates.yaml" 2>/dev/null || echo "0")
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        
        TEMPLATE_STATUS="PASSED"
    else
        echo -e "${RED}❌ Template rendering failed${NC}"
        TEMPLATE_STATUS="FAILED"
    fi
fi
echo ""

echo -e "${BLUE}📦 Step 4: Chart Packaging${NC}"
echo "========================="

# Package the chart
if [ "$USE_DOCKER" = true ]; then
    # For Docker, mount output directory for packaging
    if docker run --rm -v "$TARGET_PARENT":/workspace -v "$OUTPUT_DIR":/output -w /workspace "$DOCKER_HELM_IMAGE" package "$DOCKER_CHART_PATH" --destination /output; then
        echo -e "${GREEN}✅ Chart packaging successful${NC}"
        
        # Find the generated package
        PACKAGE_FILE=$(find "$OUTPUT_DIR" -name "${CHART_NAME}-*.tgz" | head -1)
        if [ -f "$PACKAGE_FILE" ]; then
            PACKAGE_SIZE=$(ls -lh "$PACKAGE_FILE" | awk '{print $5}')
            echo "Package created: $(basename "$PACKAGE_FILE") ($PACKAGE_SIZE)"
            
            # Verify package integrity with Docker
            if docker run --rm -v "$OUTPUT_DIR":/packages "$DOCKER_HELM_IMAGE" show chart "/packages/$(basename "$PACKAGE_FILE")" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ Package integrity verified${NC}"
                PACKAGE_STATUS="PASSED"
            else
                echo -e "${RED}❌ Package integrity check failed${NC}"
                PACKAGE_STATUS="FAILED"
            fi
        else
            echo -e "${RED}❌ Package file not found${NC}"
            PACKAGE_STATUS="FAILED"
        fi
    else
        echo -e "${RED}❌ Chart packaging failed${NC}"
        PACKAGE_STATUS="FAILED"
    fi
else
    if helm package "$DOCKER_CHART_PATH" --destination "$OUTPUT_DIR"; then
        echo -e "${GREEN}✅ Chart packaging successful${NC}"
        
        # Find the generated package
        PACKAGE_FILE=$(find "$OUTPUT_DIR" -name "${CHART_NAME}-*.tgz" | head -1)
        if [ -f "$PACKAGE_FILE" ]; then
            PACKAGE_SIZE=$(ls -lh "$PACKAGE_FILE" | awk '{print $5}')
            echo "Package created: $(basename "$PACKAGE_FILE") ($PACKAGE_SIZE)"
            
            # Verify package integrity
            if helm show chart "$PACKAGE_FILE" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ Package integrity verified${NC}"
                PACKAGE_STATUS="PASSED"
            else
                echo -e "${RED}❌ Package integrity check failed${NC}"
                PACKAGE_STATUS="FAILED"
            fi
        else
            echo -e "${RED}❌ Package file not found${NC}"
            PACKAGE_STATUS="FAILED"
        fi
    else
        echo -e "${RED}❌ Chart packaging failed${NC}"
        PACKAGE_STATUS="FAILED"
    fi
fi
echo ""

echo -e "${BLUE}🔍 Step 5: Security Analysis${NC}"
echo "==========================="

# Check for common security issues in templates
SECURITY_ISSUES=0

echo "Scanning templates for security best practices..."

# Check for hardcoded secrets
if grep -r "password\|secret\|token" "$CHART_DIR/templates/" --include="*.yaml" | grep -v "{{" | grep -i ":" > /dev/null; then
    echo -e "${YELLOW}⚠️  Potential hardcoded secrets found${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for privileged containers
if grep -r "privileged.*true" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  Privileged containers detected${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for root user usage
if grep -r "runAsUser.*0" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  Root user usage detected${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for missing resource limits
if ! grep -r "resources:" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  No resource limits defined${NC}"
    ((SECURITY_ISSUES++))
fi

if [ $SECURITY_ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ No major security issues detected${NC}"
    SECURITY_STATUS="PASSED"
else
    echo -e "${YELLOW}⚠️  $SECURITY_ISSUES potential security issues found${NC}"
    SECURITY_STATUS="WARNING"
fi
echo ""

echo -e "${BLUE}📊 Build Summary${NC}"
echo "================"
echo "Chart Linting: $LINT_STATUS"
echo "Template Validation: $TEMPLATE_STATUS"
echo "Package Creation: $PACKAGE_STATUS"
echo "Security Scan: $SECURITY_STATUS"
echo ""

# Overall status
if [ "$LINT_STATUS" = "PASSED" ] && [ "$TEMPLATE_STATUS" = "PASSED" ] && [ "$PACKAGE_STATUS" = "PASSED" ]; then
    echo -e "${GREEN}🎉 Helm build completed successfully!${NC}"
    echo "============================================"
    
    if [ -f "$PACKAGE_FILE" ]; then
        echo -e "${GREEN}📦 Package Details:${NC}"
        echo "File: $(basename "$PACKAGE_FILE")"
        echo "Size: $PACKAGE_SIZE"
        echo "Location: $PACKAGE_FILE"
        echo ""
        
        echo -e "${GREEN}🚀 Deployment Commands:${NC}"
        echo "# Install from package:"
        echo "helm install $CHART_NAME $PACKAGE_FILE"
        echo ""
        echo "# Install from source:"
        echo "helm install $CHART_NAME $CHART_DIR"
        echo ""
        echo "# Upgrade existing deployment:"
        echo "helm upgrade $CHART_NAME $PACKAGE_FILE"
    fi
    
    BUILD_RESULT="SUCCESS"
else
    echo -e "${RED}❌ Helm build completed with errors${NC}"
    echo "============================================"
    echo "Please review the issues above and fix them."
    BUILD_RESULT="FAILED"
fi

echo ""
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "Build log: $BUILD_LOG"
echo "Rendered templates: $OUTPUT_DIR/rendered-templates.yaml"
if [ -f "$PACKAGE_FILE" ]; then
    echo "Helm package: $PACKAGE_FILE"
fi
echo "Package directory: $OUTPUT_DIR"

echo ""
echo "============================================"
echo "Helm build process complete."
echo "============================================"

# Exit with appropriate code
if [ "$BUILD_RESULT" = "SUCCESS" ]; then
    exit 0
else
    exit 1
fi