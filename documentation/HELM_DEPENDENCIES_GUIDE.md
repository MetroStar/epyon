# 🔐 Helm Dependencies Resolution Guide

## Overview

The `advana-marketplace-monolith-node` Helm chart requires external dependencies that need to be resolved before security scanning can be performed effectively.

## 📋 Dependencies Required

The chart has two dependencies defined in `Chart.yaml`:

1. **✅ postgresql** (Public)
   - Version: 15.5.38
   - Repository: https://charts.bitnami.com/bitnami
   - Status: Accessible without authentication

2. **❌ advana-library** (Private)
   - Version: 2.0.4
   - Repository: oci://231388672283.dkr.ecr.us-gov-west-1.amazonaws.com/tenant
   - Status: Requires AWS ECR authentication

## 🛠️ Solution Options

### Option 1: AWS ECR Authentication (Recommended for Production)

**Use this if you have access to the AWS government account.**

#### Prerequisites
- AWS CLI installed
- Valid AWS credentials for account `231388672283`
- ECR permissions for `tenant/advana-library` repository
- Access to `us-gov-west-1` region

#### Quick Setup
```bash
# Run the automated script
./scripts/aws-ecr-helm-auth.sh

# Or using npm
npm run aws:ecr:auth
```

#### Manual Setup
```bash
# 1. Configure AWS credentials
aws configure
# OR
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_DEFAULT_REGION=us-gov-west-1

# 2. Login to ECR
aws ecr get-login-password --region us-gov-west-1 | \
  docker login --username AWS --password-stdin \
  231388672283.dkr.ecr.us-gov-west-1.amazonaws.com

# 3. Add public repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# 4. Navigate to chart directory
cd "/path/to/advana-marketplace-monolith-node/chart"

# 5. Resolve dependencies
helm dependency update

# 6. Verify resolution
ls -la charts/
# Should show: postgresql-15.5.38.tgz and advana-library-2.0.4.tgz
```

### Option 2: Stub Dependencies (For Testing/Demo)

**Use this if you don't have AWS ECR access but want to test the security scanning.**

```bash
# Create stub dependencies
./scripts/create-stub-dependencies.sh

# Or using npm
npm run helm:deps:stub
```

This creates minimal stub implementations of the `advana-library` chart that provide basic template functions, allowing Helm to render templates for security analysis.

## 🔍 Verification

After resolving dependencies, you can verify the setup:

### Test Template Rendering
```bash
cd "/path/to/chart"
helm template test-render . > rendered-templates.yaml

# Check generated resources
grep "^kind:" rendered-templates.yaml | sort | uniq -c
```

### Run Security Scans
```bash
# Run Checkov on resolved chart
TARGET_DIR="/path/to/project" ./scripts/run-checkov-scan.sh

# Run full security suite
./scripts/run-target-security-scan.sh "/path/to/project" full
```

## 📊 Expected Results

### With Proper Dependencies (Option 1)
- **Helm Templates**: Render complete Kubernetes manifests
- **Checkov Scan**: Analyzes actual security configurations
- **Resource Count**: 10-20+ Kubernetes resources
- **Security Findings**: Detailed analysis of deployment, services, secrets, etc.

### With Stub Dependencies (Option 2)
- **Helm Templates**: Render basic stub manifests
- **Checkov Scan**: Analyzes minimal configurations
- **Resource Count**: 2-5 basic resources
- **Security Findings**: Limited but functional for testing

## 🚨 Troubleshooting

### "Failed to perform FetchReference" Error
```
Error: could not download oci://231388672283.dkr.ecr.us-gov-west-1.amazonaws.com/tenant/advana-library
```
**Solution**: AWS ECR authentication required (Option 1)

### "No resources found" in Checkov
**Cause**: Dependencies not resolved, templates are placeholders
**Solution**: Resolve dependencies first, then re-run security scans

### "AWS credentials not configured"
**Solutions**:
- `aws configure` (interactive)
- Environment variables (`AWS_ACCESS_KEY_ID`, etc.)
- AWS SSO (`aws sso login`)
- IAM roles (for EC2/ECS instances)

## 📚 Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `aws-ecr-helm-auth.sh` | Complete ECR authentication | `./scripts/aws-ecr-helm-auth.sh` |
| `aws-ecr-helm-auth-guide.sh` | Shows step-by-step guide | `./scripts/aws-ecr-helm-auth-guide.sh` |
| `resolve-helm-dependencies.sh` | Dependency analysis | `./scripts/resolve-helm-dependencies.sh` |
| `create-stub-dependencies.sh` | Creates stub charts | `./scripts/create-stub-dependencies.sh` |

## 📝 NPM Commands

```bash
# Dependency resolution
npm run aws:ecr:auth          # Full ECR authentication
npm run helm:deps:resolve     # Analyze dependencies  
npm run helm:deps:stub        # Create stub dependencies

# Security scanning with resolved dependencies
npm run target:full --target="/path/to/project"
```

## 🏢 Production Notes

For production environments:
1. Use proper AWS IAM roles and policies
2. Implement ECR repository access controls
3. Use AWS SSO for team access management
4. Consider using Helm OCI registries for better security
5. Automate dependency resolution in CI/CD pipelines

## 🔗 Related Documentation

- [AWS ECR User Guide](https://docs.aws.amazon.com/ecr/)
- [Helm Dependency Management](https://helm.sh/docs/helm/helm_dependency/)
- [Checkov Documentation](https://www.checkov.io/)