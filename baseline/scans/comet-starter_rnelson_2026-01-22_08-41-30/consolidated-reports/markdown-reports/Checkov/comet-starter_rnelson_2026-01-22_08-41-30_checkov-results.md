# Checkov Security Report

**Scan Type:** comet-starter_rnelson_2026-01-22_08-41-30_checkov-results  
**Generated:** Thu Jan 22 08:42:12 CST 2026  

## Summary

**Total Items:** 2

```json
[
  {
    "check_type": "dockerfile",
    "results": {
      "passed_checks": [
        {
          "check_id": "CKV_DOCKER_10",
          "bc_check_id": null,
          "check_name": "Ensure that WORKDIR values are absolute paths",
          "check_result": {
            "result": "PASSED",
            "results_configuration": null
          },
          "code_block": [
            [
              1,
              "# Stage 1: Build the React app\n"
            ],
            [
              2,
              "FROM node:20-alpine@sha256:df02558528d3d3d0d621f112e232611aecfee7cbc654f6b375765f72bb262799 AS build\n"
            ],
            [
              3,
              "\n"
            ],
            [
              4,
              "# Set the working directory in the container\n"
            ],
            [
              5,
              "WORKDIR /app\n"
            ],
            [
              6,
              "\n"
            ],
            [
              7,
              "# Copy package.json and package-lock.json to the working directory\n"
            ],
            [
              8,
              "COPY package*.json ./\n"
            ],
            [
              9,
              "\n"
            ],
            [
              10,
              "# Install dependencies\n"
            ],
            [
              11,
              "RUN npm install\n"
            ],
            [
              12,
              "\n"
            ],
            [
              13,
              "# Copy the entire app to the working directory\n"
            ],
            [
              14,
              "COPY . .\n"
            ],
            [
              15,
              "\n"
            ],
            [
              16,
              "# Build the React app\n"
            ],
            [
              17,
              "RUN npm run build\n"
            ],
            [
              18,
              "\n"
            ],
            [
              19,
             
```
