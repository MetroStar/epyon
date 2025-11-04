# Grype Security Report

**Scan Type:** grype-base-python-3.11-alpine-results  
**Generated:** Tue Nov  4 12:53:09 CST 2025  

## Summary

**Total Vulnerabilities:** 7

### Severity Breakdown

- **Critical:** 0
- **High:** 0
- **Medium:** 1
- **Low:** 6

## Top Vulnerabilities

### 1. CVE-2025-8869

**Severity:** MEDIUM  
**Package:** pip @ 24.0  
**Description:** pip's fallback tar extraction doesn't check symbolic links point to extraction directory...  

### 2. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 3. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 4. CVE-2025-46394

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 5. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 6. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 7. CVE-2024-58251

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

