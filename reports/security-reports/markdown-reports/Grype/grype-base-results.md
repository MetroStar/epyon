# Grype Security Report

**Scan Type:** grype-base-results  
**Generated:** Mon Nov  3 16:31:46 CST 2025  

## Summary

**Total Vulnerabilities:** 9

### Severity Breakdown

- **Critical:** 0
- **High:** 1
- **Medium:** 2
- **Low:** 6

## Top Vulnerabilities

### 1. CVE-2023-6277

**Severity:** MEDIUM  
**Package:** tiff @ 4.7.1-r0  
**Description:** An out-of-memory flaw was found in libtiff. Passing a crafted tiff file to TIFFOpen() API may allow a remote attacker to cause a denial of service via a craft input with size smaller than 379 KB....  

### 2. CVE-2023-52356

**Severity:** HIGH  
**Package:** tiff @ 4.7.1-r0  
**Description:** A segment fault (SEGV) flaw was found in libtiff that could be triggered by passing a crafted tiff file to the TIFFReadRGBATileExt() API. This flaw allows a remote attacker to cause a heap-buffer overflow, leading to a denial of service....  

### 3. CVE-2023-6228

**Severity:** MEDIUM  
**Package:** tiff @ 4.7.1-r0  
**Description:** An issue was found in the tiffcp utility distributed by the libtiff package where a crafted TIFF file on processing may cause a heap-based buffer overflow leads to an application crash....  

### 4. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 5. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 6. CVE-2025-46394

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r19  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 7. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 8. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 9. CVE-2024-58251

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r19  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

