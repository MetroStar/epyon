# Grype Security Report

**Scan Type:** grype-base-node-18-alpine-results  
**Generated:** Mon Nov 17 09:58:59 CST 2025  

## Summary

**Total Vulnerabilities:** 17

### Severity Breakdown

- **Critical:** 0
- **High:** 4
- **Medium:** 5
- **Low:** 8

## Top Vulnerabilities

### 1. CVE-2024-21538

**Severity:** HIGH  
**Package:** cross-spawn @ 7.0.3  
**Description:** Regular Expression Denial of Service (ReDoS) in cross-spawn...  

### 2. CVE-2025-23166

**Severity:** HIGH  
**Package:** node @ 18.20.8  
**Description:** The C++ method SignTraits::DeriveBits() may incorrectly call ThrowException() based on user-supplied inputs when executing in a background thread, crashing the Node.js process. Such cryptographic operations are commonly applied to untrusted inputs. Thus, this mechanism potentially allows an adversar...  

### 3. CVE-2025-9230

**Severity:** HIGH  
**Package:** libcrypto3 @ 3.3.3-r0  
**Description:** No description available...  

### 4. CVE-2025-9230

**Severity:** HIGH  
**Package:** libssl3 @ 3.3.3-r0  
**Description:** No description available...  

### 5. CVE-2025-23165

**Severity:** LOW  
**Package:** node @ 18.20.8  
**Description:** In Node.js, the `ReadFileUtf8` internal binding leaks memory due to a corrupted pointer in `uv_fs_s.file`: a UTF-16 path buffer is allocated but subsequently overwritten when the file descriptor is set. This results in an unrecoverable memory leak on every call. Repeated use can cause unbounded memo...  

### 6. CVE-2025-9232

**Severity:** MEDIUM  
**Package:** libcrypto3 @ 3.3.3-r0  
**Description:** No description available...  

### 7. CVE-2025-9232

**Severity:** MEDIUM  
**Package:** libssl3 @ 3.3.3-r0  
**Description:** No description available...  

### 8. CVE-2025-9231

**Severity:** MEDIUM  
**Package:** libcrypto3 @ 3.3.3-r0  
**Description:** No description available...  

### 9. CVE-2025-9231

**Severity:** MEDIUM  
**Package:** libssl3 @ 3.3.3-r0  
**Description:** No description available...  

### 10. CVE-2025-23167

**Severity:** MEDIUM  
**Package:** node @ 18.20.8  
**Description:** A flaw in Node.js 20's HTTP parser allows improper termination of HTTP/1 headers using `\r\n\rX` instead of the required `\r\n\r\n`.
This inconsistency enables request smuggling, allowing attackers to bypass proxy-based access controls and submit unauthorized requests.

The issue was resolved by upg...  

### 11. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r12  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 12. CVE-2025-46394

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r12  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 13. CVE-2025-46394

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r12  
**Description:** In tar in BusyBox through 1.37.0, a TAR archive can have filenames hidden from a listing through the use of terminal escape sequences....  

### 14. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox @ 1.37.0-r12  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 15. CVE-2024-58251

**Severity:** LOW  
**Package:** busybox-binsh @ 1.37.0-r12  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 16. CVE-2024-58251

**Severity:** LOW  
**Package:** ssl_client @ 1.37.0-r12  
**Description:** In netstat in BusyBox through 1.37.0, local users can launch of network application with an argv[0] containing an ANSI terminal escape sequence, leading to a denial of service (terminal locked up) when netstat is used by a victim....  

### 17. CVE-2025-5889

**Severity:** LOW  
**Package:** brace-expansion @ 2.0.1  
**Description:** brace-expansion Regular Expression Denial of Service vulnerability...  

