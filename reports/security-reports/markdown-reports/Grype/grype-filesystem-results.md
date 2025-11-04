# Grype Security Report

**Scan Type:** grype-filesystem-results  
**Generated:** Mon Nov  3 16:31:46 CST 2025  

## Summary

**Total Vulnerabilities:** 20

### Severity Breakdown

- **Critical:** 0
- **High:** 4
- **Medium:** 14
- **Low:** 2

## Top Vulnerabilities

### 1. CVE-2025-61725

**Severity:** HIGH  
**Package:** stdlib @ go1.23.12  
**Description:** The ParseAddress function constructeds domain-literal address components through repeated string concatenation. When parsing large domain-literal components, this can cause excessive CPU consumption....  

### 2. CVE-2025-61725

**Severity:** HIGH  
**Package:** stdlib @ go1.23.12  
**Description:** The ParseAddress function constructeds domain-literal address components through repeated string concatenation. When parsing large domain-literal components, this can cause excessive CPU consumption....  

### 3. CVE-2025-47912

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: "http://[::1]/". IPv4 addresses and hostnames must...  

### 4. CVE-2025-47912

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The Parse function permits values other than IPv6 addresses to be included in square brackets within the host component of a URL. RFC 3986 permits IPv6 addresses to be included within the host component, enclosed within square brackets. For example: "http://[::1]/". IPv4 addresses and hostnames must...  

### 5. CVE-2025-58186

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does not have a limit. By sending a lot of very small cookies such as "a=;", an attacker can make an HTTP server allocate a large amount of structs, causing large memory consumption....  

### 6. CVE-2025-58186

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Despite HTTP headers having a default limit of 1MB, the number of cookies that can be parsed does not have a limit. By sending a lot of very small cookies such as "a=;", an attacker can make an HTTP server allocate a large amount of structs, causing large memory consumption....  

### 7. CVE-2025-61724

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The Reader.ReadResponse function constructs a response string through repeated string concatenation of lines. When the number of lines in a response is large, this can cause excessive CPU consumption....  

### 8. CVE-2025-61724

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The Reader.ReadResponse function constructs a response string through repeated string concatenation of lines. When the number of lines in a response is large, this can cause excessive CPU consumption....  

### 9. CVE-2025-58188

**Severity:** HIGH  
**Package:** stdlib @ go1.23.12  
**Description:** Validating certificate chains which contain DSA public keys can cause programs to panic, due to a interface cast that assumes they implement the Equal method. This affects programs which validate arbitrary certificate chains....  

### 10. CVE-2025-58188

**Severity:** HIGH  
**Package:** stdlib @ go1.23.12  
**Description:** Validating certificate chains which contain DSA public keys can cause programs to panic, due to a interface cast that assumes they implement the Equal method. This affects programs which validate arbitrary certificate chains....  

### 11. CVE-2025-61723

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input. This affects programs which parse untrusted PEM inputs....  

### 12. CVE-2025-61723

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input. This affects programs which parse untrusted PEM inputs....  

### 13. CVE-2025-58189

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped....  

### 14. CVE-2025-58189

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped....  

### 15. CVE-2025-58185

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion....  

### 16. CVE-2025-58185

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion....  

### 17. CVE-2025-58187

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Due to the design of the name constraint checking algorithm, the processing time of some inputs scals non-linearly with respect to the size of the certificate. This affects programs which validate arbitrary certificate chains....  

### 18. CVE-2025-58187

**Severity:** MEDIUM  
**Package:** stdlib @ go1.23.12  
**Description:** Due to the design of the name constraint checking algorithm, the processing time of some inputs scals non-linearly with respect to the size of the certificate. This affects programs which validate arbitrary certificate chains....  

### 19. CVE-2025-58183

**Severity:** LOW  
**Package:** stdlib @ go1.23.12  
**Description:** tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0 sparse files. A maliciously-crafted archive containing a large number of sparse regions can cause a Reader to read an unbounded amount of data from the archive into memory. When reading from a compre...  

### 20. CVE-2025-58183

**Severity:** LOW  
**Package:** stdlib @ go1.23.12  
**Description:** tar.Reader does not set a maximum size on the number of sparse region data blocks in GNU tar pax 1.0 sparse files. A maliciously-crafted archive containing a large number of sparse regions can cause a Reader to read an unbounded amount of data from the archive into memory. When reading from a compre...  

