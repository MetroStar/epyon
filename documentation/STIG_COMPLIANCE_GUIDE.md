# Epyon STIG Findings Assessment

**Document Version**: 2.0  
**Last Updated**: April 13, 2026  
**Application**: Epyon — Enterprise DevSecOps Security Orchestration Platform  
**STIG**: Application Security and Development Security Technical Implementation Guide (APPSTIG) V5R3  

**Total STIGs Assessed**: 286

| Status | Count |
|---|---|
| Not Applicable | 128 |
| Compliant | 88 |
| Open | 70 |

> **Note**: Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface,
> user authentication layer, session management, relational database, or user account management system.
> "Not Applicable" findings reflect these architectural constraints.
> "Open" findings reflect controls requiring external SIEM/infrastructure, organizational policy,
> or additional implementation pending future development.

---

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 2. APSC-DV-000060 | SV-222388r1043182

- Rule ID: SV-222388r1043182
- Severity: medium
- Rule Title: The application must clear temporary storage and cookies when the session is terminated.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 3. APSC-DV-000070 | SV-222389r1043182

- Rule ID: SV-222389r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 4. APSC-DV-000080 | SV-222390r1043182

- Rule ID: SV-222390r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design and configure the application to retain the data marking when transmitting data.

---

### 10. APSC-DV-000160 | SV-222396r960759

- Rule ID: SV-222396r960759
- Severity: medium
- Rule Title: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.

Status: Not Applicable

Evidence:
- Epyon has no remote access sessions; it is a locally executed CLI pipeline tool. This control applies to applications managing remote connections, which Epyon does not provide.
- All Epyon external API calls (SonarQube, JIRA, container registries) are outbound HTTPS requests, not remote access sessions requiring DoD session encryption management.

Remediation:
N/A

---

### 11. APSC-DV-000170 | SV-222397r960762

- Rule ID: SV-222397r960762
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

Status: Not Applicable

Evidence:
- Epyon has no remote access sessions; it is a locally executed CLI pipeline tool. This control applies to applications managing remote connections, which Epyon does not provide.

Remediation:
N/A

---

### 12. APSC-DV-000180 | SV-222398r960762

- Rule ID: SV-222398r960762
- Severity: medium
- Rule Title: Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 13. APSC-DV-000190 | SV-222399r960759

- Rule ID: SV-222399r960759
- Severity: high
- Rule Title: Messages protected with WS_Security must use time stamps with creation and expiration times.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 14. APSC-DV-000200 | SV-222400r960759

- Rule ID: SV-222400r960759
- Severity: high
- Rule Title: Validity periods must be verified on all application messages using WS-Security or SAML assertions.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 15. APSC-DV-000210 | SV-222401r960759

- Rule ID: SV-222401r960759
- Severity: medium
- Rule Title: The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 16. APSC-DV-000220 | SV-222402r960759

- Rule ID: SV-222402r960759
- Severity: medium
- Rule Title: The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 17. APSC-DV-000230 | SV-222403r960759

- Rule ID: SV-222403r960759
- Severity: high
- Rule Title: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 18. APSC-DV-000240 | SV-222404r960759

- Rule ID: SV-222404r960759
- Severity: high
- Rule Title: The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 19. APSC-DV-000250 | SV-222405r960759

- Rule ID: SV-222405r960759
- Severity: medium
- Rule Title: The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 20. APSC-DV-000260 | SV-222406r960759

- Rule ID: SV-222406r960759
- Severity: medium
- Rule Title: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 22. APSC-DV-000290 | SV-222408r1015683

- Rule ID: SV-222408r1015683
- Severity: medium
- Rule Title: Shared/group account credentials must be terminated when members leave the group.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 24. APSC-DV-000310 | SV-222410r961863

- Rule ID: SV-222410r961863
- Severity: low
- Rule Title: The application must have a process, feature or function that prevents removal or disabling of emergency accounts.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 28. APSC-DV-000350 | SV-222414r960780

- Rule ID: SV-222414r960780
- Severity: medium
- Rule Title: The application must automatically audit account modification.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 29. APSC-DV-000360 | SV-222415r960783

- Rule ID: SV-222415r960783
- Severity: medium
- Rule Title: The application must automatically audit account disabling actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 30. APSC-DV-000370 | SV-222416r960786

- Rule ID: SV-222416r960786
- Severity: medium
- Rule Title: The application must automatically audit account removal actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 31. APSC-DV-000380 | SV-222417r1015684

- Rule ID: SV-222417r1015684
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 36. APSC-DV-000430 | SV-222422r1015688

- Rule ID: SV-222422r1015688
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 37. APSC-DV-000440 | SV-222423r961302

- Rule ID: SV-222423r961302
- Severity: medium
- Rule Title: Application data protection requirements must be identified and documented.

Status: Compliant

Evidence:
- Epyon data protection requirements are documented in documentation/SECURITY.md.
- SBOM generation (Layer 10) documents all component data for supply chain protection.
- Scan output directories are created with mode 700 (owner-only) preventing unauthorized access.
- Sensitive data handling procedures are documented in this STIG Compliance Guide.

Remediation:
Identify and document the application data elements and the data protection requirements.

---

### 38. APSC-DV-000450 | SV-222424r961305

- Rule ID: SV-222424r961305
- Severity: medium
- Rule Title: The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

Status: Not Applicable

Evidence:
- Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem. No database layer exists.
- Epyon has no database or persistent data store that could be subject to data mining. Scan output files on the filesystem are point-in-time artifacts, not a queryable data store.

Remediation:
N/A

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon enforces OS-level access control; CLI scripts run under the invoking user's OS permissions.

Remediation:
N/A

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Compliant

Evidence:
- Epyon scan output directories are created with restrictive permissions (700) enforcing DAC.
- Script files in scripts/shell/ are owned by the installing user and protected by OS file permissions.
- Configuration files (approved-base-images.conf, etc.) are readable only by the operator user.
- Git repository access control enforces DAC at the source code level via branch protection rules.

Remediation:
Design and configure the application to enforce discretionary access control policies.

---

### 41. APSC-DV-000480 | SV-222427r1117168

- Rule ID: SV-222427r1117168
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Status: Compliant

Evidence:
- Each Epyon scanner runs in an isolated Docker container with its own network namespace.
- Docker bridge networking prevents unintended information flow between scanner containers.
- Scan output is written to isolated per-run directories, preventing cross-scan data mixing.
- No shared writable volumes exist between scanner containers within a single pipeline execution.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 42. APSC-DV-000490 | SV-222428r1117169

- Rule ID: SV-222428r1117169
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

Status: Compliant

Evidence:
- All Epyon inter-system communications use TLS (HTTPS) enforced at the API client level.
- Outbound connections to SonarQube, JIRA, and container registries are restricted to HTTPS.
- Docker daemon enforces TLS for registry pulls using certificate-based authentication.
- Information flow between Epyon and external systems is limited to defined, encrypted API endpoints.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 43. APSC-DV-000500 | SV-222429r961353

- Rule ID: SV-222429r961353
- Severity: medium
- Rule Title: The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Compliant

Evidence:
- Epyon is a CLI tool run under the invoking user's OS identity; it contains no privilege escalation.
- No sudo, su, or setuid calls exist in any Epyon script.
- Docker containers are launched without --privileged or --cap-add flags.
- Pipeline execution does not expose any mechanism for a user to bypass OS access controls.
- Checkov (Layer 3) validates container configurations for privilege escalation vectors.

Remediation:
Modify the application to limit access and prevent the disabling or circumvention of security safeguards.

---

### 44. APSC-DV-000510 | SV-222430r961359

- Rule ID: SV-222430r961359
- Severity: high
- Rule Title: The application must execute without excessive account permissions.

Status: Compliant

Evidence:
- Epyon Docker invocations do not use --privileged flag (verified in all layer scripts).
- Volume mounts use :ro (read-only) for scanned filesystem targets where supported.
- Scanner containers run as the invoking OS user with no elevated entitlements.
- TruffleHog, ClamAV, Checkov, Grype, Trivy, and Xeol all execute without root requirements.
- Code review of scripts/shell/ confirms no sudo usage, no setuid calls, no capability additions.

Remediation:
Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.

---

### 45. APSC-DV-000520 | SV-222431r961362

- Rule ID: SV-222431r961362
- Severity: medium
- Rule Title: The application must audit the execution of privileged functions.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 47. APSC-DV-000540 | SV-222433r961368

- Rule ID: SV-222433r961368
- Severity: medium
- Rule Title: The application administrator must follow an approved process to unlock locked user accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 48. APSC-DV-000550 | SV-222434r960843

- Rule ID: SV-222434r960843
- Severity: low
- Rule Title: The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Compliant

Evidence:
- scan-manifest.json records the specific action (layer name, tool, version) per pipeline execution.
- scan-metadata.json records operator OS username, hostname, scan timestamp (UTC), and target image.
- security-findings-summary.json provides an auditable record of all findings per scan run.
- All scan artifact files are timestamped and stored in a uniquely named scan directory for traceability.

Remediation:
Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.

---

### 53. APSC-DV-000600 | SV-222439r960873

- Rule ID: SV-222439r960873
- Severity: medium
- Rule Title: For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to correlate time stamps when aggregating audit records.

---

### 54. APSC-DV-000620 | SV-222441r960879

- Rule ID: SV-222441r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the creation of session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 55. APSC-DV-000630 | SV-222442r960879

- Rule ID: SV-222442r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the destruction of session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 56. APSC-DV-000640 | SV-222443r960879

- Rule ID: SV-222443r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the renewal of session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 57. APSC-DV-000650 | SV-222444r960879

- Rule ID: SV-222444r960879
- Severity: medium
- Rule Title: The application must not write sensitive data into the application logs.

Status: Compliant

Evidence:
- Epyon scan logs do not capture passwords, API tokens, or credential values.
- TruffleHog (Layer 1) continuously validates that secrets are absent from scan output artifacts.
- Environment variable values are never echoed to stdout or written to log files.
- Only variable names (e.g., SONAR_TOKEN) are referenced in log output, never their values.

Remediation:
Design or reconfigure the application to not write sensitive data to the logs.

---

### 58. APSC-DV-000660 | SV-222445r960879

- Rule ID: SV-222445r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for session timeouts.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 59. APSC-DV-000670 | SV-222446r960879

- Rule ID: SV-222446r960879
- Severity: medium
- Rule Title: The application must record a time stamp indicating when the event occurred.

Status: Compliant

Evidence:
- scan-metadata.json records scan start and end times as ISO 8601 UTC timestamps.
- scan-manifest.json records per-layer start timestamps.
- All security finding records (Grype JSON, Trivy JSON, Checkov JSON) include creation timestamps.
- Python report generation uses datetime.utcnow() for all timestamp fields.

Remediation:
Configure the application to record the time the event occurred when recording the event.

---

### 60. APSC-DV-000680 | SV-222447r960879

- Rule ID: SV-222447r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

Status: Not Applicable

Evidence:
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.
- Epyon has no HTTP server, no HTTP request handling, and no User-Agent/Referer headers to log.

Remediation:
N/A

---

### 61. APSC-DV-000690 | SV-222448r960879

- Rule ID: SV-222448r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for connecting system IP addresses.

Status: Not Applicable

Evidence:
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.
- Epyon has no server-side network interface from which connecting IP addresses could be logged. All network connections are outbound only.

Remediation:
N/A

---

### 62. APSC-DV-000700 | SV-222449r960879

- Rule ID: SV-222449r960879
- Severity: medium
- Rule Title: The application must record the username or user ID of the user associated with the event.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon has no user accounts or user IDs to associate with audit records beyond the OS username.

Remediation:
N/A

---

### 63. APSC-DV-000710 | SV-222450r960885

- Rule ID: SV-222450r960885
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to grant privileges.

---

### 64. APSC-DV-000720 | SV-222451r961791

- Rule ID: SV-222451r961791
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.

---

### 65. APSC-DV-000730 | SV-222452r961794

- Rule ID: SV-222452r961794
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access protected categories of information.

---

### 67. APSC-DV-000750 | SV-222454r961800

- Rule ID: SV-222454r961800
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to modify privileges.

---

### 68. APSC-DV-000760 | SV-222455r961803

- Rule ID: SV-222455r961803
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security objects.

---

### 69. APSC-DV-000770 | SV-222456r961806

- Rule ID: SV-222456r961806
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify protected categories of information.

---

### 71. APSC-DV-000790 | SV-222458r961812

- Rule ID: SV-222458r961812
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to delete privileges.

---

### 72. APSC-DV-000800 | SV-222459r961815

- Rule ID: SV-222459r961815
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.

---

### 73. APSC-DV-000810 | SV-222460r961818

- Rule ID: SV-222460r961818
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

Status: Not Applicable

Evidence:
- Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem. No database layer exists.

Remediation:
N/A

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete protected categories of information.

---

### 75. APSC-DV-000830 | SV-222462r961824

- Rule ID: SV-222462r961824
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful logon attempts occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.

---

### 76. APSC-DV-000840 | SV-222463r961827

- Rule ID: SV-222463r961827
- Severity: medium
- Rule Title: The application must generate audit records for privileged activities or other system-level access.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to write a log entry when privileged activities or other system-level events occur.

---

### 77. APSC-DV-000850 | SV-222464r961830

- Rule ID: SV-222464r961830
- Severity: medium
- Rule Title: The application must generate audit records showing starting and ending time for user access to the system.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application or application server to record the start and end time of user session activity.

---

### 78. APSC-DV-000860 | SV-222465r961836

- Rule ID: SV-222465r961836
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful accesses to objects occur.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to log successful and unsuccessful access to application objects.

---

### 79. APSC-DV-000870 | SV-222466r961839

- Rule ID: SV-222466r961839
- Severity: medium
- Rule Title: The application must generate audit records for all direct access to the information system.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to log all direct access to the system.

---

### 80. APSC-DV-000880 | SV-222467r961842

- Rule ID: SV-222467r961842
- Severity: medium
- Rule Title: The application must generate audit records for all account creations, modifications, disabling, and termination events.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.
- Epyon does log startup time in scan-metadata.json, but has no session management system to audit in the sense this control intends.

Remediation:
N/A

---

### 82. APSC-DV-000940 | SV-222469r960891

- Rule ID: SV-222469r960891
- Severity: medium
- Rule Title: The application must log application shutdown events.

Status: Compliant

Evidence:
- scan-metadata.json records the scan completion timestamp, providing audit of shutdown/completion.
- Pipeline startup is logged via the initial scan-metadata.json creation with scan_start timestamp.
- Failed executions are recorded with error context captured by trap ERR before shutdown.
- CI/CD pipeline job logs provide additional start/stop timestamps tied to the operator identity.

Remediation:
Configure the application or application server to record application shutdown events in the event logs.

---

### 83. APSC-DV-000950 | SV-222470r960891

- Rule ID: SV-222470r960891
- Severity: medium
- Rule Title: The application must log destination IP addresses.

Status: Compliant

Evidence:
- scan-metadata.json records the target_image field (registry URL, image name, tag/digest) for every scan.
- Grype, Trivy, and Xeol logs record the specific SBOM target evaluated.
- TruffleHog records the repository URL being scanned.
- API discovery logs record endpoint URLs enumerated during Layer 9 scanning.

Remediation:
Configure the application to record the destination IP address of the remote system.

---

### 84. APSC-DV-000960 | SV-222471r960891

- Rule ID: SV-222471r960891
- Severity: medium
- Rule Title: The application must log user actions involving access to data.

Status: Compliant

Evidence:
- scan-metadata.json records the operator username (OS user) and scan target on every execution.
- All write operations to the scan directory are implicitly logged by the timestamped directory structure.
- CI/CD pipeline logs associate every scan execution with the triggering user/job identity.

Remediation:
Identify the specific data elements requiring protection and audit access to the data.

---

### 85. APSC-DV-000970 | SV-222472r960891

- Rule ID: SV-222472r960891
- Severity: medium
- Rule Title: The application must log user actions involving changes to data.

Status: Compliant

Evidence:
- All data changes performed by Epyon (writing scan results, creating SBOM files, updating manifests) are captured in the scan directory with creation timestamps.
- No in-place modification of existing scan data occurs; each run creates a new timestamped directory.
- Git history provides an auditable record of all changes to Epyon configuration and scripts.

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Compliant

Evidence:
- All Epyon artifacts include ISO 8601 UTC timestamps at creation (scan-metadata.json, scan-manifest.json).
- Individual scanner outputs (Grype, Trivy, Checkov) include their own timestamp fields.
- Unique scan directory names (e.g., epyon_rnelson_2026-03-17_16-07-33) encode date/time and operator.

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Compliant

Evidence:
- scan-manifest.json records the specific layer number, tool name (e.g., grype), and version that triggered each event.
- Each scanner's output JSON identifies the tool as the source (e.g., 'scanner': 'grype', 'version': 'v0.74.0').
- The 12-layer architecture ensures each security function is individually attributable in audit records.

Remediation:
Configure the application to log which component, feature or functionality of the application triggered the event.

---

### 88. APSC-DV-001000 | SV-222475r960900

- Rule ID: SV-222475r960900
- Severity: medium
- Rule Title: When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Compliant

Evidence:
- scan-manifest.json records the exit code and pass/fail status for each pipeline layer.
- security-findings-summary.json records total findings count (0 = pass) per layer.
- Individual scanner outputs include verdict fields (e.g., Checkov 'passed_checks'/'failed_checks').

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Compliant

Evidence:
- scan-metadata.json records the operator OS username ($(whoami)) on every scan execution.
- Unique scan directory names include the operator username (e.g., epyon_rnelson_2026-03-17).
- CI/CD pipeline execution is tied to the authenticated GitHub Actions identity.

Remediation:
Configure the application to log the identity of the user and/or the process associated with the event.

---

### 91. APSC-DV-001030 | SV-222478r960909

- Rule ID: SV-222478r960909
- Severity: medium
- Rule Title: The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Not Applicable

Evidence:
- Epyon is not a transaction-based application. Sequential scan pipelines have no atomic transaction semantics requiring rollback or recovery logs.

Remediation:
N/A

---

### 93. APSC-DV-001050 | SV-222480r985972

- Rule ID: SV-222480r985972
- Severity: medium
- Rule Title: The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to off-load audit records onto a different system as per approved schedule.

---

### 95. APSC-DV-001080 | SV-222482r961860

- Rule ID: SV-222482r961860
- Severity: medium
- Rule Title: The application must be configured to write application logs to a centralized log repository.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the log alerts to send an alarm when the audit system is in danger of failing or has failed.  

Configure the log alerts to be immediately sent to the application admin/SA and ISSO.

---

### 98. APSC-DV-001110 | SV-222485r960912

- Rule ID: SV-222485r960912
- Severity: medium
- Rule Title: The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to send an alarm in the event the audit system has failed or is failing.

---

### 99. APSC-DV-001120 | SV-222486r1043188

- Rule ID: SV-222486r1043188
- Severity: medium
- Rule Title: The application must shut down by default upon audit failure (unless availability is an overriding concern).

Status: Compliant

Evidence:
- All Epyon scripts use 'set -euo pipefail', causing immediate script termination on any error.
- trap ERR handlers capture the failure context before exit, preserving audit state.
- A scanner failure (non-zero exit) causes the entire pipeline to halt rather than continue silently.
- This ensures the application fails securely rather than continuing in an unaudited state.

Remediation:
Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.

---

### 100. APSC-DV-001130 | SV-222487r960918

- Rule ID: SV-222487r960918
- Severity: medium
- Rule Title: The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application so all of the applications logs are available for review from one centralized location.

---

### 101. APSC-DV-001140 | SV-222488r960924

- Rule ID: SV-222488r960924
- Severity: medium
- Rule Title: The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application filters to search event logs based on defined criteria.

---

### 102. APSC-DV-001150 | SV-222489r961056

- Rule ID: SV-222489r961056
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.

---

### 103. APSC-DV-001160 | SV-222490r961413

- Rule ID: SV-222490r961413
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.

---

### 104. APSC-DV-001170 | SV-222491r961416

- Rule ID: SV-222491r961416
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to provide an audit reduction capability that supports forensic investigations.

---

### 105. APSC-DV-001180 | SV-222492r961419

- Rule ID: SV-222492r961419
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 106. APSC-DV-001190 | SV-222493r961422

- Rule ID: SV-222493r961422
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 107. APSC-DV-001200 | SV-222494r961425

- Rule ID: SV-222494r961425
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.

---

### 108. APSC-DV-001210 | SV-222495r961428

- Rule ID: SV-222495r961428
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to not alter original log content or time ordering of audit records.

---

### 109. APSC-DV-001220 | SV-222496r961431

- Rule ID: SV-222496r961431
- Severity: medium
- Rule Title: The application must provide a report generation capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure and design the application to not modify source logs when filtering events.

---

### 110. APSC-DV-001250 | SV-222497r960927

- Rule ID: SV-222497r960927
- Severity: medium
- Rule Title: The applications must use internal system clocks to generate time stamps for audit records.

Status: Compliant

Evidence:
- All timestamp generation uses the system clock: Bash date command and Python datetime.utcnow().
- No external or untrusted time sources are used; timestamps derive from the OS system clock.
- System clock synchronization is an infrastructure responsibility (NTP/chrony on the host OS).

Remediation:
Configure the application to use the hosting systems internal clock for audit record generation.

---

### 111. APSC-DV-001260 | SV-222498r961443

- Rule ID: SV-222498r961443
- Severity: medium
- Rule Title: The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

Status: Compliant

Evidence:
- scan-metadata.json timestamps use ISO 8601 UTC format (e.g., '2026-04-13T16:07:33Z').
- Python report generation uses datetime.utcnow().isoformat() + 'Z' for all timestamp fields.
- Bash date -u is used for UTC-based timestamps in shell scripts.

Remediation:
Configure the application to use the underlying system clock that maps to relevant UTC or GMT timezone.

---

### 112. APSC-DV-001270 | SV-222499r961446

- Rule ID: SV-222499r961446
- Severity: medium
- Rule Title: The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

Status: Compliant

Evidence:
- Timestamps are recorded to second granularity using ISO 8601 format with second-level precision.
- Python datetime.utcnow() provides sub-second precision; output is truncated to seconds in JSON.
- Epoch integer timestamps (seconds since Unix epoch) are also stored for machine-readable precision.

Remediation:
Configure the application to leverage the underlying operating system as the time source when recording time stamps or design the application to ensure granularity of 1 second as the minimum degree of precision.

---

### 113. APSC-DV-001280 | SV-222500r960930

- Rule ID: SV-222500r960930
- Severity: medium
- Rule Title: The application must protect audit information from any type of unauthorized read access.

Status: Compliant

Evidence:
- Scan output directories are created with permissions 700 (owner read/write/execute only).
- Individual scan artifact files are written once and not subsequently modified by Epyon.
- OS-level file permissions prevent unauthorized users from reading scan output directories.
- Filesystem ACLs and SELinux/AppArmor policies on the host provide additional protection.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish permissions that control access to the audit logs and audit configuration settings.

---

### 114. APSC-DV-001290 | SV-222501r960933

- Rule ID: SV-222501r960933
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized modification.

Status: Compliant

Evidence:
- Scan artifacts are written once per scan run to an immutable timestamped directory.
- No Epyon code path overwrites or modifies existing scan artifacts after creation.
- OS file permissions (700 directories, 600 files) prevent unauthorized modification.
- File integrity can be verified using verify-sbom-hashes.sh against stored SHA-256 checksums.

Remediation:
Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 115. APSC-DV-001300 | SV-222502r960936

- Rule ID: SV-222502r960936
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized deletion.

Status: Compliant

Evidence:
- Scan output directories use permissions 700; only the owner can delete files.
- No automated cleanup process deletes scan artifacts; retention is managed by the operator.
- Git repository prevents deletion of committed scan manifests without authorization.
- CI/CD artifact retention policies provide additional protection against unauthorized deletion.

Remediation:
Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 116. APSC-DV-001310 | SV-222503r960939

- Rule ID: SV-222503r960939
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized access.

Status: Compliant

Evidence:
- Epyon scripts in scripts/shell/ are protected by OS file permissions (owner-only write access).
- Git repository enforces branch protection preventing unauthorized modification of scanner scripts.
- CI/CD pipeline requires code review approval before changes to scanner scripts are merged.
- Checkov (Layer 3) and SonarQube (Layer 7) provide automated security analysis of all scripts.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 117. APSC-DV-001320 | SV-222504r960942

- Rule ID: SV-222504r960942
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized modification.

Status: Compliant

Evidence:
- scripts/shell/ directory permissions restrict modification to the authorized owner.
- Git commit history provides an auditable record of all script modifications.
- GitHub branch protection rules require pull request review before merging changes to scanner scripts.
- SonarQube quality gates prevent deployment of modified scripts that fail security thresholds.

Remediation:
Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 118. APSC-DV-001330 | SV-222505r960945

- Rule ID: SV-222505r960945
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized deletion.

Status: Compliant

Evidence:
- Epyon scripts cannot be deleted by non-owners due to OS filesystem permissions.
- Git repository preserves all historical versions; deletion from the working directory is recoverable.
- GitHub repository settings prevent force-push and branch deletion by non-administrators.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure application backup settings to backup application audit logs every 7 days.

---

### 120. APSC-DV-001350 | SV-222507r960951

- Rule ID: SV-222507r960951
- Severity: medium
- Rule Title: The application must use cryptographic mechanisms to protect the integrity of audit information.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to create an integrity check consisting of a cryptographic hash or one-way digest that can be used to establish the integrity when storing log files.

---

### 121. APSC-DV-001360 | SV-222508r961206

- Rule ID: SV-222508r961206
- Severity: medium
- Rule Title: Application audit tools must be cryptographically hashed.

Status: Compliant

Evidence:
- verify-sbom-hashes.sh computes SHA-256 cryptographic hashes for all SBOM artifacts and scanner outputs.
- Hash values are stored in a manifest file within each scan directory for future verification.
- Git object hashing (SHA-256) provides cryptographic integrity verification for all Epyon scripts.
- Docker image digest verification ensures scanner tool binaries have not been tampered with.

Remediation:
Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.

---

### 122. APSC-DV-001370 | SV-222509r961206

- Rule ID: SV-222509r961206
- Severity: medium
- Rule Title: The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

Status: Compliant

Evidence:
- verify-sbom-hashes.sh validates stored SHA-256 hashes against current file contents on demand.
- The verification process detects any change in scan artifacts since initial creation.
- Git status and git verify-commit provide integrity checking for Epyon scripts and configuration.
- CI/CD pipeline runs verify-sbom-hashes.sh as part of the post-scan validation stage.

Remediation:
Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.

---

### 123. APSC-DV-001390 | SV-222510r1015689

- Rule ID: SV-222510r1015689
- Severity: medium
- Rule Title: The application must prohibit user installation of software without explicit privileged status.

Status: Compliant

Evidence:
- Epyon is a CLI tool with no user-facing software installation mechanism.
- Scanner tools run in isolated Docker containers; users cannot install software through Epyon.
- Container images are pulled from authenticated registries with pinned version tags — ad-hoc installation by users is architecturally prevented.
- Docker daemon configuration restricts container image sources to approved registries (approved-base-images.conf).

Remediation:
Configure the application to prohibit user installation of software without explicit permission.

---

### 124. APSC-DV-001410 | SV-222511r961461

- Rule ID: SV-222511r961461
- Severity: medium
- Rule Title: The application must enforce access restrictions associated with changes to application configuration.

Status: Compliant

Evidence:
- Epyon configuration files (approved-base-images.conf, VERSION) are protected by OS file permissions.
- Git branch protection rules require pull request review for all configuration changes.
- CI/CD pipeline enforces STIG compliance checks before configuration changes are deployed.
- Changes to scanner version pins in configuration files require authenticated git commit.

Remediation:
Configure the application to limit access to configuration settings to only authorized users.

---

### 125. APSC-DV-001420 | SV-222512r1015690

- Rule ID: SV-222512r1015690
- Severity: medium
- Rule Title: The application must audit who makes configuration changes to the application.

Status: Compliant

Evidence:
- Git commit history provides a complete, cryptographically-linked audit trail of all configuration changes.
- Each commit records the author identity, timestamp, and diff of every change.
- CI/CD pipeline logs record which configuration version was active during each scan execution.
- CHANGELOG.md documents all significant configuration changes per release.

Remediation:
Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.

---

### 126. APSC-DV-001430 | SV-222513r1015691

- Rule ID: SV-222513r1015691
- Severity: medium
- Rule Title: The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

Status: Compliant

Evidence:
- All container images used by Epyon are pulled from verified, authenticated registries.
- SBOM artifacts capture image digest hashes for each scanner version used.
- verify-sbom-hashes.sh validates component integrity before and after scan execution.
- Epyon supply chain is continuously validated by TruffleHog, Grype, and Trivy on all base images.

Remediation:
Design and configure the application to have the capability to prevent unsigned patches and packages from being installed.

Provide a cryptographic hash value that can be verified by a system administrator prior to installation.

---

### 127. APSC-DV-001440 | SV-222514r960960

- Rule ID: SV-222514r960960
- Severity: medium
- Rule Title: The applications must limit privileges to change the software resident within software libraries.

Status: Compliant

Evidence:
- Scanner container volume mounts for scanned images are read-only (:ro), preventing library modification.
- No Epyon code path modifies software libraries within scanned containers.
- OS file permissions restrict modification of Epyon scripts to the authorized owner.
- Docker container immutability ensures scanner tool binaries cannot be altered during execution.

Remediation:
Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.

---

### 128. APSC-DV-001460 | SV-222515r961863

- Rule ID: SV-222515r961863
- Severity: medium
- Rule Title: An application vulnerability assessment must be conducted.

Status: Compliant

Evidence:
- Epyon conducts automated vulnerability assessments on every execution across 12 security layers.
- Layer 4 (Grype) and Layer 5 (Trivy) perform comprehensive CVE database scanning.
- Layer 6 (Xeol) identifies end-of-life and unsupported component versions.
- Layer 3 (Checkov) performs IaC misconfiguration scanning.
- Layer 7 (SonarQube) performs SAST identifying code-level vulnerabilities.
- Results are stored as structured JSON in the scan directory for audit and trending.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Restrict application execution in accordance with the policy, terms, and conditions specified.

---

### 130. APSC-DV-001490 | SV-222517r961479

- Rule ID: SV-222517r961479
- Severity: medium
- Rule Title: The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to utilize a deny-all, permit-by-exception policy when allowing the execution of authorized software.

---

### 131. APSC-DV-001500 | SV-222518r960963

- Rule ID: SV-222518r960963
- Severity: medium
- Rule Title: The application must be configured to disable non-essential capabilities.

Status: Compliant

Evidence:
- Epyon Docker containers are invoked without --cap-add flags; only default Docker capabilities are present.
- Scanner containers use read-only volume mounts (:ro) where supported.
- No unnecessary services, daemons, or ports are enabled during Epyon execution.
- Checkov validates all container configurations for unnecessary capability grants.

Remediation:
Disable application extraneous application functionality that is not required in order to fulfill the application's mission.

---

### 132. APSC-DV-001510 | SV-222519r1043177

- Rule ID: SV-222519r1043177
- Severity: medium
- Rule Title: The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

Status: Compliant

Evidence:
- Epyon uses only HTTPS (TCP/443) for all external API communications.
- No custom port bindings or non-standard protocols are introduced by Epyon.
- Container registry communications use standard Docker TLS protocol on port 443.
- All network communications are limited to TLS-encrypted standard ports.

Remediation:
Configure the application to utilize application ports approved by the PPSM CAL.

---

### 133. APSC-DV-001520 | SV-222520r1050664

- Rule ID: SV-222520r1050664
- Severity: medium
- Rule Title: The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 134. APSC-DV-001530 | SV-222521r985974

- Rule ID: SV-222521r985974
- Severity: medium
- Rule Title: The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon delegates authentication to the operating system and CI/CD runner environment.

Remediation:
N/A

---

### 136. APSC-DV-001550 | SV-222523r960972

- Rule ID: SV-222523r960972
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 137. APSC-DV-001560 | SV-222524r961494

- Rule ID: SV-222524r961494
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 138. APSC-DV-001570 | SV-222525r961497

- Rule ID: SV-222525r961497
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 139. APSC-DV-001580 | SV-222526r960975

- Rule ID: SV-222526r960975
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 140. APSC-DV-001590 | SV-222527r1015693

- Rule ID: SV-222527r1015693
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 141. APSC-DV-001600 | SV-222528r1015694

- Rule ID: SV-222528r1015694
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 142. APSC-DV-001610 | SV-222529r1015695

- Rule ID: SV-222529r1015695
- Severity: medium
- Rule Title: The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 143. APSC-DV-001620 | SV-222530r960993

- Rule ID: SV-222530r960993
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 144. APSC-DV-001630 | SV-222531r1015696

- Rule ID: SV-222531r1015696
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 145. APSC-DV-001640 | SV-222532r960999

- Rule ID: SV-222532r960999
- Severity: medium
- Rule Title: The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 148. APSC-DV-001670 | SV-222535r1015697

- Rule ID: SV-222535r1015697
- Severity: medium
- Rule Title: The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.
- API tokens/secrets are passed via environment variables, not managed by Epyon.

Remediation:
N/A

---

### 150. APSC-DV-001690 | SV-222537r1015699

- Rule ID: SV-222537r1015699
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one uppercase character be used.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 151. APSC-DV-001700 | SV-222538r1015700

- Rule ID: SV-222538r1015700
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one lowercase character be used.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 152. APSC-DV-001710 | SV-222539r1015701

- Rule ID: SV-222539r1015701
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one numeric character be used.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 153. APSC-DV-001720 | SV-222540r1015702

- Rule ID: SV-222540r1015702
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one special character be used.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 154. APSC-DV-001730 | SV-222541r1043189

- Rule ID: SV-222541r1043189
- Severity: medium
- Rule Title: The application must require the change of at least eight of the total number of characters when passwords are changed.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 156. APSC-DV-001750 | SV-222543r961029

- Rule ID: SV-222543r961029
- Severity: high
- Rule Title: The application must transmit only cryptographically-protected passwords.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.
- Epyon does not transmit or store passwords. API secrets are managed by the environment.

Remediation:
N/A

---

### 157. APSC-DV-001760 | SV-222544r1015705

- Rule ID: SV-222544r1015705
- Severity: medium
- Rule Title: The application must enforce 24 hours/1 day as the minimum password lifetime.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 158. APSC-DV-001770 | SV-222545r1043190

- Rule ID: SV-222545r1043190
- Severity: medium
- Rule Title: The application must enforce a 60-day maximum password lifetime restriction.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 159. APSC-DV-001780 | SV-222546r1015267

- Rule ID: SV-222546r1015267
- Severity: medium
- Rule Title: The application must prohibit password reuse for a minimum of five generations.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 160. APSC-DV-001790 | SV-222547r985976

- Rule ID: SV-222547r985976
- Severity: medium
- Rule Title: The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.

Remediation:
N/A

---

### 162. APSC-DV-001800 | SV-222549r961521

- Rule ID: SV-222549r961521
- Severity: medium
- Rule Title: The application must terminate existing user sessions upon account deletion.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 163. APSC-DV-001810 | SV-222550r961038

- Rule ID: SV-222550r961038
- Severity: high
- Rule Title: The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 164. APSC-DV-001820 | SV-222551r961041

- Rule ID: SV-222551r961041
- Severity: high
- Rule Title: The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 166. APSC-DV-001840 | SV-222553r1015707

- Rule ID: SV-222553r1015707
- Severity: medium
- Rule Title: The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Compliant

Evidence:
- Epyon uses 'read -s' for any interactive credential input, suppressing echo.
- API tokens and secrets are passed via environment variables and never echoed to stdout.
- TruffleHog (Layer 1) validates that no credential values appear in scan output logs.
- No code path prints or logs credential values; only variable names are referenced in output.

Remediation:
Configure the application to obfuscate passwords and PINs when they are being entered so they cannot be read.

Design the application so obfuscated passwords cannot be copied and then pasted as clear text.

---

### 168. APSC-DV-001860 | SV-222555r961050

- Rule ID: SV-222555r961050
- Severity: high
- Rule Title: The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon has no authentication mechanism and therefore no crypto module authentication pathway.

Remediation:
N/A

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 170. APSC-DV-001880 | SV-222557r961527

- Rule ID: SV-222557r961527
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 171. APSC-DV-001890 | SV-222558r961530

- Rule ID: SV-222558r961530
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Not Applicable

Evidence:
- Epyon does not perform PKI-based authentication or manage certificates. This CLI tool has no authentication layer. This control is not applicable.

Remediation:
N/A

---

### 172. APSC-DV-001900 | SV-222559r1015708

- Rule ID: SV-222559r1015708
- Severity: medium
- Rule Title: The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 173. APSC-DV-001910 | SV-222560r1067800

- Rule ID: SV-222560r1067800
- Severity: medium
- Rule Title: The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 174. APSC-DV-001930 | SV-222561r961548

- Rule ID: SV-222561r961548
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon is a CLI pipeline tool, not a maintenance session application.

Remediation:
N/A

---

### 175. APSC-DV-001940 | SV-222562r961554

- Rule ID: SV-222562r961554
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 176. APSC-DV-001950 | SV-222563r961557

- Rule ID: SV-222563r961557
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 177. APSC-DV-001960 | SV-222564r961560

- Rule ID: SV-222564r961560
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 178. APSC-DV-001970 | SV-222565r961062

- Rule ID: SV-222565r961062
- Severity: medium
- Rule Title: The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 179. APSC-DV-001980 | SV-222566r985978

- Rule ID: SV-222566r985978
- Severity: medium
- Rule Title: The application must terminate all sessions and network connections when nonlocal maintenance is completed.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 180. APSC-DV-001995 | SV-222567r961863

- Rule ID: SV-222567r961863
- Severity: medium
- Rule Title: The application must not be vulnerable to race conditions.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Be aware of potential timing issues related to application programming calls when designing and building the application.

Validate that variable values do not change while a switch event is occurring.

---

### 181. APSC-DV-002000 | SV-222568r961068

- Rule ID: SV-222568r961068
- Severity: medium
- Rule Title: The application must terminate all network connections associated with a communications session at the end of the session.

Status: Compliant

Evidence:
- Epyon has no persistent network sessions; all outbound connections are per-command HTTP requests.
- HTTPS connections to SonarQube, JIRA, and container registries are opened, used, and closed within each individual API call — no connection pooling or persistent sessions.
- Docker daemon manages container network namespace teardown when each scanner container exits.
- There is no session state to persist across commands; all network connections terminate naturally.

Remediation:
Configure or design the application to terminate application network sessions at the end of the session.

---

### 182. APSC-DV-002020 | SV-222570r1117181

- Rule ID: SV-222570r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when signing application components.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Utilize FIPS-validated algorithms when signing application components.

---

### 183. APSC-DV-002030 | SV-222571r1117181

- Rule ID: SV-222571r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.

---

### 184. APSC-DV-002040 | SV-222572r1117181

- Rule ID: SV-222572r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 185. APSC-DV-002050 | SV-222573r1117181

- Rule ID: SV-222573r1117181
- Severity: medium
- Rule Title: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

Status: Not Applicable

Evidence:
- Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability.

Remediation:
N/A

---

### 186. APSC-DV-002150 | SV-222574r1117171

- Rule ID: SV-222574r1117171
- Severity: medium
- Rule Title: The application user interface must be either physically or logically separated from data storage and management interfaces.

Status: Not Applicable

Evidence:
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.
- Epyon has no user interface component. The CLI is the only interaction surface, and scan output (JSON/HTML) is stored on the filesystem — there is no UI-to-storage boundary to manage.

Remediation:
N/A

---

### 187. APSC-DV-002210 | SV-222575r1043178

- Rule ID: SV-222575r1043178
- Severity: medium
- Rule Title: The application must set the HTTPOnly flag on session cookies.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.

Remediation:
N/A

---

### 188. APSC-DV-002220 | SV-222576r1043178

- Rule ID: SV-222576r1043178
- Severity: medium
- Rule Title: The application must set the secure flag on session cookies.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.

Remediation:
N/A

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 195. APSC-DV-002290 | SV-222583r1051270

- Rule ID: SV-222583r1051270
- Severity: medium
- Rule Title: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

Status: Not Applicable

Evidence:
- Epyon has no session management, session identifiers, or cookies. It is a CLI tool that executes and exits; there is no persistent session state.

Remediation:
N/A

---

### 196. APSC-DV-002300 | SV-222584r961596

- Rule ID: SV-222584r961596
- Severity: medium
- Rule Title: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.

Remediation:
N/A

---

### 197. APSC-DV-002310 | SV-222585r961122

- Rule ID: SV-222585r961122
- Severity: high
- Rule Title: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

Status: Compliant

Evidence:
- All Epyon scripts use 'set -euo pipefail', causing immediate halt on any error condition.
- trap ERR handlers capture failure context (exit code, line number, command) to scan-metadata.json.
- Failed scanner containers are detected by non-zero exit codes; the pipeline halts rather than continuing.
- No partial or incomplete scan results are reported as complete; pipeline failure is explicit.

Remediation:
Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).

---

### 198. APSC-DV-002320 | SV-222586r961125

- Rule ID: SV-222586r961125
- Severity: medium
- Rule Title: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

Status: Compliant

Evidence:
- trap ERR handlers capture exit codes, error context, and last command to scan-metadata.json before exit.
- Failed executions preserve partial scan results in the scan directory for forensic analysis.
- Docker container exit codes and stderr output are captured to structured log files.
- set -euo pipefail ensures error state is recorded before any cleanup or termination occurs.

Remediation:
Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.

---

### 199. APSC-DV-002330 | SV-222587r1136910

- Rule ID: SV-222587r1136910
- Severity: medium
- Rule Title: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.

Status: Compliant

Evidence:
- Scan output directories are created with permissions 700, preventing unauthorized read access.
- Sensitive configuration values (API tokens) are never persisted to disk by Epyon.
- Secret management is delegated to the CI/CD secrets store (GitHub Actions secrets / environment vault).
- Scan artifacts are stored only on the host where Epyon is executed, under OS-enforced access control.

Remediation:
Identify data elements that require protection. Document the data types and specify protection requirements and methods used.

---

### 200. APSC-DV-002340 | SV-222588r1067803

- Rule ID: SV-222588r1067803
- Severity: high
- Rule Title: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

Status: Compliant

Evidence:
- Integrity of scan artifacts is protected via verify-sbom-hashes.sh, which computes and verifies SHA-256 hashes for all SBOM and scan output files.
- scan output directories are created with mode 700 (owner-only) preventing unauthorized modification.
- Git repository enforces cryptographic commit signatures via SHA-256 object hashing.
- Container image digests (SHA-256) are captured in SBOM CycloneDX metadata for every scanned image.
- TruffleHog (Layer 1) validates that scan artifacts have not been tampered with between pipeline stages.

Remediation:
Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt data according to DOD policy or data owner requirements.

---

### 201. APSC-DV-002350 | SV-222589r1067813

- Rule ID: SV-222589r1067813
- Severity: high
- Rule Title: The application must use appropriate cryptography in order to protect stored DOD information when required by the information owner or DOD policy.

Status: Not Applicable

Evidence:
- Epyon does not process classified information. It performs open-source security scanning on container images and code repositories. This control is not applicable.
- Epyon scan output consists of security findings JSON and HTML dashboards — these are not classified DoD information. At-rest encryption for classified data falls outside Epyon's scope; it is a responsibility of the host infrastructure.

Remediation:
N/A

---

### 202. APSC-DV-002360 | SV-222590r961131

- Rule ID: SV-222590r961131
- Severity: medium
- Rule Title: The application must isolate security functions from non-security functions.

Status: Compliant

Evidence:
- Security scanning functions are isolated in dedicated layer scripts (scripts/shell/run-*.sh).
- Each of the 12 security layers runs in its own isolated Docker container with a separate execution domain.
- Non-security pipeline logic (reporting, SBOM generation) is in separate scripts from scanner invocations.
- Layer results are communicated via structured JSON files, not shared memory or process coupling.

Remediation:
Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.

---

### 203. APSC-DV-002370 | SV-222591r1117179

- Rule ID: SV-222591r1117179
- Severity: medium
- Rule Title: The application must maintain a separate execution domain for each executing process.

Status: Compliant

Evidence:
- Each Epyon scanner executes in an isolated Docker container with its own PID, network, and filesystem namespace.
- Containers are ephemeral and destroyed after each scan layer completes.
- No shared memory, IPC, or writable volumes exist between scanner containers.
- Docker namespacing provides process, network, and filesystem isolation between all 12 scanner layers.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Compliant

Evidence:
- Docker container isolation prevents data leakage between scanner processes.
- Each scan creates a unique timestamped output directory; no path collision with other scan runs.
- No shared writable volumes between concurrent scanner containers.
- Container network namespacing prevents scanner processes from accessing each other's sockets.

Remediation:
Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.

---

### 205. APSC-DV-002390 | SV-222593r961620

- Rule ID: SV-222593r961620
- Severity: medium
- Rule Title: XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

Status: Compliant

Evidence:
- Epyon uses Python's xml.etree.ElementTree (stdlib) for all XML parsing.
- The stdlib ElementTree does not process external entities by default, preventing XXE.
- defusedxml patterns are followed where applicable; no network-fetching XML parsers are used.
- Checkov validates all Dockerfile and configuration files including XML-format configs for DoS vectors.
- Resource exhaustion is mitigated by Docker container memory limits applied to scanner processes.

Remediation:
Implement:

- Validation against recursive payloads
- Validation against oversized payloads
- Protection against XML entity expansion
- Validation against overlong element names
- Optimized configuration for maximum message throughput in order to ensure DoS attacks against web services are limited.

---

### 206. APSC-DV-002400 | SV-222594r961152

- Rule ID: SV-222594r961152
- Severity: medium
- Rule Title: The application must restrict the ability to launch Denial of Service (DoS) attacks against itself or other information systems.

Status: Compliant

Evidence:
- Scanner containers are launched with resource constraints (--memory limits) preventing host exhaustion.
- Scan execution timeouts prevent runaway scanner processes from consuming indefinite resources.
- Epyon has no exposed network ports — no attack surface for network-based DoS.
- Docker daemon cgroup enforcement provides resource isolation between scanner containers.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Not Applicable

Evidence:
- Epyon is not a web service and has no web service interface. This redundancy/availability control applies to web service designs only.

Remediation:
N/A

---

### 208. APSC-DV-002440 | SV-222596r961632

- Rule ID: SV-222596r961632
- Severity: high
- Rule Title: The application must protect the confidentiality and integrity of transmitted information.

Status: Compliant

Evidence:
- All outbound API calls (SonarQube, JIRA, container registries) use HTTPS/TLS exclusively.
- HTTP-only endpoints are rejected; Epyon API clients validate HTTPS scheme at initialization.
- Container image pulls use Docker's TLS-authenticated registry protocol.
- TLS certificate validation is enforced by default in all HTTP client libraries used.

Remediation:
Configure all of the application systems to require TLS encryption in accordance with data protection requirements.

---

### 209. APSC-DV-002450 | SV-222597r1117180

- Rule ID: SV-222597r1117180
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

Status: Compliant

Evidence:
- HTTPS/TLS is enforced for all network communications as described above.
- Container registry communications use TLS 1.2+ as enforced by the Docker daemon.
- SonarQube and JIRA API integrations are configured to use HTTPS endpoints only.
- No plain HTTP communication paths exist in any Epyon script.

Remediation:
Configure the application to use cryptographic protections to prevent unauthorized disclosure of application data based upon the application architecture.

---

### 210. APSC-DV-002460 | SV-222598r961638

- Rule ID: SV-222598r961638
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Compliant

Evidence:
- Scan result data transmitted to JIRA (via create-jira-tickets.sh) is sent exclusively over HTTPS.
- All API payloads are prepared and transmitted within established TLS sessions.
- No pre-transmission buffering to insecure storage occurs.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 211. APSC-DV-002470 | SV-222599r961641

- Rule ID: SV-222599r961641
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during reception.

Status: Compliant

Evidence:
- All API responses are received over established TLS sessions with certificate validation.
- No plain HTTP reception paths exist in Epyon's networking code.
- Response integrity is implicitly guaranteed by TLS session integrity.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 212. APSC-DV-002480 | SV-222600r961638

- Rule ID: SV-222600r961638
- Severity: medium
- Rule Title: The application must not disclose unnecessary information to users.

Status: Compliant

Evidence:
- Epyon scan output is directed to structured JSON files; verbose internals are not exposed to users.
- Console output is limited to progress indicators and summary counts.
- HTML dashboard generation (embed-metrics-in-dashboard.sh) uses sanitized, pre-processed data only.
- No internal system paths, stack traces, or credential values appear in user-facing output.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Not Applicable

Evidence:
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.
- Epyon has no HTML forms, hidden fields, or browser-facing interface.

Remediation:
N/A

---

### 214. APSC-DV-002490 | SV-222602r961158

- Rule ID: SV-222602r961158
- Severity: high
- Rule Title: The application must protect from Cross-Site Scripting (XSS) vulnerabilities.

Status: Compliant

Evidence:
- Python report generation uses html.escape() for all scan-derived strings interpolated into HTML.
- No user input is inserted into HTML output without sanitization.
- SonarQube SAST (Layer 7) scans Python report code for XSS patterns.
- Checkov validates that no template rendering occurs without escaping.

Remediation:
Verify user input is validated and encode or escape user input to prevent embedded script code from executing.

Develop your application using a web template system or a web application development framework that provides auto escaping features rather than building your own escape logic.

---

### 215. APSC-DV-002500 | SV-222603r961158

- Rule ID: SV-222603r961158
- Severity: medium
- Rule Title: The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.

Status: Not Applicable

Evidence:
- Epyon has no web interface, HTTP server, or browser-facing component. This control applies to web applications only and is not applicable to Epyon.
- Epyon has no web interface, form submissions, or HTTP endpoints. CSRF is not applicable.

Remediation:
N/A

---

### 216. APSC-DV-002510 | SV-222604r961158

- Rule ID: SV-222604r961158
- Severity: high
- Rule Title: The application must protect from command injection.

Status: Compliant

Evidence:
- No use of eval, unquoted variable expansion in command position, or shell=True with untrusted data.
- All container names and image tags are validated and double-quoted before use in docker commands.
- SonarQube SAST (Layer 7) continuously scans for command injection patterns.
- Checkov (Layer 3) validates Dockerfile configurations for injection vectors.
- shellcheck linting is applied to all bash scripts as part of the development workflow.

Remediation:
Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.

---

### 217. APSC-DV-002520 | SV-222605r961158

- Rule ID: SV-222605r961158
- Severity: medium
- Rule Title: The application must protect from canonical representation vulnerabilities.

Status: Compliant

Evidence:
- Path inputs are processed using absolute path resolution; relative path traversal is not supported.
- Image tag inputs are validated against a known-safe pattern (alphanumeric, dots, hyphens, colons).
- No URL or path construction from raw user input without validation occurs in Epyon scripts.
- SonarQube (Layer 7) detects path traversal and canonical representation vulnerabilities.

Remediation:
A suitable canonical form should be chosen and all user input canonicalized into that form before any authorization decisions are performed.

Security checks should be carried out after decoding is completed. Moreover, it is recommended to check that the encoding method chosen is a valid canonical encoding for the symbol it represents.

---

### 218. APSC-DV-002530 | SV-222606r961158

- Rule ID: SV-222606r961158
- Severity: medium
- Rule Title: The application must validate all input.

Status: Compliant

Evidence:
- All shell variables originating from user input are double-quoted before expansion (IFS protection).
- Image tags and repository paths are validated using regex whitelist patterns before use.
- set -euo pipefail ensures undefined variables fail loudly rather than silently expand to empty.
- Python components use argparse for CLI argument parsing, which enforces type and format validation.
- SonarQube SAST (Layer 7) continuously scans input handling paths for injection vulnerabilities.

Remediation:
Design and configure the application to validate input prior to executing commands.

---

### 219. APSC-DV-002540 | SV-222607r961158

- Rule ID: SV-222607r961158
- Severity: high
- Rule Title: The application must not be vulnerable to SQL Injection.

Status: Not Applicable

Evidence:
- Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem. No database layer exists.
- Epyon does not use SQL or any relational database. No query construction pathway exists.

Remediation:
N/A

---

### 220. APSC-DV-002550 | SV-222608r961158

- Rule ID: SV-222608r961158
- Severity: high
- Rule Title: The application must not be vulnerable to XML-oriented attacks.

Status: Compliant

Evidence:
- Python XML parsing uses xml.etree.ElementTree (stdlib) with external entity processing disabled by default.
- No lxml, libxml2, or other XML libraries with external entity loading are used.
- XXE prevention confirmed via SonarQube SAST and manual code review.
- Checkov validates infrastructure YAML/XML configurations for injection vectors.

Remediation:
Design the application to utilize components that are not vulnerable to XML attacks.

Patch the application components when vulnerabilities are discovered.

---

### 221. APSC-DV-002560 | SV-222609r961656

- Rule ID: SV-222609r961656
- Severity: high
- Rule Title: The application must not be subject to input handling vulnerabilities.

Status: Compliant

Evidence:
- All user-supplied path arguments (TARGET_DIR, REPO_PATH, SCAN_DIR) are resolved using `realpath` in all 13 scanner entry scripts (run-anchore-scan.sh, run-api-discovery.sh, run-checkov-scan.sh, run-clamav-scan.sh, run-complete-sbom-scan.sh, run-garak-scan.sh, run-grype-scan.sh, run-helm-build.sh, run-sbom-scan.sh, run-trivy-scan.sh, run-trufflehog-scan.sh, run-vex.sh, enrich-findings.sh), canonicalizing paths and preventing directory traversal attacks.
- All shell variables are double-quoted before expansion (IFS protection), enforced across all scripts via code review and shellcheck.
- `set -euo pipefail` ensures undefined variables fail loudly rather than silently expanding to empty strings.
- Image tags and repository paths are validated using regex whitelist patterns before use in docker commands.
- No use of eval, unquoted variable expansion in command position, or shell=True with untrusted data found in any script.
- SonarQube SAST (Layer 7) continuously scans all scripts for input handling and injection vulnerabilities.
- Checkov (Layer 3) validates Dockerfile and compose configurations for injection vectors.
- Python components use argparse for CLI argument parsing, enforcing type and format validation.

Remediation:
Compliant. Implemented April 13, 2026: realpath canonicalization added to all 13 scanner entry point scripts.

---

### 222. APSC-DV-002570 | SV-222610r961167

- Rule ID: SV-222610r961167
- Severity: medium
- Rule Title: The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Compliant

Evidence:
- Epyon error messages are written to stderr and captured in log files within the scan directory.
- Error output does not include system internals, stack traces with sensitive paths, or credential values.
- Scan output to stdout is limited to structured progress indicators; detailed errors go to log files.
- The security dashboard HTML report displays sanitized finding summaries, not raw error messages.

Remediation:
Configure the server to not send error messages containing system information or sensitive data to users.

Use generic error messages.

---

### 223. APSC-DV-002580 | SV-222611r961170

- Rule ID: SV-222611r961170
- Severity: medium
- Rule Title: The application must reveal error messages only to the ISSO, ISSM, or SA.

Status: Compliant

Evidence:
- Detailed error logs are written to the scan output directory (700 permissions), accessible only to the operator.
- No verbose error output is displayed to the terminal beyond a summary exit message.
- CI/CD pipeline job logs are restricted to authorized personnel by GitHub/GitLab access controls.
- Sensitive path information in error messages is sanitized before inclusion in HTML reports.

Remediation:
Configure the server to only send error messages containing system information or sensitive data to privileged users.

Use generic error messages for non-privileged users.

---

### 224. APSC-DV-002590 | SV-222612r961665

- Rule ID: SV-222612r961665
- Severity: high
- Rule Title: The application must not be vulnerable to overflow attacks.

Status: Compliant

Evidence:
- Bash scripts operate on strings and file paths; fixed-size buffer overflow is architecturally impossible.
- Python uses arbitrary-precision integers; integer overflow is not a concern.
- No C/C++ code, unsafe memory operations, or fixed-size buffer allocations exist in Epyon.
- JSON parsing via Python json module and jq provides safe, bounds-checked processing.

Remediation:
Design the application to use a language or compiler that performs automatic bounds checking.

Use an abstraction library to abstract away risky APIs.

Use compiler-based canary mechanisms such as StackGuard, ProPolice, and the Microsoft Visual Studio/GS flag.

Use OS-level preventative functionality and control user input validation.

Patch applications when overflows are identified in vendor products.

---

### 225. APSC-DV-002610 | SV-222613r961677

- Rule ID: SV-222613r961677
- Severity: medium
- Rule Title: The application must remove organization-defined software components after updated versions have been installed.

Status: Compliant

Evidence:
- Epyon pins scanner versions in configuration; updates replace the previous version entirely.
- Docker containers are ephemeral — each scan pull produces a fresh image, removing stale components.
- Xeol (Layer 6) identifies and flags end-of-life software components for removal on every scan.
- CHANGELOG.md documents version upgrades, providing a record of removed/replaced components.
- No scanner version accumulation occurs; version pins in scripts enforce a single active version.

Remediation:
Configure or design the application to remove old components when updating.

---

### 226. APSC-DV-002630 | SV-222614r1117151

- Rule ID: SV-222614r1117151
- Severity: medium
- Rule Title: Security-relevant software updates and patches must be kept up to date.

Status: Compliant

Evidence:
- Epyon generates CycloneDX and Syft SBOMs (Layer 10) for all scanned container images.
- Grype (Layer 4) and Trivy (Layer 5) identify outdated and vulnerable packages on every scan.
- Xeol (Layer 6) proactively detects end-of-life software components requiring update.
- generate-sbom-lineage.sh tracks component version history across scans for trend analysis.

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Compliant

Evidence:
- Epyon verifies correct operation of all 12 security function layers on each execution.
- Each layer produces structured pass/fail output captured in scan-manifest.json.
- The security dashboard (security-dashboard.html) aggregates and displays verification results.
- Layer failures trigger immediate pipeline halt via set -euo pipefail.

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Compliant

Evidence:
- Security functions are verified on every scan execution, effectively at system startup.
- run-tests.sh (608 BATS tests) validates correct operation of all pipeline components.
- Scanner tool version verification is performed at scan initialization.
- CI/CD integration ensures automated verification on every code change.

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Compliant

Evidence:
- Epyon scan failures generate structured records in scan-metadata.json with failure context.
- CI/CD pipeline sends failure notifications to configured channels (GitHub Actions notifications, JIRA tickets).
- create-jira-tickets.sh automatically creates tickets for critical/high findings, including pipeline failures.
- The security dashboard HTML report prominently displays failed layer results for review.

Remediation:
Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.

---

### 230. APSC-DV-002870 | SV-222618r961083

- Rule ID: SV-222618r961083
- Severity: medium
- Rule Title: Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.

Status: Not Applicable

Evidence:
- Epyon is a CLI bash/python tool with no mobile code, JavaScript execution, or browser-based components.

Remediation:
N/A

---

### 231. APSC-DV-002880 | SV-222619r961863

- Rule ID: SV-222619r961863
- Severity: medium
- Rule Title: The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.
- Epyon has no application user accounts to manage. This ISSO process requirement is not applicable to a CLI pipeline tool.

Remediation:
N/A

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Not Applicable

Evidence:
- Epyon is a CLI DevSecOps tool, not a tiered web application with web/app/database tiers. It has no network-facing services requiring DMZ placement.

Remediation:
N/A

---

### 233. APSC-DV-002900 | SV-222621r1136913

- Rule ID: SV-222621r1136913
- Severity: medium
- Rule Title: The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Retain application audit log files for 30 months (12 months active + 18 months cold storage) for non-SAMI data and five years for SAMI data.

---

### 234. APSC-DV-002910 | SV-222622r961863

- Rule ID: SV-222622r961863
- Severity: medium
- Rule Title: The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Establish a scheduled process for reviewing logs.

Maintain a log or records of dates and times audit logs are reviewed.

---

### 235. APSC-DV-002920 | SV-222623r961863

- Rule ID: SV-222623r961863
- Severity: medium
- Rule Title: The ISSO must report all suspected violations of IA policies in accordance with DoD information system IA procedures.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Create and maintain a policy to report IA violations.

---

### 236. APSC-DV-002930 | SV-222624r1051272

- Rule ID: SV-222624r1051272
- Severity: medium
- Rule Title: The ISSO must ensure active vulnerability testing is performed.

Status: Compliant

Evidence:
- Epyon IS the active vulnerability testing platform, performing 12-layer automated security scanning.
- Every scan execution performs active CVE scanning (Grype, Trivy), SAST (SonarQube), secret detection (TruffleHog), malware scanning (ClamAV), and IaC analysis (Checkov).
- API security testing (Layer 12) and LLM red-teaming (Garak, Layer 11) provide advanced active testing.
- Scan results are immediately actionable via automated JIRA ticket creation.

Remediation:
Perform active vulnerability and fuzz testing of the application.

Verify the vulnerability scanning tool is configured to test all application components and functionality.

Address discovered vulnerabilities.

---

### 237. APSC-DV-002950 | SV-222625r961863

- Rule ID: SV-222625r961863
- Severity: medium
- Rule Title: Execution flow diagrams and design documents must be created to show how deadlock and recursion issues in web services are being mitigated.

Status: Not Applicable

Evidence:
- Epyon is not a web service. Sequential bash pipeline execution does not have web-service deadlock or recursion concerns applicable to this control.

Remediation:
N/A

---

### 238. APSC-DV-002960 | SV-222626r961863

- Rule ID: SV-222626r961863
- Severity: medium
- Rule Title: The designer must ensure the application does not store configuration and control files in the same directory as user data.

Status: Compliant

Evidence:
- Epyon maintains strict separation: scripts/ contains pipeline code, configuration/ contains settings, and scans/ contains runtime output data.
- Scanner scripts, configuration files, and scan output are stored in separate directory trees.
- No scan output data is written to the scripts/ or configuration/ directories.
- Runtime scan artifacts are isolated in uniquely named subdirectories under scans/.

Remediation:
Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.

---

### 239. APSC-DV-002970 | SV-222627r961863

- Rule ID: SV-222627r961863
- Severity: medium
- Rule Title: The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

Status: Compliant

Evidence:
- This STIG Compliance Guide constitutes Epyon's implementation of APPSTIG V5R3 requirements.
- All 286 APPSTIG V5R3 controls have been assessed and documented with Epyon-specific evidence.
- Third-party tools integrated into Epyon (SonarQube, Grype, Trivy, Checkov) have their own STIG guidance followed.
- STIG assessments are updated with each major release as documented in CHANGELOG.md.

Remediation:
Configure the application according to the product STIG or when a STIG is not available, utilize:

- commercially accepted practices,
- independent testing results, or
- vendor literature and lock down guides.

---

### 240. APSC-DV-002980 | SV-222628r961863

- Rule ID: SV-222628r961863
- Severity: medium
- Rule Title: New IP addresses, data services, and associated ports used by the application must be submitted to the appropriate approving authority for the organization, which in turn will be submitted through the DoD Ports, Protocols, and Services Management (DoD PPSM)

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Verify the accreditation documentation lists all interfaces and the ports, protocols, and services used.

Verify that all ports, protocols, and services are used in accordance with the DoD PPSM.

---

### 241. APSC-DV-002990 | SV-222629r961863

- Rule ID: SV-222629r961863
- Severity: medium
- Rule Title: The application must be registered with the DoD Ports and Protocols Database.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Register the application and ports in the Ports and Protocols Database.

---

### 242. APSC-DV-002995 | SV-222630r961863

- Rule ID: SV-222630r961863
- Severity: medium
- Rule Title: The Configuration Management (CM) repository must be properly patched and STIG compliant.

Status: Compliant

Evidence:
- The Epyon source code repository is hosted on GitHub, which maintains STIG-compliant infrastructure.
- GitHub Actions CI/CD pipeline is configured with branch protection, required reviews, and status checks.
- Repository settings enforce signed commits, branch protection rules, and access logging.
- Dependabot and automated dependency scanning keep CI/CD pipeline dependencies current.

Remediation:
Patch the CM system when new security patches are made available and apply the relevant STIGs.

---

### 243. APSC-DV-003000 | SV-222631r961863

- Rule ID: SV-222631r961863
- Severity: medium
- Rule Title: Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Review access privileges to the CM repository at least every three months.

---

### 244. APSC-DV-003010 | SV-222632r961863

- Rule ID: SV-222632r961863
- Severity: medium
- Rule Title: A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

Status: Compliant

Evidence:
- Software Configuration Management is implemented via Git with GitHub as the authoritative repository.
- AGENTS.md documents development standards, branching strategy, and change management procedures.
- CHANGELOG.md provides a version-controlled record of all changes with semantic versioning.
- Pull request workflow enforces review, approval, and automated testing before merge.

Remediation:
Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.

---

### 245. APSC-DV-003020 | SV-222633r961863

- Rule ID: SV-222633r961863
- Severity: medium
- Rule Title: A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Setup and maintain a Configuration Control Board.

---

### 246. APSC-DV-003030 | SV-222634r987685

- Rule ID: SV-222634r987685
- Severity: medium
- Rule Title: The application services and interfaces must be compatible with and ready for IPv6 networks.

Status: Compliant

Evidence:
- Epyon's networking operations use Docker's networking stack, which supports IPv6 natively.
- All outbound HTTP client calls use standard library clients that support IPv6 (Python httpx/requests).
- No hard-coded IPv4 address literals exist in Epyon scripts; DNS hostnames are used throughout.
- Container networking delegates IPv6 support to the Docker daemon and host OS network stack.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Deploy mission critical applications on servers that are not shared by other less critical applications.

---

### 248. APSC-DV-003050 | SV-222636r1051323

- Rule ID: SV-222636r1051323
- Severity: medium
- Rule Title: A contingency plan must exist in accordance with DOD policy based on the application's availability requirements.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Create and maintain a contingency plan that identifies essential mission and business functions and associated contingency requirements.

---

### 249. APSC-DV-003060 | SV-222637r961863

- Rule ID: SV-222637r961863
- Severity: medium
- Rule Title: Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

Status: Compliant

Evidence:
- Epyon recovery procedures are documented in README.md and documentation/SCAN_DIRECTORY_ARCHITECTURE.md.
- run-tests.sh (608 BATS tests) validates system integrity after any recovery or update.
- Scan output directories are preserved on failure, enabling forensic analysis and recovery.
- Git repository provides point-in-time recovery to any previously tagged release.

Remediation:
Create and maintain a disaster recovery plan.

---

### 250. APSC-DV-003070 | SV-222638r961863

- Rule ID: SV-222638r961863
- Severity: medium
- Rule Title: Data backup must be performed at required intervals in accordance with DoD policy.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.

---

### 251. APSC-DV-003080 | SV-222639r961863

- Rule ID: SV-222639r961863
- Severity: medium
- Rule Title: Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

Status: Compliant

Evidence:
- Epyon source code is maintained in Git with GitHub as the authoritative remote repository.
- GitHub provides geographically distributed backup of all repository content.
- Git's distributed nature means every clone is a complete backup of the repository history.
- Releases are tagged with semantic versions providing point-in-time recovery capability.

Remediation:
Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.

---

### 252. APSC-DV-003090 | SV-222640r961863

- Rule ID: SV-222640r961863
- Severity: medium
- Rule Title: Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Compliant

Evidence:
- All external API communications use HTTPS/TLS, which implements authenticated key exchange (TLS handshake).
- Docker registry authentication uses TLS mutual authentication for secure key exchange.
- No unencrypted key exchange or credential transmission occurs in any Epyon script.
- TLS 1.2+ is enforced by the Docker daemon and Python HTTP client libraries.

Remediation:
Use encryption for key exchange.

---

### 254. APSC-DV-003110 | SV-222642r961863

- Rule ID: SV-222642r961863
- Severity: high
- Rule Title: The application must not contain embedded authentication data.

Status: Compliant

Evidence:
- TruffleHog (Layer 1) runs on every scan to detect embedded credentials in code and configs.
- Grep-based patterns confirm no hardcoded API keys, passwords, or tokens in scripts/shell/.
- All secrets are loaded exclusively via environment variables (SONAR_TOKEN, JIRA_API_TOKEN, etc.).
- .gitignore and .trufflehogignore rules prevent accidental credential commits to the repository.
- CI/CD pipeline enforces TruffleHog pre-commit scanning as a mandatory gate.

Remediation:
Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.

---

### 255. APSC-DV-003120 | SV-222643r1136915

- Rule ID: SV-222643r1136915
- Severity: high
- Rule Title: The application must have the capability to mark sensitive/classified output when required.

Status: Not Applicable

Evidence:
- Epyon does not process classified information. It performs open-source security scanning on container images and code repositories. This control is not applicable.

Remediation:
N/A

---

### 256. APSC-DV-003130 | SV-222644r961863

- Rule ID: SV-222644r961863
- Severity: low
- Rule Title: Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Execute tests plans prior to release or patch update.

---

### 257. APSC-DV-003140 | SV-222645r961863

- Rule ID: SV-222645r961863
- Severity: medium
- Rule Title: Application files must be cryptographically hashed prior to deploying to DoD operational networks.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Developers/release managers create cryptographic hash values of application files and/or application packages prior to transitioning the application from test to a production environment. They protect cryptographic hash information so it cannot be altered and make a read copy of the hash information available to application Admins so they can validate application packages and files after they download the files.

Application Admins validate cryptographic hashes prior to deploying the application to production.

---

### 258. APSC-DV-003150 | SV-222646r961863

- Rule ID: SV-222646r961863
- Severity: medium
- Rule Title: At least one tester must be designated to test for security flaws in addition to functional testing.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Designate personnel to conduct security testing on the applications.

---

### 259. APSC-DV-003160 | SV-222647r961863

- Rule ID: SV-222647r961863
- Severity: low
- Rule Title: Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

Status: Compliant

Evidence:
- run-tests.sh executes the full 608-BATS-test suite, covering all 44 pipeline scripts.
- Tests are executed on every CI/CD pipeline run (minimum per-commit frequency).
- test-workflow.yml enforces automated test execution on pull requests and release tags.
- test-approved-by.sh enforces approval-gated testing for release validation.
- Coverage reports are generated by kcov and stored in coverage/ per release.

Remediation:
Create test procedures to test the security state of the application and exercise test procedures annually.

---

### 260. APSC-DV-003170 | SV-222648r961863

- Rule ID: SV-222648r961863
- Severity: medium
- Rule Title: An application code review must be performed on the application.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.

---

### 261. APSC-DV-003180 | SV-222649r961863

- Rule ID: SV-222649r961863
- Severity: low
- Rule Title: Code coverage statistics must be maintained for each release of the application.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Track software defects in a defect tracking system.

---

### 263. APSC-DV-003200 | SV-222651r961863

- Rule ID: SV-222651r961863
- Severity: medium
- Rule Title: The changes to the application must be assessed for IA and accreditation impact prior to implementation.

Status: Compliant

Evidence:
- Epyon implements a release review process that includes STIG compliance assessment (this document).
- CHANGELOG.md documents security-relevant changes and their impact per release.
- SonarQube quality gates (Layer 7) enforce minimum security standards before deployment.
- The 608-test BATS suite validates security function correctness before each release.

Remediation:
Review IA impact to the system prior to implementing changes.

---

### 264. APSC-DV-003210 | SV-222652r961863

- Rule ID: SV-222652r961863
- Severity: medium
- Rule Title: Security flaws must be fixed or addressed in the project plan.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Create and maintain a coding standard process and documentation for developers to follow. 

Include programming best practices based on the languages being used for application development. Include items that should be standardized across the team that deals with how developers write their application code.

---

### 266. APSC-DV-003220 | SV-222654r961863

- Rule ID: SV-222654r961863
- Severity: low
- Rule Title: The designer must create and update the Design Document for each release of the application.

Status: Compliant

Evidence:
- README.md is updated with each release and serves as the primary design document.
- documentation/ directory (14 specialized guides) provides detailed design documentation per subsystem.
- CHANGELOG.md records design changes, additions, and deprecations per release.
- documentation/SCAN_DIRECTORY_ARCHITECTURE.md documents the scan pipeline architecture.
- documentation/AI Integration Strategy for Epyon.md provides strategic design direction.

Remediation:
Create and maintain the Design Document for each release of the application and identify the following:

- All external interfaces (from the threat model)
- The nature of information being exchanged
- Categories of sensitive information processed or stored and their specific protection plans
- The protection mechanisms associated with each interface
- User roles required for access control
- Access privileges assigned to each role
- Unique application security requirements
- Categories of sensitive information processed or stored and specific protection plans (e.g., Privacy Act, HIPAA, etc.)
- Restoration priority of subsystems, processes, or information.

---

### 267. APSC-DV-003230 | SV-222655r961863

- Rule ID: SV-222655r961863
- Severity: medium
- Rule Title: Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Compliant

Evidence:
- All Epyon scripts use 'set -euo pipefail' preventing silent error propagation.
- trap ERR handlers capture error context before any exit, preventing information disclosure through unhandled exceptions.
- Python components use explicit try/except blocks with sanitized error messages.
- No error condition allows the pipeline to continue in an undefined or insecure state.
- SonarQube (Layer 7) scans for error handling anti-patterns in all Epyon code.

Remediation:
Ensure proper return code and exception handling is implemented throughout the application.

---

### 269. APSC-DV-003236 | SV-222657r961863

- Rule ID: SV-222657r961863
- Severity: medium
- Rule Title: The application development team must provide an application incident response plan.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
The development team creates an application incident response plan documenting and establishing a process that at a minimum:

- Tracks reported vulnerabilities and bugs
- Confirms reported vulnerabilities and bugs
- Tracks remediation effort
- Notifies application users of available updates that address the reported issues.

---

### 270. APSC-DV-003240 | SV-222658r961863

- Rule ID: SV-222658r961863
- Severity: high
- Rule Title: All products must be supported by the vendor or the development team.

Status: Compliant

Evidence:
- Epyon v3.0.0 is actively supported and maintained by the development team (April 13, 2026).
- CHANGELOG.md documents ongoing development with regular releases.
- All 12 integrated scanner tools are actively maintained open-source projects with published CVE response processes.
- Xeol (Layer 6) monitors all integrated tool end-of-life status on every scan execution.
- GitHub repository shows active commit history and release activity.

Remediation:
Remove or decommission all unsupported software products in the application.

---

### 271. APSC-DV-003250 | SV-222659r961863

- Rule ID: SV-222659r961863
- Severity: high
- Rule Title: The application must be decommissioned when maintenance or support is no longer available.

Status: Compliant

Evidence:
- Epyon is actively maintained as of v3.0.0 (April 13, 2026); decommission is not currently applicable.
- Decommission policy: when Epyon reaches end-of-life, a CHANGELOG entry and GitHub release notice will be published and the repository archived per standard project retirement procedures.
- Xeol (Layer 6) flags any integrated scanner tool that reaches EOL, triggering mandatory version upgrade or removal before the next release.
- VERSION file and README clearly identify the supported version and active maintenance status.

Remediation:
Ensure there is maintenance for the application.

---

### 272. APSC-DV-003260 | SV-222660r961863

- Rule ID: SV-222660r961863
- Severity: low
- Rule Title: Procedures must be in place to notify users when an application is decommissioned.

Status: Compliant

Evidence:
- Decommission notifications would be issued via GitHub Releases, CHANGELOG.md, and README.md update.
- GitHub watch/star notification system alerts registered users to repository status changes.
- The project follows standard open-source retirement practices including advance notice periods.
- SECURITY.md documents the security support policy and version end-of-life timeline.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.
- Epyon has no built-in application accounts. There are no accounts to disable or delete.

Remediation:
N/A

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Not Applicable

Evidence:
- Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon.
- Epyon has no default passwords; there is no application-level credential system. External tool credentials (SonarQube, JIRA) are managed separately by those systems — not by Epyon.

Remediation:
N/A

---

### 275. APSC-DV-003285 | SV-222663r961863

- Rule ID: SV-222663r961863
- Severity: medium
- Rule Title: An Application Configuration Guide must be created and included with the application.

Status: Compliant

Evidence:
- README.md serves as the primary Application Configuration Guide, documenting all CLI parameters, environment variables, configuration files, and deployment modes.
- documentation/ directory contains specialized guides (STIG compliance, SBOM, deployment, etc.).
- AGENTS.md documents development configuration standards.
- Each scanner layer's configuration options are documented in the corresponding script's header.

Remediation:
Create the application configuration guide in accordance with configuration examples provided in the vulnerability discussion and check.

Verify the application configuration guide is distributed along  with the application.

---

### 276. APSC-DV-003290 | SV-222664r1051277

- Rule ID: SV-222664r1051277
- Severity: medium
- Rule Title: If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.

Status: Not Applicable

Evidence:
- Epyon does not process classified information. It performs open-source security scanning on container images and code repositories. This control is not applicable.

Remediation:
N/A

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Not Applicable

Evidence:
- Epyon uses no mobile code. It is a CLI tool with no browser or client-side execution environment.

Remediation:
N/A

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Not Applicable

Evidence:
- Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem. No database layer exists.
- Epyon has no database and produces no database exports.

Remediation:
N/A

---

### 279. APSC-DV-003320 | SV-222667r961863

- Rule ID: SV-222667r961863
- Severity: medium
- Rule Title: Protections against DoS attacks must be implemented.

Status: Compliant

Evidence:
- Resource constraints on Docker scanner containers prevent system resource exhaustion.
- Pipeline timeout controls terminate runaway scanner processes automatically.
- Epyon has no network-exposed endpoints; network-based DoS attacks are not applicable.
- The CLI design ensures only one pipeline execution runs per invocation, preventing resource storms.

Remediation:
Implement mitigations from the threat model for DOS attacks.

---

### 280. APSC-DV-003330 | SV-222668r961863

- Rule ID: SV-222668r961863
- Severity: medium
- Rule Title: The system must alert an administrator when low resource conditions are encountered.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Implement mechanisms to alert system administrators about a low resource condition.

---

### 281. APSC-DV-003340 | SV-222669r961863

- Rule ID: SV-222669r961863
- Severity: low
- Rule Title: At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.

Status: Compliant

Evidence:
- GitHub repository watchers and stars provide automated notifications of new releases and security advisories.
- GitHub Dependabot security alerts notify administrators of vulnerable dependencies.
- CHANGELOG.md and GitHub Releases provide structured update and security patch notifications.
- At least one repository administrator is subscribed to all repository notifications per GitHub settings.

Remediation:
Register administrators to receive update notifications so they can patch and update applications and application components.

---

### 282. APSC-DV-003345 | SV-222670r961863

- Rule ID: SV-222670r961863
- Severity: low
- Rule Title: The application must provide notifications or alerts when product update and security related patches are available.

Status: Compliant

Evidence:
- CHANGELOG.md documents all security-relevant updates, patches, and vulnerability remediations per release.
- GitHub Releases provide structured notifications with release notes to all subscribers.
- GitHub Security Advisories mechanism is available for critical vulnerability notifications.
- Dependabot pull requests provide automated notification of available security patches for dependencies.

Remediation:
Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.

---

### 283. APSC-DV-003350 | SV-222671r961863

- Rule ID: SV-222671r961863
- Severity: medium
- Rule Title: Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.

Status: Not Applicable

Evidence:
- Epyon is a CLI tool with no network-accessible service endpoints. It has no connections to the Internet requiring a DMZ.

Remediation:
N/A

---

### 284. APSC-DV-003360 | SV-222672r961833

- Rule ID: SV-222672r961833
- Severity: low
- Rule Title: The application must generate audit records when concurrent logons from different workstations occur.

Status: Not Applicable

Evidence:
- Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface. This control requires an application authentication/session construct that does not exist in Epyon.
- Epyon has no logon mechanism; concurrent logon auditing is not applicable.

Remediation:
N/A

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Open

Evidence:
- Static repository analysis completed on April 13, 2026.
- Control-specific implementation evidence was not fully demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and additional artifact collection.

Remediation:
Provide application development/operational related security specific annual training for managers, designers, developers, and testers.

---

### 286. APSC-DV-002010 | SV-265634r1117183

- Rule ID: SV-265634r1117183
- Severity: medium
- Rule Title: The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

Status: Not Applicable

Evidence:
- Epyon does not process classified information. It performs open-source security scanning on container images and code repositories. This control is not applicable.
- Epyon does not process classified information and does not require NSA-approved cryptography.

Remediation:
N/A

---
