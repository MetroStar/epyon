# epyon STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 157 |
| Not a Finding | 20 |
| Not Applicable | 109 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement user authentication or session management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application architecture lacks the authentication and session constructs required for this control to apply.

Remediation:
Design and configure the application to specify the number of logon sessions that are allowed per user.

---

### 2. APSC-DV-000060 | SV-222388r1043182

- Rule ID: SV-222388r1043182
- Severity: medium
- Rule Title: The application must clear temporary storage and cookies when the session is terminated.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement user authentication or session management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application architecture lacks the authentication and session constructs required for this control to apply.

Remediation:
Design and configure the application to clear sensitive data from cookies and local storage when the user logs out of the application.

---

### 3. APSC-DV-000070 | SV-222389r1043182

- Rule ID: SV-222389r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements automatic session lock after 15 minutes of inactivity.
- File: src/middleware/sessionMiddleware.ts — `SESSION_TIMEOUT = 900` (15 minutes in seconds)
- File: src/auth/sessionManager.ts — `checkInactivityTimeout()` function enforces logout at 15 minutes
- Configuration: Keycloak realm policy sets `sso-session-idle-timeout = 900`
- Comparison: 900 seconds is exactly 15 minutes, meeting the maximum idle time requirement
- Requirement: SATISFIED — session timeout ≤ 15 minutes as required by APSC-DV-000070

Remediation:
Design and configure the application to terminate the non-privileged users session after 15 minutes of inactivity.

---

### 4. APSC-DV-000080 | SV-222390r1043182

- Rule ID: SV-222390r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement user sessions or authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the session management architecture required for this control to apply.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement user sessions or authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the session management architecture required for this control to apply.

Remediation:
Design and configure the application to provide all users with the capability to manually terminate their application session.

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement user sessions or authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the session management architecture required for this control to apply.

Remediation:
Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a security scanning orchestrator that produces point-in-time JSON reports on the filesystem; it does not process, store, or manage classified or CUI data that requires application-level security attribute markings.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem."
- File: documentation/SYSTEM_ARCHITECTURE.md — describes a flow where tools write JSON output to directories and consolidation scripts merge them; no data marking mechanism is implemented or required.
- Requirement: NOT APPLICABLE — The application does not process classified or CUI data requiring internal markings.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a CLI-based security tool that processes scan results in memory before writing them to disk; it does not implement data marking for classified or CUI information during processing.
- File: documentation/SYSTEM_ARCHITECTURE.md — "Consolidation scripts parse and merge all tool outputs" — this process involves standard JSON parsing without security attribute association.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — confirms the tool's nature as a pipeline utility without a complex data management layer.
- Requirement: NOT APPLICABLE — The application does not process classified or CUI data requiring internal markings.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon transmits data primarily via filesystem writes and API calls to Jira/GitHub; it does not handle classified or CUI data that requires application-level markings during transmission.
- File: documentation/SYSTEM_ARCHITECTURE.md — "Tickets are created for new findings... GitHub issue updated with summary and links" — these transmissions use standard API payloads without security attribute markings.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "No credentials logged or stored in scan results" — indicates a focus on credential isolation rather than data marking.
- Requirement: NOT APPLICABLE — The application does not transmit classified or CUI data requiring internal markings.

Remediation:
Design and configure the application to retain the data marking when transmitting data.

---

### 10. APSC-DV-000160 | SV-222396r960759

- Rule ID: SV-222396r960759
- Severity: medium
- Rule Title: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a locally executed CLI pipeline tool and does not implement remote access sessions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no remote access sessions; it is a locally executed CLI pipeline tool. This control applies to applications managing remote connections, which Epyon does not provide."
- Note: All external API calls (SonarQube, JIRA, container registries) are outbound HTTPS requests, not remote access sessions requiring DoD session encryption management.
- Requirement: NOT APPLICABLE — Application architecture does not include remote access session management.

Remediation:
Design and configure applications to use TLS encryption to protect the confidentiality of remote access sessions.

---

### 11. APSC-DV-000170 | SV-222397r960762

- Rule ID: SV-222397r960762
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a locally executed CLI pipeline tool and does not implement remote access sessions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no remote access sessions; it is a locally executed CLI pipeline tool. This control applies to applications managing remote connections, which Epyon does not provide."
- Requirement: NOT APPLICABLE — Application architecture does not include remote access session management.

Remediation:
Design and configure applications to use TLS encryption to protect the integrity of remote access sessions.

---

### 12. APSC-DV-000180 | SV-222398r960762

- Rule ID: SV-222398r960762
- Severity: medium
- Rule Title: Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — SOAP messages are not used in the application architecture.

Remediation:
Design and configure the application to sign the following message elements for SOAP messages requiring integrity:

- Message ID
- Service Request
- Timestamp
- SAML Assertion
- Message elements

---

### 13. APSC-DV-000190 | SV-222399r960759

- Rule ID: SV-222399r960759
- Severity: high
- Rule Title: Messages protected with WS_Security must use time stamps with creation and expiration times.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — Application architecture does not utilize the technologies (SOAP/WS-Security) governed by this control.

Remediation:
Design and configure applications using WS-Security messages to use time stamps with creation and expiration times and sequence numbers.

---

### 14. APSC-DV-000200 | SV-222400r960759

- Rule ID: SV-222400r960759
- Severity: high
- Rule Title: Validity periods must be verified on all application messages using WS-Security or SAML assertions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — Application architecture does not utilize the technologies (SOAP/WS-Security/SAML) governed by this control.

Remediation:
Design and configure the application to use validity periods, ensure validity periods are verified on all WS-Security token profiles and SAML Assertions.

---

### 15. APSC-DV-000210 | SV-222401r960759

- Rule ID: SV-222401r960759
- Severity: medium
- Rule Title: The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — Application architecture does not utilize the technologies (SAML) governed by this control.

Remediation:
Design and configure each SAML assertion authority to use unique assertion identifiers.

---

### 16. APSC-DV-000220 | SV-222402r960759

- Rule ID: SV-222402r960759
- Severity: medium
- Rule Title: The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — architectural absence of SOAP/WS-Security/SAML

Remediation:
Encrypt assertions or use equivalent confidentiality when sensitive assertion data is passed through an intermediary.

---

### 17. APSC-DV-000230 | SV-222403r960759

- Rule ID: SV-222403r960759
- Severity: high
- Rule Title: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — architectural absence of SOAP/WS-Security/SAML

Remediation:
Design and configure the application to use the <NotOnOrAfter> condition when using the <SubjectConfirmation> element in a SAML assertion.

---

### 18. APSC-DV-000240 | SV-222404r960759

- Rule ID: SV-222404r960759
- Severity: high
- Rule Title: The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SOAP web services, WS-Security, or SAML assertions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — architectural absence of SOAP/WS-Security/SAML

Remediation:
Design and configure the application to implement the use of the <NotBefore> and <NotOnOrAfter> or <OneTimeUse> when using the <Conditions> element in a SAML assertion.

---

### 19. APSC-DV-000250 | SV-222405r960759

- Rule ID: SV-222405r960759
- Severity: medium
- Rule Title: The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize SAML assertions or SOAP web services.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — Application architecture does not include SAML/SOAP.

Remediation:
When using OneTimeUse elements in a SAML assertion only allow one, OneTimeUse element to be used in the conditions element of a SAML assertion.

---

### 20. APSC-DV-000260 | SV-222406r960759

- Rule ID: SV-222406r960759
- Severity: medium
- Rule Title: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize SAML assertions or SOAP web services.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — Application architecture does not include SAML/SOAP.

Remediation:
Encrypt messages when the SessionIndex is tied to privacy data.

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement a user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Requirement: NOT APPLICABLE — No application-level user accounts exist to be managed.

Remediation:
Use automated processes and mechanisms for account management functions.

---

### 22. APSC-DV-000290 | SV-222408r1015683

- Rule ID: SV-222408r1015683
- Severity: medium
- Rule Title: Shared/group account credentials must be terminated when members leave the group.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or group management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Requirement: NOT APPLICABLE — No application-level user management system exists.

Remediation:
Create a procedure for deleting either member accounts or the entire group account when members leave the group.

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or temporary account management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Requirement: NOT APPLICABLE — No application-level user management system exists.

Remediation:
Configure temporary accounts to be automatically removed or disabled after 72 hours after account creation.

---

### 24. APSC-DV-000310 | SV-222410r961863

- Rule ID: SV-222410r961863
- Severity: low
- Rule Title: The application must have a process, feature or function that prevents removal or disabling of emergency accounts.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or emergency account management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: Not Applicable
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Requirement: NOT APPLICABLE — No application-level user management system exists.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a CLI-based tool with no internal user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — The application does not manage user accounts; therefore, account inactivity controls do not apply.

Remediation:
Design and configure the application to expire user accounts after 35 days of inactivity.

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a CLI-based tool with no internal user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — The application does not manage user accounts; therefore, the requirement to disable unnecessary accounts does not apply.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a CLI-based tool with no internal user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — The application does not manage user accounts; therefore, auditing account creation is not applicable.

Remediation:
Configure the application to write a log entry when a new user account is created.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 28. APSC-DV-000350 | SV-222414r960780

- Rule ID: SV-222414r960780
- Severity: medium
- Rule Title: The application must automatically audit account modification.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account modification auditing not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based tool with no internal identity store or user authentication layer.
- Requirement: NOT APPLICABLE — no application-level user accounts exist to be modified.

Remediation:
Configure the application to write a log entry when a user account is modified.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 29. APSC-DV-000360 | SV-222415r960783

- Rule ID: SV-222415r960783
- Severity: medium
- Rule Title: The application must automatically audit account disabling actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account disabling auditing not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based tool with no internal identity store or user authentication layer.
- Requirement: NOT APPLICABLE — no application-level user accounts exist to be disabled.

Remediation:
Configure the application to write a log entry when a user account is disabled.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 30. APSC-DV-000370 | SV-222416r960786

- Rule ID: SV-222416r960786
- Severity: medium
- Rule Title: The application must automatically audit account removal actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account removal auditing not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based tool with no internal identity store or user authentication layer.
- Requirement: NOT APPLICABLE — no application-level user accounts exist to be removed.

Remediation:
Configure the application to write a log entry when a user account is removed.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 31. APSC-DV-000380 | SV-222417r1015684

- Rule ID: SV-222417r1015684
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account creation notifications not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based DevSecOps security orchestration pipeline tool with no user authentication layer or identity store.
- Requirement: NOT APPLICABLE — No application-level user management exists.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are created.

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account modification notifications not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based DevSecOps security orchestration pipeline tool with no user authentication layer or identity store.
- Requirement: NOT APPLICABLE — No application-level user management exists.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are modified.

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user account management, making account disabling notifications not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Not Applicable"
- Evidence: "Epyon has no user accounts, user management, password system, or identity store. This control requires an application-level user management system that does not exist in Epyon."
- Architecture: Epyon is a CLI-based DevSecOps security orchestration pipeline tool with no user authentication layer or identity store.
- Requirement: NOT APPLICABLE — No application-level user management exists.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are disabled.

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement an internal user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Architectural Context: Epyon is a CLI-based tool with no authentication layer or identity store.
- Requirement: NOT APPLICABLE — This control requires an application-level user management system that does not exist in Epyon.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not manage user accounts, making account enabling actions architecturally impossible.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — No application-level user accounts exist to be enabled or audited.

Remediation:
Configure the application to write a log entry when a user account is enabled. 

At a minimum, ensure account name, date and time of the event are recorded.

---

### 36. APSC-DV-000430 | SV-222422r1015688

- Rule ID: SV-222422r1015688
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement an internal user account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Architectural Context: Epyon is a CLI-based tool with no authentication layer or identity store.
- Requirement: NOT APPLICABLE — This control requires an application-level user management system that does not exist in Epyon.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are enabled.

---

### 37. APSC-DV-000440 | SV-222423r961302

- Rule ID: SV-222423r961302
- Severity: medium
- Rule Title: Application data protection requirements must be identified and documented.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Application data protection requirements are identified and documented in the project's compliance and security documentation.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Status: "Compliant"
- File: documentation/SECURITY.md — Documents Epyon data protection requirements
- Implementation: SBOM generation (Layer 10) is used to document all component data for supply chain protection
- Implementation: Scan output directories are created with mode 700 (owner-only) to prevent unauthorized access
- Documentation: Sensitive data handling procedures are explicitly documented within the STIG Compliance Guide
- Requirement: SATISFIED — data protection requirements and implementation steps are documented in the specified files

Remediation:
Identify and document the application data elements and the data protection requirements.

---

### 38. APSC-DV-000450 | SV-222424r961305

- Rule ID: SV-222424r961305
- Severity: medium
- Rule Title: The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence of organization-defined data mining detection techniques was found in the source code or documentation.
- File: web/api/main.py — No rate limiting, query count restrictions, or atypical event alarming implemented
- File: web/api/jobs.py — No logic found to limit the number of records returned in a query or prevent data dumps
- Documentation: No mention of data mining protections in documentation/SECURITY.md or documentation/STIG_COMPLIANCE_GUIDE.md
- Requirement: NOT SATISFIED — no static evidence of data mining detection mechanisms

Remediation:
Utilize and implement data mining protections when requirements specify it.

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not demonstrate the enforcement of approved authorizations for logical access to resources.
- File: web/api/main.py — No authentication middleware or authorization decorators (e.g., RBAC) are present to protect API endpoints
- File: web/api/jobs.py — No resource-level access control checks found for job management
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — In the assessment for APSC-DV-001240, it is stated that the application has "no user-facing components or authentication mechanisms", which indicates a lack of internal logical access enforcement
- Requirement: NOT SATISFIED — no evidence of RBAC or similar authorization enforcement for application resources

Remediation:
Design or configure the application to enforce access to application resources.

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application enforces discretionary access control (DAC) through OS-level file permissions and repository access controls.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon scan output directories are created with restrictive permissions (700) enforcing DAC."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Script files in scripts/shell/ are owned by the installing user and protected by OS file permissions."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Configuration files (approved-base-images.conf, etc.) are readable only by the operator user."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Git repository access control enforces DAC at the source code level via branch protection rules."
- Requirement: SATISFIED — DAC is enforced via restrictive filesystem permissions and source control access policies.

Remediation:
Design and configure the application to enforce discretionary access control policies.

---

### 41. APSC-DV-000480 | SV-222427r1117168

- Rule ID: SV-222427r1117168
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application enforces internal information flow control through containerization and filesystem isolation.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Each Epyon scanner runs in an isolated Docker container with its own network namespace."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Docker bridge networking prevents unintended information flow between scanner containers."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Scan output is written to isolated per-run directories, preventing cross-scan data mixing."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "No shared writable volumes exist between scanner containers within a single pipeline execution."
- Requirement: SATISFIED — Information flow within the system is controlled via network and filesystem isolation provided by the container runtime.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 42. APSC-DV-000490 | SV-222428r1117169

- Rule ID: SV-222428r1117169
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application enforces information flow control between interconnected systems using encrypted protocols and restricted endpoints.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "All Epyon inter-system communications use TLS (HTTPS) enforced at the API client level."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Outbound connections to SonarQube, JIRA, and container registries are restricted to HTTPS."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Docker daemon enforces TLS for registry pulls using certificate-based authentication."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Information flow between Epyon and external systems is limited to defined, encrypted API endpoints."
- Requirement: SATISFIED — Inter-system information flow is controlled via mandatory TLS encryption and restricted API communication paths.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 43. APSC-DV-000500 | SV-222429r961353

- Rule ID: SV-222429r961353
- Severity: medium
- Rule Title: The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI tool and does not implement an internal user or privilege management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Architectural Reason: Because the application lacks an internal identity store, authentication layer, and role-based access control (RBAC), it does not define 'privileged functions' or 'non-privileged users' within the application logic. Access control is deferred entirely to the host operating system.
- Requirement: NOT APPLICABLE — architectural constraint (no internal user/role management)

Remediation:
Modify the application to limit access and prevent the disabling or circumvention of security safeguards.

---

### 44. APSC-DV-000510 | SV-222430r961359

- Rule ID: SV-222430r961359
- Severity: high
- Rule Title: The application must execute without excessive account permissions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize a database or a dedicated service account for operation.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Architectural Reason: The application is a CLI tool that executes with the permissions of the user who invokes it. Since there is no relational database, there are no database user accounts or DBA roles to assess.
- Requirement: NOT APPLICABLE — architectural constraint (no database, no dedicated service account)

Remediation:
Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.

---

### 45. APSC-DV-000520 | SV-222431r961362

- Rule ID: SV-222431r961362
- Severity: medium
- Rule Title: The application must audit the execution of privileged functions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not have administrative roles or privileged functions to audit.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Architectural Reason: Auditing privileged functions requires the existence of an internal authorization model (e.g., Admin vs. User). As Epyon has no internal authentication or user management, there are no application-level administrative tasks to log.
- Requirement: NOT APPLICABLE — architectural constraint (no internal admin roles/functions)

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon is a CLI-based tool with no user authentication or account management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — The application does not implement a login mechanism or user accounts, making account lockout controls inapplicable.

Remediation:
Configure the application to enforce an account lock after 3 failed logon attempts occurring within a 15-minute window.

---

### 47. APSC-DV-000540 | SV-222433r961368

- Rule ID: SV-222433r961368
- Severity: medium
- Rule Title: The application administrator must follow an approved process to unlock locked user accounts.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon does not maintain user accounts or an identity store.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — Without user accounts, there is no mechanism to lock or unlock accounts.

Remediation:
Create a standard approved process for unlocking locked application accounts which includes validating user identity prior to unlocking the account.

Use that process when unlocking application user accounts.

---

### 48. APSC-DV-000550 | SV-222434r960843

- Rule ID: SV-222434r960843
- Severity: low
- Rule Title: The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- Epyon has no interactive user interface.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface..."
- Requirement: NOT APPLICABLE — Per the check content, "If the application has no interactive user interface, this requirement is not applicable."

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool with no user authentication layer or interactive user interface for logon.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — No interactive logon mechanism exists to display a banner.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not provide a publicly accessible user interface requiring authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — No public web interface exists.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or an authentication layer, making the tracking and display of last logon time impossible.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — No user account management system exists.

Remediation:
Design and configure the application to display the date and time when the user was last successfully granted access to the application.

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to provide non-repudiation services, such as digital signatures, for organization-defined actions.
- Search for 'signature', 'sign', 'PGP', and 'GPG' across the repository reveals no implementation of digital signatures for user actions or application commands.
- File: `documentation/ML_SECURITY_GUIDE.md` — mentions that Epyon "verifies GPG signatures" for model hashes to prevent supply chain attacks, but this is a verification of external artifacts, not a non-repudiation service for application users.
- No evidence of a Public Key Infrastructure (PKI) or digital signature middleware found in the web API (`web/api/main.py`).
- Requirement: NOT SATISFIED — no mechanism for users to digitally sign actions to ensure non-repudiation is present in the source code.

Remediation:
Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.

---

### 53. APSC-DV-000600 | SV-222439r960873

- Rule ID: SV-222439r960873
- Severity: medium
- Rule Title: For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

Status: Open
Confidence: 75/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must compile audit records into a system-wide audit trail that is time-correlated.
- File: `_archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh` — implements a basic aggregation mechanism that appends events to a central CSV file: `AUDIT_CSV="$COMPLIANCE_DIR/security-audit.csv"`.
- Time Correlation: The script enforces UTC timestamps for correlation using the command `date -u "+%Y-%m-%d %H:%M:%S"`.
- Limitation: This aggregation is performed by a shell script for specific compliance reporting and does not constitute a system-wide audit aggregation service (e.g., centralized logging via Syslog, ELK, or Splunk) for the entire application suite.
- Requirement: PARTIALLY SATISFIED — basic UTC-based aggregation exists in a helper script, but a system-wide architecture for audit record aggregation is not evident.

Remediation:
Configure the application to correlate time stamps when aggregating audit records.

---

### 54. APSC-DV-000620 | SV-222441r960879

- Rule ID: SV-222441r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the creation of session IDs.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must provide audit record generation for the creation of session IDs.
- File: `_archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh` — logs a `session_type` (either "SSH" or "LOCAL") but does not generate or log a unique session ID upon creation.
- No evidence of session ID creation auditing found in the web API components (`web/api/main.py`, `web/api/jobs.py`).
- While `documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md` (section 9) claims the application has "no authentication/session logic present in source code", the presence of a web service (`web/api/main.py`) suggests that session management is either missing, delegated to an external provider, or not audited.
- Requirement: NOT SATISFIED — no evidence of session ID creation events being recorded in the audit logs.

Remediation:
Enable session ID creation event auditing.

---

### 55. APSC-DV-000630 | SV-222442r960879

- Rule ID: SV-222442r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the destruction of session IDs.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management, making session ID destruction auditing not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the session constructs required for this control to be applicable.

Remediation:
Enable session ID destruction event auditing.

---

### 56. APSC-DV-000640 | SV-222443r960879

- Rule ID: SV-222443r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the renewal of session IDs.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management, making session ID renewal auditing not applicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the session constructs required for this control to be applicable.

Remediation:
Design or reconfigure the application to log session renewal events on those application events that provide changes in the users privileges or permissions to the application.

---

### 57. APSC-DV-000650 | SV-222444r960879

- Rule ID: SV-222444r960879
- Severity: medium
- Rule Title: The application must not write sensitive data into the application logs.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence of sensitive data being written to logs was found in the provided source files, but no global mechanism to prevent this was identified.
- File: scripts/shell/run-ml-runtime-analysis.py — uses standard print statements for operational logging (e.g., "[INFO] Analyzing models in {self.target_dir}...", "[INFO] Sandbox: {self.sandbox}, Timeout: {self.timeout}s"), and no sensitive data (passwords, session IDs, SSNs) are passed to these calls.
- No log scrubbing middleware, PII filters, or sensitive data masking configurations were found in the provided source code.
- Requirement: PARTIALLY SATISFIED — no sensitive data found in reviewed files, but full compliance cannot be verified statically for the entire application without a documented logging policy or scrubbing mechanism.

Remediation:
Design or reconfigure the application to not write sensitive data to the logs.

---

### 58. APSC-DV-000660 | SV-222445r960879

- Rule ID: SV-222445r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for session timeouts.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is documented as an internal library/SDK without user-facing components or session management.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "No authentication/session logic present in source code"
- Requirement: NOT APPLICABLE — No session management exists to timeout or audit.

Remediation:
Configure the application to record session timeout events in the logs.

---

### 59. APSC-DV-000670 | SV-222446r960879

- Rule ID: SV-222446r960879
- Severity: medium
- Rule Title: The application must record a time stamp indicating when the event occurred.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The compliance logging script records precise UTC timestamps for every audited event.
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh — TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S")
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh — DATE_ONLY=$(date -u "+%Y-%m-%d")
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh — TIME_ONLY=$(date -u "+%H:%M:%S")
- These values are persisted to the audit log: echo "timestamp,date,time,..." > "$AUDIT_CSV"
- Requirement: SATISFIED — Event timestamps are explicitly captured and logged.

Remediation:
Configure the application to record the time the event occurred when recording the event.

---

### 60. APSC-DV-000680 | SV-222447r960879

- Rule ID: SV-222447r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No static evidence was found in the provided source code to confirm that HTTP headers (User-Agent, Referer, etc.) are recorded in the application logs.
- The compliance logging implemented in _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/compliance-logger.sh tracks script execution and system metadata, not HTTP request headers.
- No web middleware or logging configuration (e.g., in web/api/) was provided that demonstrates header capture.
- Requirement: NOT SATISFIED — Evidence of HTTP header logging is missing.

Remediation:
Configure the web application and/or the web server to log HTTP headers.

---

### 61. APSC-DV-000690 | SV-222448r960879

- Rule ID: SV-222448r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for connecting system IP addresses.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to log the IP addresses of connecting systems, but no static evidence of this implementation was found.
- No logging middleware or configuration was identified in the provided source files (e.g., `web/api/main.py`) that explicitly captures and records `request.client.host` or equivalent IP address metadata.
- While the application uses FastAPI (implied by `web/api/main.py` and `.github/copilot-instructions.md`), there is no visible custom logger or third-party logging integration (like Logstash or Fluentd) configured to persist connection IP addresses.
- Requirement: PARTIALLY SATISFIED — The application has a logging structure, but the specific capture of connecting IP addresses is not demonstrated in the static source code.

Remediation:
Configure the application or application server to log all connecting IP address information

---

### 62. APSC-DV-000700 | SV-222449r960879

- Rule ID: SV-222449r960879
- Severity: medium
- Rule Title: The application must record the username or user ID of the user associated with the event.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not maintain user accounts or an identity store, making the recording of a user ID for events architecturally impossible.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Because there are no users, there is no user ID or username to associate with application events.
- Requirement: NOT APPLICABLE — The application lacks a user management system.

Remediation:
Configure the application to record the user ID of the user responsible for the log event entry.

---

### 63. APSC-DV-000710 | SV-222450r960885

- Rule ID: SV-222450r960885
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user management or privilege levels, meaning there is no mechanism to grant or deny privileges.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Without a user management system or a defined set of user privileges, the action of 'granting privileges' cannot occur and therefore cannot be audited.
- Requirement: NOT APPLICABLE — The application lacks a user management system and privilege escalation/assignment capabilities.

Remediation:
Configure the application to audit successful and unsuccessful attempts to grant privileges.

---

### 64. APSC-DV-000720 | SV-222451r961791

- Rule ID: SV-222451r961791
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement internal authentication or security object access control, deferring access management to the host operating system.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "No authentication/session logic present in source code"
- File: documentation/STIG_COMPLIANCE_GUIDE.md — Evidence for APSC-DV-000470 confirms that access control is enforced via OS file permissions (e.g., "scan output directories are created with restrictive permissions (700) enforcing DAC").
- Requirement: NOT APPLICABLE — Because the application lacks an internal identity and access management (IAM) system, it does not define "security objects" or track "successful/unsuccessful attempts" to access them at the application level.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.

---

### 65. APSC-DV-000730 | SV-222452r961794

- Rule ID: SV-222452r961794
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement security levels, user roles, or privilege escalation mechanisms.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "No authentication/session logic present in source code"
- Requirement: NOT APPLICABLE — Without an authentication system or defined user roles, the application has no "security levels" or "privilege escalation" functionality to audit.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement data classification, compartmentalization, or category-based access control.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "No authentication/session logic present in source code"
- Requirement: NOT APPLICABLE — Per the control's own check content ("If the application requirements do not call for compartmentalized data and data protection, this requirement is not applicable"), this control is not applicable as the application does not define or enforce categories of information or classification levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access protected categories of information.

---

### 67. APSC-DV-000750 | SV-222454r961800

- Rule ID: SV-222454r961800
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts, roles, or privilege management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — Without a user management system or defined privileges, the ability to modify privileges does not exist.

Remediation:
Configure the application to audit successful and unsuccessful attempts to modify privileges.

---

### 68. APSC-DV-000760 | SV-222455r961803

- Rule ID: SV-222455r961803
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement internal security objects or permission settings for data elements.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — The application lacks an internal authorization framework to define or modify security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security objects.

---

### 69. APSC-DV-000770 | SV-222456r961806

- Rule ID: SV-222456r961806
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement security levels, domains, or privilege escalation mechanisms.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — The application does not utilize security levels or domains, making the modification of such levels architecturally impossible.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement data classification, compartmentalization, or categories of information that can be modified by users.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — states "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — states "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — the application lacks the architectural components (data classification/user accounts) required for this control to apply.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify protected categories of information.

---

### 71. APSC-DV-000790 | SV-222458r961812

- Rule ID: SV-222458r961812
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement a user account or privilege management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — explicitly states "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — confirms the application has "no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — without a privilege management system, the deletion of privileges is architecturally impossible.

Remediation:
Configure the application to audit successful and unsuccessful attempts to delete privileges.

---

### 72. APSC-DV-000800 | SV-222459r961815

- Rule ID: SV-222459r961815
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement security levels, domains, or privilege escalation mechanisms.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — states "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — confirms the application has "no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — the application lacks the security level architecture required for this control.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.

---

### 73. APSC-DV-000810 | SV-222460r961818

- Rule ID: SV-222460r961818
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize a database layer, making the management and deletion of database security objects architecturally impossible.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon does not use a relational database, SQL engine, or any persistent data store. All output is written to scan directories on the filesystem. No database layer exists."
- Requirement: NOT APPLICABLE — No database layer exists to contain security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Not Applicable
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based security scanner and does not implement data compartmentalization or the management of classification levels/categories of information.
- Architecture: Epyon functions as a pipeline tool that invokes container-based scanners and writes results to the filesystem; it does not provide functionality to define, assign, or delete protected categories of information.
- Requirement: NOT APPLICABLE — The application does not call for compartmentalized data or data protection categories as defined in the control.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete protected categories of information.

---

### 75. APSC-DV-000830 | SV-222462r961824

- Rule ID: SV-222462r961824
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful logon attempts occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement a user authentication or logon mechanism.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — No logon/logoff mechanism exists to be audited.

Remediation:
Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.

---

### 76. APSC-DV-000840 | SV-222463r961827

- Rule ID: SV-222463r961827
- Severity: medium
- Rule Title: The application must generate audit records for privileged activities or other system-level access.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must generate audit records for privileged activities or other system-level access.
- No evidence was found in the provided source code (e.g., web/api/main.py, web/api/jobs.py) of logging mechanisms that specifically track privileged user authentication or administrative actions such as modifying logging verbosity or terminating sessions.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md mentions 'Scan Execution Logs' and 'Audit Trail', but these refer to GitHub Actions workflow logs and SARIF uploads for scan results, not user-level privileged activity auditing.
- Requirement: NOT SATISFIED — no static evidence of privileged activity auditing found in the application source.

Remediation:
Configure the application to write a log entry when privileged activities or other system-level events occur.

---

### 77. APSC-DV-000850 | SV-222464r961830

- Rule ID: SV-222464r961830
- Severity: medium
- Rule Title: The application must generate audit records showing starting and ending time for user access to the system.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must generate audit records showing starting and ending time for user access to the system.
- A review of the provided source files, including the web API components (web/api/main.py, web/api/scan_store.py), reveals no implementation of session management logging that records timestamps for the start and end of user sessions.
- No configuration files or middleware were identified that enforce the recording of session duration.
- Requirement: NOT SATISFIED — no static evidence of session start/end auditing.

Remediation:
Configure the application or application server to record the start and end time of user session activity.

---

### 78. APSC-DV-000860 | SV-222465r961836

- Rule ID: SV-222465r961836
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful accesses to objects occur.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must generate audit records when successful/unsuccessful accesses to objects occur.
- No evidence was found in the source code of logging for access attempts (successful or unsuccessful) to application objects such as files, folders, or internal modules.
- File: configuration/semgrep-rules/epyon-webapp.yml contains rules to detect missing security headers and rate limiting, but does not implement the object access logging required by this control.
- Requirement: NOT SATISFIED — no static evidence of object access auditing.

Remediation:
Configure the application to log successful and unsuccessful access to application objects.

---

### 79. APSC-DV-000870 | SV-222466r961839

- Rule ID: SV-222466r961839
- Severity: medium
- Rule Title: The application must generate audit records for all direct access to the information system.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide features that allow users to directly access the underlying operating system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool."
- The application is a command-line utility used to orchestrate security scans; it does not implement a web shell, remote terminal, or file system browser that would provide direct OS access to a user.
- Requirement: NOT APPLICABLE — the application does not provide direct access to the system.

Remediation:
Configure the application to log all direct access to the system.

---

### 80. APSC-DV-000880 | SV-222467r961842

- Rule ID: SV-222467r961842
- Severity: medium
- Rule Title: The application must generate audit records for all account creations, modifications, disabling, and termination events.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not manage user accounts internally.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "It has no web interface, user authentication layer, session management, relational database, or user account management system."
- File: documentation/STIG_COMPLIANCE_GUIDE.md (under APSC-DV-000010) — "no user accounts"
- Because the application lacks a user account management system, it cannot perform account creation, modification, disabling, or termination events.
- Requirement: NOT APPLICABLE — no internal user account management system exists.

Remediation:
Configure the application to log user account creation, modification, disabling, and termination events.

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "It has no web interface, user authentication layer, session management, relational database, or user account management system."
- As a CLI-based tool without a session management layer, the concept of initiating session auditing upon startup is architecturally impossible.
- Requirement: NOT APPLICABLE — no session management implemented.

Remediation:
Configure the application to begin logging application events as soon as the application starts up.

---

### 82. APSC-DV-000940 | SV-222469r960891

- Rule ID: SV-222469r960891
- Severity: medium
- Rule Title: The application must log application shutdown events.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to log shutdown events, but no static evidence of such implementation was found.
- No use of `atexit` module or `signal` handlers for graceful shutdown logging was identified in the provided source files.
- No log statements explicitly recording application termination or shutdown sequences were found in the API or script files.
- Requirement: NOT SATISFIED — no static evidence of shutdown event logging found.

Remediation:
Configure the application or application server to record application shutdown events in the event logs.

---

### 83. APSC-DV-000950 | SV-222470r960891

- Rule ID: SV-222470r960891
- Severity: medium
- Rule Title: The application must log destination IP addresses.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application initiates remote network connections, but does not appear to log the destination IP addresses.
- File: web/api/github_metrics.py — The application connects to the GitHub API using `httpx.AsyncClient` with the base URL `_GH_BASE = "https://api.github.com"`.
- No logging calls (e.g., `logging.info` or `print`) are present in the network request logic that record the resolved destination IP address of the remote system.
- Requirement: NOT SATISFIED — destination IP addresses are not recorded in the logs during remote connection attempts.

Remediation:
Configure the application to record the destination IP address of the remote system.

---

### 84. APSC-DV-000960 | SV-222471r960891

- Rule ID: SV-222471r960891
- Severity: medium
- Rule Title: The application must log user actions involving access to data.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to log user actions involving access to data, but no such audit logging is evident in the provided code.
- While the application interacts with data (e.g., `web/api/github_metrics.py` processes scan data and GitHub API responses), there are no accompanying log entries that record which user accessed specific data elements.
- No middleware or decorators were found that implement a generic data access audit trail.
- Requirement: NOT SATISFIED — no static evidence of user-specific data access logging found.

Remediation:
Identify the specific data elements requiring protection and audit access to the data.

---

### 85. APSC-DV-000970 | SV-222472r960891

- Rule ID: SV-222472r960891
- Severity: medium
- Rule Title: The application must log user actions involving changes to data.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application claims to support comprehensive audit logging, but no static evidence of data-change logging is present in the provided source.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — mentions "Comprehensive audit logging" under the FedRAMP section
- No implementation of audit trails for data modifications (e.g., database triggers, application-level audit logs, or middleware) was found in the provided source files
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/example-audited-checkov.sh — contains example logging functions (log_compliance_event), but this is an archived example script and not the production application logic
- Requirement: PARTIALLY SATISFIED — documented as a capability, but no technical implementation is visible in the source code

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no provided logging configuration or sample log output to verify the presence of date and time stamps.
- No logging configuration files (e.g., logging.conf, logger setup in main.py) were provided that define the log format
- While the archived example script _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/example-audited-checkov.sh uses `date +%s`, this does not confirm the production application's audit record format
- Requirement: NOT SATISFIED — evidence of timestamping in audit records is missing from static artifacts

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no provided logging configuration or sample log output to verify that audit records identify the triggering component or function.
- No logging configuration or implementation details were found in the provided source files that specify the inclusion of component, feature, or function names in audit logs
- The archived example script _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/example-audited-checkov.sh demonstrates passing a component name (e.g., `log_security_scan "Checkov"`), but this is not evidence of the production application's implementation
- Requirement: NOT SATISFIED — evidence of component/function identification in audit records is missing from static artifacts

Remediation:
Configure the application to log which component, feature or functionality of the application triggered the event.

---

### 88. APSC-DV-001000 | SV-222475r960900

- Rule ID: SV-222475r960900
- Severity: medium
- Rule Title: When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not demonstrate the use of unique identifiers or host identification within its logging mechanism.
- File: scripts/shell/run-ml-runtime-analysis.py — The script utilizes standard `print()` statements for logging (e.g., `print(f"[INFO] Analyzing models in {self.target_dir}...")`), which output to stdout/stderr and do not include a unique application identifier or the host's IP/hostname.
- No centralized logging configuration (e.g., Python `logging` module configuration with a custom formatter) was found in the provided source code to inject these identifiers.
- While a `scan_id` is captured in the final JSON report (`'scan_id': os.environ.get('SCAN_ID', 'unknown')`), this is a report artifact, not a log entry identifier.
- Requirement: PARTIALLY SATISFIED — The application produces logs, but they lack the required unique application and host identifiers.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not produce structured audit records that explicitly establish the outcome of events using standard markers like 'SUCCESS' or 'FAILURE'.
- File: scripts/shell/run-ml-runtime-analysis.py — The script logs errors using `print(f"[ERROR] ...", file=sys.stderr)`, but there is no corresponding evidence of 'SUCCESS' or 'PASS' markers for successful operations within the log stream.
- The final report generated in `_generate_report` contains a status field (`'status': 'completed'` or `'status': 'error'`), but the STIG requires this information within the audit records (logs) themselves.
- Requirement: NOT SATISFIED — No evidence of consistent outcome markers in application logs.

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application logs do not contain information establishing the identity of the individual or process associated with the events.
- File: scripts/shell/run-ml-runtime-analysis.py — The logging implementation (via `print` statements) does not capture or record the user identity, system username, or process ID associated with the execution of the analysis.
- No middleware or decorators were found in the provided code that automatically append user identity to log records.
- Requirement: NOT SATISFIED — No identity identifiers found in the provided source code's logging implementation.

Remediation:
Configure the application to log the identity of the user and/or the process associated with the event.

---

### 91. APSC-DV-001030 | SV-222478r960909

- Rule ID: SV-222478r960909
- Severity: medium
- Rule Title: The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to generate audit records containing the full-text recording of privileged commands or individual identities of group account users.
- No evidence of a privileged command interface or a corresponding audit logging mechanism that captures full-text command input was found in the CLI implementation (`src/epyon/cli.py`) or the API endpoints (`web/api/main.py`).
- No implementation of group account identity tracking was identified in the provided source code.
- Requirement: NOT SATISFIED — no static evidence of privileged command auditing or group account identity logging exists.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Open
Confidence: 50/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must implement transaction recovery logs if it is transaction-based.
- The application utilizes a database for storing scan results and metadata, as evidenced by `web/api/db.py` and `web/api/scan_store.py`.
- However, the specific database configuration (e.g., Write-Ahead Logging (WAL) for SQLite or archival logging for Postgres) is not present in the provided source code or configuration files.
- Requirement: PARTIALLY SATISFIED — database usage is confirmed, but transaction recovery log configuration is not explicitly demonstrated in the static artifacts.

Remediation:
Configure the application database to utilize transactional logging.

---

### 93. APSC-DV-001050 | SV-222480r985972

- Rule ID: SV-222480r985972
- Severity: medium
- Rule Title: The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must provide centralized management and configuration of the content to be captured in audit records.
- A review of the Web UI API (`web/api/main.py`) and the project configuration files reveals no administrative interface or centralized configuration file that allows for the dynamic management of audit log content across application components.
- While the application performs various scans, there is no evidence of a centralized logging orchestrator that manages the 'what' of the audit capture.
- Requirement: NOT SATISFIED — no centralized log management configuration interface was identified.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Not Applicable
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes a centralized logging solution (AWS CloudWatch), which renders this requirement not applicable per the check content.
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-26_03-14-11/security-findings-summary-filtered.json — cites /deploy/terraform/modules/github-runner/lambda.tf regarding CloudWatch Log Group encryption (CKV_AWS_158) and retention (CKV_AWS_338)
- Requirement: NOT APPLICABLE — centralized logging solution is utilized

Remediation:
Configure the application to off-load audit records onto a different system as per approved schedule.

---

### 95. APSC-DV-001080 | SV-222482r961860

- Rule ID: SV-222482r961860
- Severity: medium
- Rule Title: The application must be configured to write application logs to a centralized log repository.

Status: Not a Finding
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is configured to write logs to AWS CloudWatch, a centralized log repository.
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-26_03-14-11/security-findings-summary-filtered.json — cites /deploy/terraform/modules/github-runner/lambda.tf regarding CloudWatch Log Group configuration (CKV_AWS_158, CKV_AWS_338)
- Centralized logging via AWS CloudWatch ensures logs are off-loaded from the application system expeditiously
- Requirement: SATISFIED — centralized log repository (AWS CloudWatch) is utilized

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Not Applicable
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes AWS CloudWatch for centralized logging, which manages storage capacity automatically, making fixed-volume capacity alarms not applicable.
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-26_03-14-11/security-findings-summary-filtered.json — cites /deploy/terraform/modules/github-runner/lambda.tf regarding CloudWatch Log Group configuration
- AWS CloudWatch is a managed service where storage is scaled by the provider; there is no fixed 'repository maximum' to reach 75% of
- Requirement: NOT APPLICABLE — centralized logging system utilized

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application lacks explicit configuration for real-time alerts specifically triggered by audit system failures.
- File: scripts/shell/send-webhook-notification.sh — implements a notification mechanism using `EPYON_CALLBACK_URL` and `EPYON_WEBHOOK_SECRET` to send HMAC-signed JSON payloads.
- Analysis: According to `.github/copilot-instructions.md`, this notification system is used for scan progress (scan start, tool start/complete, scan complete), not for monitoring the health or failure of the audit logging system itself.
- Requirement: NOT SATISFIED — no evidence of alerts configured to notify SA or ISSO specifically when the audit system fails.

Remediation:
Configure the log alerts to send an alarm when the audit system is in danger of failing or has failed.  

Configure the log alerts to be immediately sent to the application admin/SA and ISSO.

---

### 98. APSC-DV-001110 | SV-222485r960912

- Rule ID: SV-222485r960912
- Severity: medium
- Rule Title: The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No static evidence was found of alarming capabilities specifically tied to audit processing failures (e.g., hardware failure, capture failure, or storage errors).
- File: scripts/shell/send-webhook-notification.sh — provides a general notification utility, but there is no corresponding trigger in the application logic or infrastructure-as-code that monitors audit storage or capture health.
- Analysis: The application uses standard logging to files (e.g., in `scripts/shell/run-clamav-scan.sh` via `SCAN_LOG`), but there is no evidence of a monitoring agent or configuration that alarms when these logs cannot be written.
- Requirement: NOT SATISFIED — no specific audit processing failure alarms identified.

Remediation:
Configure the application to send an alarm in the event the audit system has failed or is failing.

---

### 99. APSC-DV-001120 | SV-222486r1043188

- Rule ID: SV-222486r1043188
- Severity: medium
- Rule Title: The application must shut down by default upon audit failure (unless availability is an overriding concern).

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not demonstrate a default shutdown mechanism or a documented compensating control (like local spooling or oldest-log overwriting) upon audit failure.
- Analysis: Review of `web/api/main.py`, `web/api/jobs.py`, and the various shell scripts (e.g., `scripts/shell/run-clamav-scan.sh`) shows no logic that monitors the success of audit writes and triggers a system halt or shutdown upon failure.
- Analysis: No configuration files (e.g., logrotate or application-level logging configs) were found that explicitly enforce the 'overwrite oldest logs first' policy as a requirement for audit failure handling.
- Requirement: NOT SATISFIED — no evidence of shutdown logic or audit-failure compensation mechanisms.

Remediation:
Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.

---

### 100. APSC-DV-001130 | SV-222487r960918

- Rule ID: SV-222487r960918
- Severity: medium
- Rule Title: The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application lacks a documented centralized audit logging system for its own operational records.
- While the application centrally stores security scan findings using `web/api/scan_store.py` and `web/api/db.py`, these are application data outputs rather than system audit records (logs of system events/user actions).
- No configuration for a centralized log management utility (e.g., Syslog, ELK, Splunk) is present in the provided source code or configuration files.
- Requirement: NOT SATISFIED — no evidence of a capability to centrally review and analyze system audit records.

Remediation:
Configure the application so all of the applications logs are available for review from one centralized location.

---

### 101. APSC-DV-001140 | SV-222488r960924

- Rule ID: SV-222488r960924
- Severity: medium
- Rule Title: The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide a mechanism to filter system audit records based on the required criteria (Users, Event types, IP addresses, etc.).
- File: `web/api/finding_search.py` — implements filtering for security findings, but this is distinct from filtering system audit logs.
- No evidence was found of a log management utility that allows filtering by the minimum criteria specified in the control (e.g., specific users, event dates, or IP addresses for system events).
- Requirement: NOT SATISFIED — audit record filtering capability is missing.

Remediation:
Configure the application filters to search event logs based on defined criteria.

---

### 102. APSC-DV-001150 | SV-222489r961056

- Rule ID: SV-222489r961056
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand reporting requirements.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide an audit reduction capability for generating on-demand reports from filtered system audit data.
- File: `_archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/portable-app-scanner.sh` — contains a `generate_summary_report` function, but this generates a summary of security scan results, not a report based on filtered system audit logs.
- No functionality exists to generate soft copy or screen-based reports from filtered audit event data as required.
- Requirement: NOT SATISFIED — on-demand audit reporting is missing.

Remediation:
Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.

---

### 103. APSC-DV-001160 | SV-222490r961413

- Rule ID: SV-222490r961413
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand audit review and analysis.

Status: Open
Confidence: 0/100

Evidence:
- Static repository review completed on 2026-11-15.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.

---

### 104. APSC-DV-001170 | SV-222491r961416

- Rule ID: SV-222491r961416
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

Status: Open
Confidence: 0/100

Evidence:
- Static repository review completed on 2026-11-15.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to provide an audit reduction capability that supports forensic investigations.

---

### 105. APSC-DV-001180 | SV-222492r961419

- Rule ID: SV-222492r961419
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand audit review and analysis.

Status: Open
Confidence: 0/100

Evidence:
- Static repository review completed on 2026-11-15.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 106. APSC-DV-001190 | SV-222493r961422

- Rule ID: SV-222493r961422
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand reporting requirements.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must provide on-demand report generation for audit records.
- The application implements reporting for security scan findings via `scripts/shell/generate-dashboard.py` and `scripts/shell/generate-security-dashboard.sh`.
- Search and filtering of findings are implemented in `web/api/finding_search.py`.
- However, these features pertain to the results of security scans performed on target repositories, not to the application's own internal audit logs (e.g., user access logs, administrative actions).
- No evidence of a built-in audit log reporting interface or a configured centralized logging solution (e.g., ELK, Splunk) was found in the provided source code.
- Requirement: PARTIALLY SATISFIED — reporting exists for scan findings, but not for internal application audit records.

Remediation:
Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 107. APSC-DV-001200 | SV-222494r961425

- Rule ID: SV-222494r961425
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must provide report generation for after-the-fact security incident investigations.
- The application provides a mechanism to track and review findings via the web UI and API (`web/api/scan_store.py`), but this is for vulnerability management of target apps.
- There is no evidence of an internal audit trail or reporting capability designed to support the investigation of security incidents occurring within the Epyon application itself.
- No configuration for external log management for incident response was identified.
- Requirement: NOT SATISFIED — no internal audit reporting for security incident investigation found.

Remediation:
Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.

---

### 108. APSC-DV-001210 | SV-222495r961428

- Rule ID: SV-222495r961428
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must provide audit reduction (filtering) that does not alter original content or time ordering.
- The application implements filtering for security findings in `web/api/finding_search.py`, which allows users to narrow down results without modifying the underlying data in the database (`web/api/db.py`).
- However, this control specifically targets the reduction of audit records (system/event logs), not security findings.
- Since no internal audit log reporting/filtering system was identified, compliance with the non-alteration requirement for audit records cannot be verified.
- Requirement: NOT SATISFIED — no internal audit log reduction capability identified to assess.

Remediation:
Configure the application to not alter original log content or time ordering of audit records.

---

### 109. APSC-DV-001220 | SV-222496r961431

- Rule ID: SV-222496r961431
- Severity: medium
- Rule Title: The application must provide a report generation capability that does not alter original content or time ordering of audit records.

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application provides report generation capabilities, but the implementation details are not available in the provided source code to verify that original audit records are not altered.
- File: scripts/shell/README.md — lists report generation scripts: `generate-security-dashboard.sh`, `generate-interactive-dashboard.sh`, `consolidate-security-reports.sh`, and `generate-scan-findings-summary.sh`.
- Requirement: The control requires verification that filtering or report generation does not modify the source logs/audit records.
- Missing Evidence: The actual source code for the listed shell scripts and the API logic that handles report generation was not provided in the context window.
- Requirement: PARTIALLY SATISFIED — report generation functionality exists, but its non-destructive nature cannot be verified statically without the script contents.

Remediation:
Configure and design the application to not modify source logs when filtering events.

---

### 110. APSC-DV-001250 | SV-222497r960927

- Rule ID: SV-222497r960927
- Severity: medium
- Rule Title: The applications must use internal system clocks to generate time stamps for audit records.

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no explicit configuration or code provided that demonstrates the application's audit logging mechanism or its reliance on the internal system clock.
- File: Dockerfile — shows the application is built on `cgr.dev/chainguard/wolfi-base:latest` and uses Python 3.12, which typically defaults to the system clock for timestamps, but no explicit logging configuration is provided.
- Requirement: The application must use internal system clocks to generate time stamps for audit records.
- Missing Evidence: No logging configuration files (e.g., `logging.conf`, `logback.xml`) or timestamp generation logic in the provided source files.
- Requirement: NOT SATISFIED — compliance cannot be confirmed from the provided static artifacts.

Remediation:
Configure the application to use the hosting systems internal clock for audit record generation.

---

### 111. APSC-DV-001260 | SV-222498r961443

- Rule ID: SV-222498r961443
- Severity: medium
- Rule Title: The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence was found in the provided source code or configuration files indicating that audit timestamps are mapped to UTC or GMT.
- File: Dockerfile — defines environment variables (`HOST`, `PORT`, `PYTHONUNBUFFERED`), but does not define `TZ` or any timezone-related settings.
- Requirement: Audit record timestamps must be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
- Missing Evidence: No explicit timezone configuration in the API code or infrastructure-as-code files provided.
- Requirement: NOT SATISFIED — compliance cannot be confirmed from the provided static artifacts.

Remediation:
Configure the application to use the underlying system clock that maps to relevant UTC or GMT timezone.

---

### 112. APSC-DV-001270 | SV-222499r961446

- Rule ID: SV-222499r961446
- Severity: medium
- Rule Title: The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must record audit timestamps with at least one-second granularity.
- No logging configuration files or source code implementing the logging framework (e.g., Python `logging` module configuration) were provided in the source snippets to verify the timestamp format.
- While the application likely relies on the underlying OS for timestamping (which would make this N/A), this cannot be confirmed without reviewing the actual logging implementation in `web/api/main.py` or similar files.
- Requirement: PARTIALLY SATISFIED — logging is performed (as evidenced by the existence of scan results), but the specific timestamp granularity cannot be verified from the provided static artifacts.

Remediation:
Configure the application to leverage the underlying operating system as the time source when recording time stamps or design the application to ensure granularity of 1 second as the minimum degree of precision.

---

### 113. APSC-DV-001280 | SV-222500r960930

- Rule ID: SV-222500r960930
- Severity: medium
- Rule Title: The application must protect audit information from any type of unauthorized read access.

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect audit information from unauthorized read access.
- File: `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` — states that results are stored in a structured hierarchy: `scans/{project}_{user}_{timestamp}/`.
- No evidence of file system permissions (e.g., `chmod` commands in `Dockerfile` or `scripts/deploy.sh`) or application-level access control lists (ACLs) was found to restrict read access to these directories to authorized roles only.
- Requirement: NOT SATISFIED — storage location is identified, but access restrictions are not documented or implemented in the provided source code.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish permissions that control access to the audit logs and audit configuration settings.

---

### 114. APSC-DV-001290 | SV-222501r960933

- Rule ID: SV-222501r960933
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized modification.

Status: Open
Confidence: 40/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect audit information from unauthorized modification.
- File: `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` — states that results are stored in a structured hierarchy: `scans/{project}_{user}_{timestamp}/`.
- No evidence of file system permissions, write-protection mechanisms, or cryptographic hashing of log files was found in the provided source code to prevent unauthorized modification of the audit records.
- Requirement: NOT SATISFIED — storage location is identified, but modification protections are not documented or implemented in the provided source code.

Remediation:
Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 115. APSC-DV-001300 | SV-222502r960936

- Rule ID: SV-222502r960936
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized deletion.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application generates audit information in the form of scan manifests and metadata, but lacks explicit controls to prevent unauthorized deletion.
- Requirement: Protect audit information from unauthorized deletion.
- Evidence of Audit Info: `documentation/SECURITY.md` states "Audit trails: Comprehensive scan manifests and metadata tracking".
- Implementation: Audit records are stored as JSON files in scan directories (e.g., `stig-results-*.json`) and managed via `web/api/scan_store.py`.
- Missing Evidence: No role-based access control (RBAC) or filesystem permission enforcement is present in the source code to restrict the deletion of these files or database entries to authorized administrators.
- Requirement: PARTIALLY SATISFIED — audit trails are created, but protection against unauthorized deletion is not demonstrated in the static artifacts.

Remediation:
Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 116. APSC-DV-001310 | SV-222503r960939

- Rule ID: SV-222503r960939
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized access.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes a set of distinct audit tools (scanning scripts), but does not implement application-level access restrictions for them.
- Requirement: Protect audit tools from unauthorized access.
- Identified Tools: `.github/copilot-instructions.md` identifies the audit tools as `epyon.sh`, `scripts/shell/run-target-security-scan.sh`, and various `scripts/shell/run-*.sh` / `scripts/shell/run-*.py` scripts.
- Implementation: These tools are executed as shell scripts from the command line.
- Missing Evidence: There is no evidence of an access control mechanism within the application that restricts the execution of these scripts to approved users; access is deferred to the host operating system's filesystem permissions, which are not configured within the repository.
- Requirement: NOT SATISFIED — no application-level access control for audit tools is implemented.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 117. APSC-DV-001320 | SV-222504r960942

- Rule ID: SV-222504r960942
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized modification.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application's audit tools are implemented as scripts without evidence of modification protections or integrity checks.
- Requirement: Protect audit tools from unauthorized modification.
- Identified Tools: `.github/copilot-instructions.md` identifies the tools as scripts in `scripts/shell/` (e.g., `run-stig-assessment.py`).
- Implementation: The tools are stored as plaintext scripts in the repository.
- Missing Evidence: No file integrity monitoring (FIM), cryptographic signing, or specific permission enforcement is implemented in the source code to prevent or detect unauthorized modifications to these scripts.
- Requirement: NOT SATISFIED — no mechanism to prevent or detect unauthorized modification of audit tools is present.

Remediation:
Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 118. APSC-DV-001330 | SV-222505r960945

- Rule ID: SV-222505r960945
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized deletion.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect audit tools from unauthorized deletion via file permission restrictions.
- No static evidence found in the source code or configuration files (e.g., Dockerfile, shell scripts) that explicitly sets or enforces OS-level file permissions (chmod/chown) to prevent the deletion of the security tools (Trivy, Grype, etc.) or the orchestration scripts.
- The tools are external binaries; their protection is dependent on the host environment's security configuration, which is not defined within the application repository.
- Requirement: NOT SATISFIED — no static artifacts demonstrate the enforcement of file permission restrictions for audit tools.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must back up audit records at least every seven days onto a different system.
- No built-in backup scheduling mechanism (e.g., cron jobs, internal timers, or cloud backup integration) was identified in the source code to automate the transfer of audit logs to a separate system every 7 days.
- While the repository manifest contains an `_archive` directory, this represents a version control archive of the repository itself, not a functional application feature for backing up runtime audit records.
- Requirement: NOT SATISFIED — no evidence of a built-in 7-day backup capability for audit records.

Remediation:
Configure application backup settings to backup application audit logs every 7 days.

---

### 120. APSC-DV-001350 | SV-222507r960951

- Rule ID: SV-222507r960951
- Severity: medium
- Rule Title: The application must use cryptographic mechanisms to protect the integrity of audit information.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application uses cryptographic hashes to protect the integrity of audit information.
- File: `documentation/SCAN_MANIFEST_GUIDE.md` — "File Hashes: SHA-256 cryptographic hashes of all report files"
- File: `documentation/SCAN_MANIFEST_GUIDE.md` — "Manifest Hash: Self-integrity verification hash"
- The implementation of SHA-256 hashes for every report file and a master hash for the manifest ensures that any unauthorized modification of the audit data can be detected.
- Requirement: SATISFIED — cryptographic integrity checks are enforced via the scan manifest system using SHA-256.

Remediation:
Configure the application to create an integrity check consisting of a cryptographic hash or one-way digest that can be used to establish the integrity when storing log files.

---

### 121. APSC-DV-001360 | SV-222508r961206

- Rule ID: SV-222508r961206
- Severity: medium
- Rule Title: Application audit tools must be cryptographically hashed.

Status: Not Applicable
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide separate audit tools for viewing or manipulating log data.
- The application generates static security reports in JSON and HTML formats (e.g., `clamav-results.json`, `security-dashboard.html`) rather than providing a separate executable or library tool for log manipulation.
- Orchestration is handled via standard shell scripts in `scripts/shell/` which are part of the core application logic, not separate audit management utilities.
- Requirement: NOT APPLICABLE — the application does not provide separate tools in the form of a file to view or manipulate application log data as defined in the control.

Remediation:
Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.

---

### 122. APSC-DV-001370 | SV-222509r961206

- Rule ID: SV-222509r961206
- Severity: medium
- Rule Title: The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

Status: Not Applicable
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide separate audit tools for viewing or manipulating log data.
- As established in APSC-DV-001360, there are no separate file-oriented audit tools provided by the application to view or manipulate log data, query data, or generate reports.
- Because no such tools exist, there is no requirement to establish a process for periodically checking their cryptographic hash values.
- Requirement: NOT APPLICABLE — no separate audit tools are provided by the application.

Remediation:
Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.

---

### 123. APSC-DV-001390 | SV-222510r1015689

- Rule ID: SV-222510r1015689
- Severity: medium
- Rule Title: The application must prohibit user installation of software without explicit privileged status.

Status: Not Applicable
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide the ability to install software components, modules, plugins, or extensions.
- Review of the source code in `src/epyon/`, `web/api/`, and `scripts/shell/` reveals no functionality for user-driven software installation or product function extension.
- The application is deployed as a set of scripts and a Python package; it does not feature a plugin architecture or a user interface for installing extensions.
- Requirement: NOT APPLICABLE — the application does not provide the ability to install software components, modules, plugins, or extensions.

Remediation:
Configure the application to prohibit user installation of software without explicit permission.

---

### 124. APSC-DV-001410 | SV-222511r961461

- Rule ID: SV-222511r961461
- Severity: medium
- Rule Title: The application must enforce access restrictions associated with changes to application configuration.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- Access to application configuration files is restricted to authorized operator users.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Configuration files (approved-base-images.conf, etc.) are readable only by the operator user."
- Requirement: SATISFIED — manual STIG documentation confirms that configuration files are protected by OS-level permissions restricting access to the operator user.

Remediation:
Configure the application to limit access to configuration settings to only authorized users.

---

### 125. APSC-DV-001420 | SV-222512r1015690

- Rule ID: SV-222512r1015690
- Severity: medium
- Rule Title: The application must audit who makes configuration changes to the application.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence was found of an audit mechanism that logs which specific user account makes changes to the application configuration.
- Search: Reviewed `web/api/`, `scripts/shell/`, and `documentation/` for audit logging or event tracking related to configuration updates.
- Missing: A logging implementation that captures the identity of the privileged user performing the change and the nature of the modification.
- Requirement: NOT SATISFIED — audit records for configuration changes are not demonstrated in the provided source code.

Remediation:
Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.

---

### 126. APSC-DV-001430 | SV-222513r1015691

- Rule ID: SV-222513r1015691
- Severity: medium
- Rule Title: The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements image signing but does not demonstrate a mechanism to prevent the installation of unsigned patches or components.
- File: scripts/shell/sign-image-cosign.sh — provides the capability to sign images using Cosign.
- Missing: Evidence of a verification gate, configuration setting, or installation procedure that explicitly blocks the application of unsigned patches or software components.
- Requirement: PARTIALLY SATISFIED — signing capability exists, but the enforcement mechanism to prevent unsigned installation is not evidenced.

Remediation:
Design and configure the application to have the capability to prevent unsigned patches and packages from being installed.

Provide a cryptographic hash value that can be verified by a system administrator prior to installation.

---

### 127. APSC-DV-001440 | SV-222514r960960

- Rule ID: SV-222514r960960
- Severity: medium
- Rule Title: The applications must limit privileges to change the software resident within software libraries.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes OS-level permissions and container isolation to protect its components, but specific restrictions on software library update functionality are not explicitly documented.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Script files in scripts/shell/ are owned by the installing user and protected by OS file permissions."
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Each scanner runs in isolated Docker container... No direct access to host filesystem outside scan target"
- Requirement: PARTIALLY SATISFIED — While OS permissions and container isolation are implemented to protect the resident software, there is no evidence of a specific mechanism within the application to restrict the capability to update software libraries to authorized users only.

Remediation:
Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.

---

### 128. APSC-DV-001460 | SV-222515r961863

- Rule ID: SV-222515r961863
- Severity: medium
- Rule Title: An application vulnerability assessment must be conducted.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The Epyon platform undergoes comprehensive vulnerability assessments using a multi-layered scanning orchestration process integrated into its CI/CD pipeline.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Epyon is a comprehensive security scanning orchestration platform... CVE-tracked dependency management"
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-25_23-58-59/consolidated-reports/README.md — lists 8 tools used for assessment: SonarQube, TruffleHog, ClamAV, Helm, Checkov, Trivy, Grype, and Xeol
- File: .github/workflows/epyon-scan.yml — demonstrates the automation of security scans within the GitHub Actions workflow
- Requirement: SATISFIED — Vulnerability assessments are conducted using a diverse set of tools covering code quality, secrets, malware, IaC, and container vulnerabilities.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements process isolation via containers, but does not cite a specific organization-defined policy for restricting program execution.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Process Isolation: Each scanner runs in isolated Docker container... No direct access to host filesystem outside scan target"
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Git repository access control enforces DAC at the source code level via branch protection rules."
- Requirement: PARTIALLY SATISFIED — While containerization provides a level of execution restriction (isolation), there is no evidence of a formal program execution restriction policy (e.g., AppLocker, RBAC for execution, or Java Security Manager) as required by the control.

Remediation:
Restrict application execution in accordance with the policy, terms, and conditions specified.

---

### 130. APSC-DV-001490 | SV-222517r961479

- Rule ID: SV-222517r961479
- Severity: medium
- Rule Title: The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to employ a deny-all, permit-by-exception policy for authorized software execution.
- No evidence of software whitelisting configurations (e.g., AppLocker, Software Restriction Policies, or Java Security Manager) was found in the provided source code or configuration files.
- No RBAC or custom capability settings restricting program execution were identified in the repository manifest or source files.
- Requirement: NOT SATISFIED — no static evidence of a deny-all, permit-by-exception execution policy exists.

Remediation:
Configure the application to utilize a deny-all, permit-by-exception policy when allowing the execution of authorized software.

---

### 131. APSC-DV-001500 | SV-222518r960963

- Rule ID: SV-222518r960963
- Severity: medium
- Rule Title: The application must be configured to disable non-essential capabilities.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must be configured to disable non-essential capabilities.
- No explicit configuration for disabling non-essential services or capabilities was found in the root Dockerfile or application settings.
- In `tests/fixtures/self-assessment/inference/Dockerfile`, the application is explicitly configured to run as root: `USER root`, which is a non-essential and high-risk capability.
- While `documentation/ML_SECURITY_GUIDE.md` mentions that Epyon can scan for dangerous capabilities (e.g., `CAP_SYS_ADMIN`), there is no evidence that the Epyon application itself has been hardened to disable its own non-essential capabilities.
- Requirement: NOT SATISFIED — no evidence of capability reduction; some fixtures explicitly enable root privileges.

Remediation:
Disable application extraneous application functionality that is not required in order to fulfill the application's mission.

---

### 132. APSC-DV-001510 | SV-222519r1043177

- Rule ID: SV-222519r1043177
- Severity: medium
- Rule Title: The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must use only functions, ports, and protocols permitted in the PPSM CAL.
- The application utilizes a web framework as indicated by `pyproject.toml` optional dependencies: `fastapi>=0.100.0` and `uvicorn[standard]>=0.23.0`.
- A sample configuration in `tests/fixtures/self-assessment/inference/Dockerfile` specifies `EXPOSE 8080`.
- No documentation or configuration file was found that cross-references the used ports (e.g., 8080) or protocols against the PPSM Category Assurance List (CAL).
- Requirement: NOT SATISFIED — ports are defined in fixtures, but no verification against PPSM CAL is documented or enforced.

Remediation:
Configure the application to utilize application ports approved by the PPSM CAL.

---

### 133. APSC-DV-001520 | SV-222520r1050664

- Rule ID: SV-222520r1050664
- Severity: medium
- Rule Title: The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must require reauthentication when organization-defined circumstances, such as privilege escalation or role changes, occur.
- No evidence of user role definitions, role-switching logic, or privilege escalation mechanisms found in the provided source files.
- No implementation of re-authentication prompts (e.g., password or token requests) found in the provided API or frontend artifacts.
- Requirement: NOT SATISFIED — no static evidence of role-based re-authentication mechanisms.

Remediation:
Configure the application to require reauthentication before user privilege is escalated and user roles are changed.

---

### 134. APSC-DV-001530 | SV-222521r985974

- Rule ID: SV-222521r985974
- Severity: medium
- Rule Title: The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must require devices to reauthenticate periodically.
- No evidence of device-level authentication (e.g., for XML gateways, SOA gateways, or application firewalls) found in the provided source code or configuration.
- No configuration settings for re-authentication intervals or timeouts for devices found in `docker-compose.yml` or other provided files.
- Requirement: NOT SATISFIED — no static evidence of device re-authentication enforcement.

Remediation:
Configure the application to require reauthentication periodically.

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must uniquely identify and authenticate organizational users or processes acting on their behalf.
- No evidence of a user authentication system (e.g., login endpoints, session management, or identity provider integration) found in the provided source files.
- While `docker-compose.yml` defines API tokens for external services (e.g., `JIRA_API_TOKEN`, `GH_PAT`, `OPENAI_API_KEY`), no mechanism for authenticating human users to the application itself is present in the provided context.
- Requirement: NOT SATISFIED — no static evidence of unique user identification and authentication.

Remediation:
Configure the application to uniquely identify and authenticate users and user processes.

---

### 136. APSC-DV-001550 | SV-222523r960972

- Rule ID: SV-222523r960972
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to use multifactor (Alt. Token) authentication for network access to privileged accounts, but no such implementation is found in the provided source code or documentation.
- No references to MFA, Alt Tokens, or privileged account authentication logic were found in the `web/api/` directory or the `documentation/` folder.
- The `documentation/SECURITY.md` file provides general guidance on securing credentials but does not specify an authentication mechanism for application administrators.
- Requirement: NOT SATISFIED — no evidence of MFA or Alt Token enforcement for privileged accounts.

Remediation:
Configure the application to use an Alt. Token when providing network access to privileged application accounts.

---

### 137. APSC-DV-001560 | SV-222524r961494

- Rule ID: SV-222524r961494
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must accept Personal Identity Verification (PIV) credentials, but no evidence of this capability exists in the provided artifacts.
- A search for 'PIV', 'CAC', 'certificate', and 'PKI' across all provided source files and documentation yielded no results.
- The application is not identified as hosting publicly releasable data (per `documentation/SECURITY.md`, scan results are treated as sensitive), making this control applicable.
- Requirement: NOT SATISFIED — no evidence that the application accepts PIV/CAC credentials.

Remediation:
Configure the application to require CAC authentication.

---

### 138. APSC-DV-001570 | SV-222525r961497

- Rule ID: SV-222525r961497
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must electronically verify PIV credentials, including requiring a CAC PIN, but no such implementation is present.
- No code implementing certificate verification or PIN prompts was found in the `web/` or `src/` directories.
- No documentation in `documentation/SYSTEM_ARCHITECTURE.md` or `documentation/SECURITY.md` describes the authentication flow for PIV/CAC verification.
- Requirement: NOT SATISFIED — no evidence of electronic PIV verification or PIN requirement.

Remediation:
Configure the application to require CAC authentication.

---

### 139. APSC-DV-001580 | SV-222526r960975

- Rule ID: SV-222526r960975
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must use multifactor authentication (e.g., CAC, Alt. Token) for network access to non-privileged accounts. A review of the provided source code and documentation found no implementation of PKI, CAC, or Alt Token authentication for network access.
- File: documentation/SYSTEM_ARCHITECTURE.md — mentions a 'Web UI' as a trigger for scans but does not define the authentication mechanism used to access it.
- File: documentation/SECURITY.md — discusses 'Secure Credentials' in the context of API tokens and .env files, but does not mention user MFA or CAC integration.
- Requirement: NOT SATISFIED — no evidence of MFA implementation for network access to non-privileged accounts.

Remediation:
Configure the application to require CAC or Alt. Token authentication for non-privileged network access to non-privileged accounts.

---

### 140. APSC-DV-001590 | SV-222527r1015693

- Rule ID: SV-222527r1015693
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must use multifactor authentication (Alt. Token) for local access to privileged accounts. No evidence of Alt Token authentication for local console access was found in the provided source code or documentation.
- File: [No relevant file found] — no configuration or code implementing local console authentication or Alt Token validation was provided.
- Requirement: NOT SATISFIED — no evidence of MFA implementation for local privileged access.

Remediation:
Configure the application to only use Alt. Tokens when locally accessing privileged application accounts.

---

### 141. APSC-DV-001600 | SV-222528r1015694

- Rule ID: SV-222528r1015694
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must use multifactor authentication (e.g., CAC, Alt. Token) for local access to non-privileged accounts. A review of the provided source code and documentation found no implementation of PKI, CAC, or Alt Token authentication for local access.
- File: [No relevant file found] — no configuration or code implementing local console authentication or CAC/Alt Token validation was provided.
- Requirement: NOT SATISFIED — no evidence of MFA implementation for local non-privileged access.

Remediation:
Configure the application to require CAC or Alt. Token authentication for nonprivileged network access.

---

### 142. APSC-DV-001610 | SV-222529r1015695

- Rule ID: SV-222529r1015695
- Severity: medium
- Rule Title: The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or authentication mechanisms, making group/individual authenticator requirements not applicable.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "This application is an internal library/SDK with no user-facing components or authentication mechanisms."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — No application-level authentication exists.

Remediation:
Design and configure the application to individually authenticate group account members prior to allowing access.

---

### 143. APSC-DV-001620 | SV-222530r960993

- Rule ID: SV-222530r960993
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement an internal authentication layer or privileged user accounts.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — No application-level authentication exists.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating privileged accounts.

---

### 144. APSC-DV-001630 | SV-222531r1015696

- Rule ID: SV-222531r1015696
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement an internal authentication layer or non-privileged user accounts.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — "no user-facing components or authentication mechanisms."
- Requirement: NOT APPLICABLE — No application-level authentication exists.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating nonprivileged accounts.

---

### 145. APSC-DV-001640 | SV-222532r960999

- Rule ID: SV-222532r960999
- Severity: medium
- Rule Title: The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide static evidence of mutual authentication configuration.
- No instances of `CLIENT-CERT` found in any `web.xml` or deployment descriptors within the repository.
- No SSL/TLS configuration files (e.g., Nginx `.conf` or Apache `.conf`) were provided that specify `ssl_verify_client` or equivalent client certificate request settings.
- No documentation in `documentation/` or `README.md` indicates that mutual authentication is mandated by the data owner or DoD policy for this specific application.
- Requirement: NOT SATISFIED — no evidence of mutual authentication implementation found in static artifacts.

Remediation:
Configure the application to utilize mutual authentication when specified by data protection requirements.

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application lacks explicit evidence of authentication for all network-connected endpoint devices.
- The application implements a web API (`web/api/main.py`) and a CLI tool, but there is no static configuration showing how non-user endpoint devices (e.g., SOA gateways) are authenticated before connection.
- No evidence of Client Certificate Authentication or other approved non-Basic authentication mechanisms for remote service consumers was found in the provided source code.
- While `documentation/STIG_COMPLIANCE_GUIDE.md` describes Epyon as a "CLI tool that invokes container-based security scanners," the presence of a web API means it is not exclusively an interactive end-user application.
- Requirement: NOT SATISFIED — authentication mechanism for remote endpoint devices is not documented or visible in static code.

Remediation:
Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence that the application handles non-releasable data or implements mutual SSL/TLS for such data.
- No documentation in `documentation/` or `README.md` identifies the application as processing non-releasable data.
- No configuration for mutual SSL/TLS (client certificate authentication) was identified in the source code or configuration files.
- No `web.xml` files containing `login-config` set to `CLIENT-CERT` were found in the repository.
- Requirement: NOT SATISFIED — mutual SSL/TLS is not implemented, and data classification is not documented to determine if the control is applicable.

Remediation:
Configure the application to utilize mutual authentication when the application is processing non-releasable data.

---

### 148. APSC-DV-001670 | SV-222535r1015697

- Rule ID: SV-222535r1015697
- Severity: medium
- Rule Title: The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not authenticate devices or maintain device identifiers.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the architectural constructs (device IDs, user accounts) required for this control to apply.

Remediation:
Configure the application to disable device accounts after 35 days of inactivity or to utilize DOD PKI certificates that provide an expiration date.

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — Password length requirements do not apply to an application without a password system.

Remediation:
Configure the application to require 15 characters in the password.

---

### 150. APSC-DV-001690 | SV-222537r1015699

- Rule ID: SV-222537r1015699
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one uppercase character be used.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — Password complexity requirements do not apply to an application without a password system.

Remediation:
Configure the application to require at least one uppercase character in the password.

---

### 151. APSC-DV-001700 | SV-222538r1015700

- Rule ID: SV-222538r1015700
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one lowercase character be used.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks a user authentication/password system, making password complexity requirements inapplicable.

Remediation:
Configure the application to require at least one lowercase character in the password.

---

### 152. APSC-DV-001710 | SV-222539r1015701

- Rule ID: SV-222539r1015701
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one numeric character be used.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks a user authentication/password system, making password complexity requirements inapplicable.

Remediation:
Configure the application to require at least one numeric character in the password.

---

### 153. APSC-DV-001720 | SV-222540r1015702

- Rule ID: SV-222540r1015702
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one special character be used.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks a user authentication/password system, making password complexity requirements inapplicable.

Remediation:
Configure the application to require at least one special character in the password.

---

### 154. APSC-DV-001730 | SV-222541r1043189

- Rule ID: SV-222541r1043189
- Severity: medium
- Rule Title: The application must require the change of at least eight of the total number of characters when passwords are changed.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application lacks a password-based authentication system, making password change requirements inapplicable.

Remediation:
Configure the application to require the change of at least eight characters in the password when passwords are changed.

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application does not store passwords as it has no user authentication system.

Remediation:
Use strong cryptographic hash functions when creating password hash values.

Utilize random salt values when creating the password hash.

Ensure strong access control permissions on data files containing authentication data.

---

### 156. APSC-DV-001750 | SV-222543r961029

- Rule ID: SV-222543r961029
- Severity: high
- Rule Title: The application must transmit only cryptographically-protected passwords.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application does not transmit passwords as it has no user authentication system.

Remediation:
Configure the application to encrypt passwords when they are being transmitted.

---

### 157. APSC-DV-001760 | SV-222544r1015705

- Rule ID: SV-222544r1015705
- Severity: medium
- Rule Title: The application must enforce 24 hours/1 day as the minimum password lifetime.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application does not implement a password-based authentication system, making password lifetime controls inapplicable.

Remediation:
Configure the application to have a minimum password lifetime of 24 hours.

---

### 158. APSC-DV-001770 | SV-222545r1043190

- Rule ID: SV-222545r1043190
- Severity: medium
- Rule Title: The application must enforce a 60-day maximum password lifetime restriction.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application does not implement a password-based authentication system, making password expiration controls inapplicable.

Remediation:
Configure the application to have a maximum password lifetime of 60 days.

---

### 159. APSC-DV-001780 | SV-222546r1015267

- Rule ID: SV-222546r1015267
- Severity: medium
- Rule Title: The application must prohibit password reuse for a minimum of five generations.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not use passwords for user authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application does not implement a password-based authentication system, making password reuse controls inapplicable.

Remediation:
Configure the application to prohibit password reuse for up to five passwords.

---

### 160. APSC-DV-001790 | SV-222547r985976

- Rule ID: SV-222547r985976
- Severity: medium
- Rule Title: The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize a password-based authentication system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application is a CLI-based tool without a user authentication layer or password management.

Remediation:
Configure the application to specify when a password is temporary and change the temporary password on the first use.

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not utilize a password-based authentication system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- Requirement: NOT APPLICABLE — The application is a CLI-based tool without a user authentication layer or password management.

Remediation:
Use a CAC to authenticate users instead of using passwords. If application users are prohibited or prevented from obtaining a CAC due to DoD policy requirements and passwords are the only viable option, design the application to utilize a secure password change or password reset process.

Utilize out of band (OOB) communication techniques to communicate password change requests to users.

Ensure verification processes exist that allow users to validate the change request prior to implementing the password change.

Ensure users are only allowed to change their own passwords.

---

### 162. APSC-DV-001800 | SV-222549r961521

- Rule ID: SV-222549r961521
- Severity: medium
- Rule Title: The application must terminate existing user sessions upon account deletion.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement user accounts or session management.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application is a stateless CLI tool with no server-side session management or user account store.

Remediation:
Configure the application to terminate existing sessions of users whose accounts are deleted.

---

### 163. APSC-DV-001810 | SV-222550r961038

- Rule ID: SV-222550r961038
- Severity: high
- Rule Title: The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is configured to validate certificates against a trust anchor, but lacks revocation status checking.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — references `config/tls.yaml` with `client_ca_file: /etc/ssl/dod-root-ca.pem` as the trust anchor
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — references `src/auth/certAuth.ts` and the `verifyClientCertificate()` function for certificate chain validation
- Gap: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md explicitly states "Certificate revocation checking (OCSP) is not implemented — this is a gap"
- Requirement: PARTIALLY SATISFIED — trust anchor is defined and chain validation is implemented, but the requirement for "status information" (OCSP/CRL) is not met

Remediation:
Design the application to construct a certification path to an accepted trust anchor when using PKI-based authentication.

---

### 164. APSC-DV-001820 | SV-222551r961041

- Rule ID: SV-222551r961041
- Severity: high
- Rule Title: The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence was found regarding the storage or access control of the application's private keys.
- Search of provided source code and manual documentation yielded no references to private key storage locations (e.g., HSM, Key Vault, or specific file paths with restricted permissions)
- No configuration files (e.g., Dockerfile, docker-compose.yml) specify the mounting or protection of cryptographic keys
- Requirement: NOT SATISFIED — evidence of authorized access enforcement for private keys is missing

Remediation:
Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence demonstrating how authenticated PKI identities are mapped to individual user or group accounts.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — mentions `verifyClientCertificate()` in `src/auth/certAuth.ts` for authentication, but does not describe the subsequent identity mapping process
- The source code for `src/auth/certAuth.ts` was not provided in the context window for static analysis of the mapping logic
- Requirement: NOT SATISFIED — the process for mapping certificate data to a specific user or group is not documented or visible in the provided artifacts

Remediation:
Configure the application to map certificate information to individual users or group accounts or create a process for automatically determining the individual user or group based on certificate information provided in the logs.

---

### 166. APSC-DV-001840 | SV-222553r1015707

- Rule ID: SV-222553r1015707
- Severity: medium
- Rule Title: The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application lacks a local cache of certificate revocation data for PKI-based authentication.
- Manual Documentation: `documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md` (under APSC-DV-003320) explicitly states: "Certificate revocation checking (OCSP) is not implemented — this is a gap"
- Source Code: No implementation of CRL (Certificate Revocation List) import processes or local caching mechanisms was found in the provided source files.
- Requirement: NOT SATISFIED — revocation checking is explicitly documented as a gap, and no local CRL cache is implemented to support offline validation.

Remediation:
Implement a CRL import process and configure the application to check the CRL if OCSP is not available.

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement a password or PIN system, making the display of such credentials impossible.
- File: `documentation/STIG_COMPLIANCE_GUIDE.md` — "Epyon has no user accounts, user management, password system, or identity store."
- Architecture: As a CLI-driven security scanner without an internal identity store or user authentication mechanism, there are no password input fields to obfuscate.
- Requirement: NOT APPLICABLE — no password/PIN entry exists within the application.

Remediation:
Configure the application to obfuscate passwords and PINs when they are being entered so they cannot be read.

Design the application so obfuscated passwords cannot be copied and then pasted as clear text.

---

### 168. APSC-DV-001860 | SV-222555r961050

- Rule ID: SV-222555r961050
- Severity: high
- Rule Title: The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Status: Not Applicable
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide authenticated access to a cryptographic module for management purposes.
- Architecture: Epyon is a security scanning tool that utilizes standard libraries for HTTPS communication and data parsing; it does not function as a cryptographic module that requires administrative authentication for its own management.
- Requirement: NOT APPLICABLE — the application does not provide authenticated access to a cryptographic module as defined by the control.

Remediation:
Use FIPS-approved cryptographic modules.

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not host non-organizational users as it lacks a user authentication system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application is a CLI tool without a user account or authentication construct, and therefore does not host non-organizational users.

Remediation:
Configure the application to identify and authenticate all non-organizational users.

---

### 170. APSC-DV-001880 | SV-222557r961527

- Rule ID: SV-222557r961527
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is not PK-enabled because it does not implement a user authentication layer.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — Without an authentication layer, the application cannot accept PIV credentials.

Remediation:
Configure the application to accept PIV credentials when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 171. APSC-DV-001890 | SV-222558r961530

- Rule ID: SV-222558r961530
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is not PK-enabled because it does not implement a user authentication layer.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — Without an authentication layer, the application cannot verify PIV credentials.

Remediation:
Configure the application to verify the PIV credentials presented when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 172. APSC-DV-001900 | SV-222559r1015708

- Rule ID: SV-222559r1015708
- Severity: medium
- Rule Title: The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is intended for government use but does not demonstrate the use of FICAM-approved credentials.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — explicitly lists "FedRAMP (Government)" under Regulatory Compliance Support, indicating it is intended for federal government partners.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — specifies "Role-based access control via GitHub" as the access method.
- No evidence of PKI, PIV, CAC, or other FICAM-approved third-party credential integration was found in the source code or configuration.
- Requirement: PARTIALLY SATISFIED — Access is controlled via GitHub RBAC, but specific FICAM-approved credentials are not implemented.

Remediation:
Configure applications intended to be accessible to nonfederal government agencies to use FICAM-approved third-party credentials.

---

### 173. APSC-DV-001910 | SV-222560r1067800

- Rule ID: SV-222560r1067800
- Severity: medium
- Rule Title: The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes an external identity provider but does not provide evidence of conforming to FICAM-issued profiles.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — identifies "Role-based access control via GitHub" as the authentication mechanism.
- While GitHub uses OAuth2/OpenID Connect, there is no documentation or code implementation (e.g., SAML metadata, specific OIDC profile configurations) confirming conformance to FICAM-issued technical profiles.
- Requirement: PARTIALLY SATISFIED — An external identity provider is used, but conformance to FICAM profiles is not demonstrated.

Remediation:
Configure the application to conform to FICAM-issued technical profiles when providing services that rely on external (federal government) identity providers.

---

### 174. APSC-DV-001930 | SV-222561r961548

- Rule ID: SV-222561r961548
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence of remote maintenance functions or corresponding audit logs was found in the static analysis.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — mentions an "Audit trail via GitHub Security tab", but this refers to the repository's security posture, not application-level maintenance sessions.
- The application provides a Web UI and API (referenced in web/api/main.py and web/api/jobs.py), but no specific remote maintenance or diagnostic functions (e.g., remote log management, process restarts, or user administration) were identified in the provided source.
- No audit logs capturing the execution of maintenance tasks were located.
- Requirement: NOT SATISFIED — Remote maintenance capabilities and their associated audit logs are not identified.

Remediation:
Configure the application to log when application maintenance functionality is executed remotely.

---

### 175. APSC-DV-001940 | SV-222562r961554

- Rule ID: SV-222562r961554
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide non-local maintenance and diagnostic capabilities within the application layer. Maintenance is performed via infrastructure-level access (e.g., SSH, Kubernetes exec) rather than through application-provided functions. Furthermore, the application lacks a user authentication and role-based access control system, making the concept of a 'maintenance session' within the application inapplicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: web/api/main.py — No authentication middleware or role-based access control implemented for API endpoints.
- Requirement: NOT APPLICABLE — No application-level remote maintenance functions provided.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 176. APSC-DV-001950 | SV-222563r961557

- Rule ID: SV-222563r961557
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide non-local maintenance and diagnostic capabilities within the application layer. Maintenance is performed via infrastructure-level access (e.g., SSH, Kubernetes exec) rather than through application-provided functions. Furthermore, the application lacks a user authentication and role-based access control system, making the concept of a 'maintenance session' within the application inapplicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: web/api/main.py — No authentication middleware or role-based access control implemented for API endpoints.
- Requirement: NOT APPLICABLE — No application-level remote maintenance functions provided.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 177. APSC-DV-001960 | SV-222564r961560

- Rule ID: SV-222564r961560
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide non-local maintenance and diagnostic capabilities within the application layer. Maintenance is performed via infrastructure-level access (e.g., SSH, Kubernetes exec) rather than through application-provided functions. Furthermore, the application lacks a user authentication and role-based access control system, making the concept of a 'maintenance session' within the application inapplicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- File: web/api/main.py — No authentication middleware or role-based access control implemented for API endpoints.
- Requirement: NOT APPLICABLE — No application-level remote maintenance functions provided.

Remediation:
Configure the application to verify termination of remote maintenance sessions.

---

### 178. APSC-DV-001970 | SV-222565r961062

- Rule ID: SV-222565r961062
- Severity: medium
- Rule Title: The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide internal non-local maintenance or diagnostic capabilities that require application-level authentication.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- Requirement: NOT APPLICABLE — The application lacks the architectural construct of an internal maintenance interface; maintenance is performed via the host OS or CI/CD pipeline, which are outside the scope of the application's internal source code.

Remediation:
Configure the application to use strong authentication (CAC) when accessing the application for maintenance purposes.

---

### 179. APSC-DV-001980 | SV-222566r985978

- Rule ID: SV-222566r985978
- Severity: medium
- Rule Title: The application must terminate all sessions and network connections when nonlocal maintenance is completed.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management or user authentication, making idle timeout controls inapplicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism, and no web interface."
- This assessment is consistent with the manual findings for APSC-DV-000070 and APSC-DV-000080 documented in the same file, which address the same idle timeout requirements.
- Requirement: NOT APPLICABLE — No application-level sessions exist to be terminated.

Remediation:
Configure the application to expire idle user sessions after 10 minutes of inactivity for admin users and after 15 minutes of inactivity for regular users.

---

### 180. APSC-DV-001995 | SV-222567r961863

- Rule ID: SV-222567r961863
- Severity: medium
- Rule Title: The application must not be vulnerable to race conditions.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No static evidence, architecture documentation, or test results were found to demonstrate that the application has been analyzed for race conditions.
- Search of the repository for concurrency controls or race condition analysis in documentation (e.g., documentation/STIG_COMPLIANCE_GUIDE.md) yielded no results.
- No code review test results from a vendor or internal security team were provided in the source tree.
- Requirement: NOT SATISFIED — Compliance cannot be verified from the provided static artifacts.

Remediation:
Be aware of potential timing issues related to application programming calls when designing and building the application.

Validate that variable values do not change while a switch event is occurring.

---

### 181. APSC-DV-002000 | SV-222568r961068

- Rule ID: SV-222568r961068
- Severity: medium
- Rule Title: The application must terminate all network connections associated with a communications session at the end of the session.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is a CLI-based tool and does not implement session management or network communications sessions.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon is a CLI-based DevSecOps security orchestration pipeline tool. It has no web interface, user authentication layer, session management, relational database, or user account management system."
- Requirement: NOT APPLICABLE — The application lacks the session management architecture required for this control to apply.

Remediation:
Configure or design the application to terminate application network sessions at the end of the session.

---

### 182. APSC-DV-002020 | SV-222570r1117181

- Rule ID: SV-222570r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when signing application components.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements component signing, but there is no static evidence that FIPS-validated cryptographic modules are used.
- File: scripts/shell/sign-image-cosign.sh — This script implements image signing using the Cosign tool.
- No configuration files or documentation in the repository (e.g., documentation/STIG_COMPLIANCE_GUIDE.md) specify that the signing process is configured to use FIPS 140-2 validated modules or that the underlying environment enforces FIPS mode.
- Requirement: PARTIALLY SATISFIED — Signing is implemented via Cosign, but FIPS validation of the cryptographic module is not evidenced.

Remediation:
Utilize FIPS-validated algorithms when signing application components.

---

### 183. APSC-DV-002030 | SV-222571r1117181

- Rule ID: SV-222571r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes a FIPS-approved hashing algorithm for all cryptographic hashing operations.
- File: documentation/SCAN_MANIFEST_GUIDE.md — "SHA-256 is used for all cryptographic hashing"
- Standard: The documentation explicitly states SHA-256 is "FIPS 140-2 approved"
- Requirement: SATISFIED — The application uses SHA-256, which is a FIPS-validated hashing algorithm, and explicitly avoids prohibited algorithms like MD5 or SHA1.

Remediation:
Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.

---

### 184. APSC-DV-002040 | SV-222572r1117181

- Rule ID: SV-222572r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- While the application documents the use of FIPS-approved hashing (SHA-256), there is no explicit evidence of a FIPS-validated cryptographic module used for general data protection or encryption of unclassified information.
- File: documentation/SCAN_MANIFEST_GUIDE.md — confirms SHA-256 for hashing, but does not specify the underlying FIPS-validated module (e.g., OpenSSL FIPS provider) used for broader cryptographic protection.
- Requirement: PARTIALLY SATISFIED — Hashing is compliant, but general cryptographic module validation for all protected data is not explicitly documented in the provided source.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 185. APSC-DV-002050 | SV-222573r1117181

- Rule ID: SV-222573r1117181
- Severity: medium
- Rule Title: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement SAML assertions, making this control architecturally inapplicable.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon does not implement SOAP web services, WS-Security, or SAML assertions. It is a CLI tool that invokes container-based security scanners; this control has no applicability."
- Requirement: NOT APPLICABLE — No SAML assertions are generated or processed by the application.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 186. APSC-DV-002150 | SV-222574r1117171

- Rule ID: SV-222574r1117171
- Severity: medium
- Rule Title: The application user interface must be either physically or logically separated from data storage and management interfaces.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The requirement is to ensure the application user interface is physically or logically separated from data storage and management interfaces.
- No configuration files (e.g., Nginx configs, Kubernetes manifests, or network security group definitions) were provided that explicitly define separate ports, virtual NICs, or network namespaces for user traffic versus management traffic.
- While `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` mentions 'Network Isolation' for scanners running in isolated network namespaces, this describes the scanner's execution environment rather than the application's UI/Management interface separation.
- Requirement: NOT SATISFIED — no static evidence of interface separation found in provided artifacts.

Remediation:
Configure the application so user interface to the application and management interface to the application is separated.

---

### 187. APSC-DV-002210 | SV-222575r1043178

- Rule ID: SV-222575r1043178
- Severity: medium
- Rule Title: The application must set the HTTPOnly flag on session cookies.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The requirement is to set the HTTPOnly flag on session cookies to prevent client-side script access.
- No source code implementing session cookie creation (e.g., `Set-Cookie` headers in `web/api/main.py` or session middleware configuration) was provided in the context window to verify the presence of the `HttpOnly` flag.
- `configuration/semgrep-rules/epyon-webapp.yml` contains a rule `epyon.browser-token-in-localstorage` that recommends using `httpOnly` cookies, but this is a detection rule for the scanner and not evidence of the application's own implementation.
- Requirement: NOT SATISFIED — implementation of session cookie flags cannot be verified from provided source code.

Remediation:
Configure the application to set the HTTPOnly flag on session cookies.

---

### 188. APSC-DV-002220 | SV-222576r1043178

- Rule ID: SV-222576r1043178
- Severity: medium
- Rule Title: The application must set the secure flag on session cookies.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The requirement is to set the Secure flag on session cookies to ensure they are only transmitted over encrypted channels.
- No source code implementing session cookie creation was provided in the context window to verify the presence of the `Secure` flag.
- `configuration/semgrep-rules/epyon-webapp.yml` contains a rule `epyon.browser-token-in-localstorage` that recommends using `Secure` cookies, but this is a detection rule for the scanner and not evidence of the application's own implementation.
- Requirement: NOT SATISFIED — implementation of session cookie flags cannot be verified from provided source code.

Remediation:
Configure the application to ensure the secure flag is set on session cookies.

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect session identifiers in transit using SSL/TLS.
- No configuration files for the web server (e.g., Nginx, Caddy) or FastAPI middleware were provided in the source code to verify the enforcement of HTTPS.
- No evidence of the 'Secure' flag being set on session cookies was found in the provided snippets.
- While the manifest lists `web/api/main.py` and `web/static/app.js`, the content of these files was not provided for review.
- Requirement: NOT SATISFIED — no static evidence of TLS enforcement or secure cookie configuration found.

Remediation:
Configure the application to protect session IDs from interception or from manipulation.

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must destroy session IDs or cookies upon logoff or browser closure.
- No source code implementing session termination or logout logic (e.g., `/logout` endpoints or cookie clearing functions) was provided in the source code snippets.
- The manifest lists `web/api/main.py` and `web/static/app.js`, but their contents are missing from the provided context, preventing verification of session destruction mechanisms.
- Requirement: NOT SATISFIED — no static evidence of session destruction logic found.

Remediation:
Configure the application to destroy session ID cookies once the application session has terminated.

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must use system-generated session identifiers and protect against session fixation by regenerating IDs upon authentication.
- No source code implementing session generation or authentication-based session regeneration was provided in the source code snippets.
- The manifest lists `web/api/main.py`, but the content is missing, making it impossible to verify if the application uses secure, system-generated identifiers or if it regenerates them after login.
- Requirement: NOT SATISFIED — no static evidence of session generation or fixation protection found.

Remediation:
Design the application to generate new session IDs with unique values when authenticating user sessions.

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management or user authentication.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — explicitly states "This application is an internal library/SDK with no user-facing components or authentication mechanisms" and "No authentication/session logic present in source code".
- Requirement: NOT APPLICABLE — session validation is not required for an application without session management.

Remediation:
Configure the application to configure user session identifiers.

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management or user authentication.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — explicitly states "This application is an internal library/SDK with no user-facing components or authentication mechanisms" and "No authentication/session logic present in source code".
- Requirement: NOT APPLICABLE — URL embedded session IDs are not possible without session management.

Remediation:
Configure the application to transmit session ID information via cookies.

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement session management or user authentication.
- File: documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md — explicitly states "This application is an internal library/SDK with no user-facing components or authentication mechanisms" and "No authentication/session logic present in source code".
- Requirement: NOT APPLICABLE — session recycling is not possible without session management.

Remediation:
Design the application to not re-use session IDs.

---

### 195. APSC-DV-002290 | SV-222583r1051270

- Rule ID: SV-222583r1051270
- Severity: medium
- Rule Title: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must generate unique session identifiers using a FIPS 140-2/140-3 approved random number generator.
- No source code implementing session identifier generation or session management was provided in the available files.
- While the manifest lists `web/api/main.py` and `web/api/db.py`, the content of these files was not included in the provided source code context.
- There is no evidence of a configured FIPS-approved RNG (e.g., use of `secrets` module in Python or specific OS-level entropy sources) for session IDs.
- Requirement: NOT SATISFIED — evidence of session ID generation and the use of a FIPS-approved RNG is missing.

Remediation:
Configure the application server to generate unique session identifiers and to use a FIPS 140-2/140-3 random number generator to generate the randomness of the session identifiers.

---

### 196. APSC-DV-002300 | SV-222584r961596

- Rule ID: SV-222584r961596
- Severity: medium
- Rule Title: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must only allow the use of DoD-approved certificate authorities for verification of protected sessions.
- No TLS/SSL configuration files, CA trust store definitions, or certificate validation logic were found in the provided source code.
- The manifest lists `Dockerfile` and `docker-compose.yml`, but their contents were not provided, preventing verification of whether DoD root certificates are injected into the system trust store.
- There is no evidence of code that restricts certificate verification to DoD-approved PKI or ECA certificates.
- Requirement: NOT SATISFIED — evidence of DoD-approved CA enforcement is missing.

Remediation:
Configure the application to utilize DoD-approved PKI established CAs when verifying DoD-signed certificates.

---

### 197. APSC-DV-002310 | SV-222585r961122

- Rule ID: SV-222585r961122
- Severity: high
- Rule Title: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must fail to a secure state if system initialization, shutdown, or aborts fail.
- No evidence of 'fail-secure' logic (e.g., comprehensive error handling during startup/shutdown that ensures access controls remain active or the system becomes inaccessible) was found in the provided source code.
- The manifest lists `web/start.sh` and `web/api/main.py`, but the content of these files was not provided, making it impossible to assess the initialization and shutdown sequences.
- There are no documented test plans or design specifications in the provided materials that describe the application's behavior during a simulated failure of the web or database services.
- Requirement: NOT SATISFIED — evidence of fail-secure state implementation is missing.

Remediation:
Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).

---

### 198. APSC-DV-002320 | SV-222586r961125

- Rule ID: SV-222586r961125
- Severity: medium
- Rule Title: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements state capture and logging mechanisms to assist in failure analysis, but lacks a formal operational recovery document.
- File: documentation/SCAN_MANIFEST_GUIDE.md — The `scan-manifest.json` captures "Scan Metadata", "Target Information", and "Tool Versions", which preserves the system state necessary to reproduce and determine the cause of failure.
- File: configuration/semgrep-rules/epyon-webapp.yml — The rule `epyon.express-error-message-disclosure` explicitly requires the application to "Log server-side and return a generic message", confirming the existence of a server-side error logging architecture.
- Requirement: PARTIALLY SATISFIED — Technical mechanisms for logging and state preservation are present, but the required operational requirements documentation specifying exactly what information must be preserved for mission return is not found in the repository.

Remediation:
Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.

---

### 199. APSC-DV-002330 | SV-222587r1136910

- Rule ID: SV-222587r1136910
- Severity: medium
- Rule Title: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements several technical controls to protect the confidentiality and integrity of stored information.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Scan output directories are created with mode 700 (owner-only) preventing unauthorized access."
- File: documentation/SCAN_MANIFEST_GUIDE.md — "SHA-256 cryptographic hashes of all report files" are generated to ensure the integrity of stored scan results.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "GitHub Secrets used for sensitive configuration" ensures the confidentiality of stored credentials.
- Requirement: PARTIALLY SATISFIED — Confidentiality and integrity protections are implemented via filesystem permissions, cryptographic hashing, and secret management, but a formal data classification mapping (e.g., identifying CUI or classified data) is not documented.

Remediation:
Identify data elements that require protection. Document the data types and specify protection requirements and methods used.

---

### 200. APSC-DV-002340 | SV-222588r1067803

- Rule ID: SV-222588r1067803
- Severity: high
- Rule Title: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application uses approved cryptographic hashing to prevent unauthorized modification of data at rest.
- File: documentation/SCAN_MANIFEST_GUIDE.md — "SHA-256 cryptographic hashes of all report files" and a "Manifest Hash" are used for "Self-integrity verification".
- Algorithm: SHA-256 is a FIPS-approved cryptographic mechanism for ensuring data integrity.
- Requirement: PARTIALLY SATISFIED — Integrity is protected against unauthorized modification via SHA-256 hashes; however, there is no static evidence of encryption at rest (e.g., AES-256) for the data repository itself.

Remediation:
Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt data according to DOD policy or data owner requirements.

---

### 201. APSC-DV-002350 | SV-222589r1067813

- Rule ID: SV-222589r1067813
- Severity: high
- Rule Title: The application must use appropriate cryptography in order to protect stored DOD information when required by the information owner or DOD policy.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to use appropriate cryptography to protect stored DOD information.
- No explicit implementation of data-at-rest encryption (e.g., AES-256, LUKS, or database-level TDE) was found in the provided source code or configuration files.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — references that data protection requirements are documented in 'documentation/SECURITY.md', but that file was not provided for review.
- No cryptographic key management configurations or secrets for storage encryption were identified in the repository.
- Requirement: NOT SATISFIED — static evidence of cryptographic protection for stored data is missing.

Remediation:
Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt classified data using Type 1, Suite B, or other NSA-approved encryption solutions.

---

### 202. APSC-DV-002360 | SV-222590r961131

- Rule ID: SV-222590r961131
- Severity: medium
- Rule Title: The application must isolate security functions from non-security functions.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must isolate security functions from non-security functions.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — mentions 'Role-based access control via GitHub' under the FedRAMP section, indicating an externalized access control mechanism.
- No evidence was found of internal architectural isolation (e.g., separate microservices, restricted namespaces, or isolated modules) that separates security-critical configuration functions from general application logic.
- The repository contains a mix of API logic (web/api/) and scanning scripts (scripts/shell/) without a demonstrated structural boundary enforcing the isolation of security functions.
- Requirement: PARTIALLY SATISFIED — RBAC is implemented via GitHub, but internal functional isolation is not demonstrated.

Remediation:
Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.

---

### 203. APSC-DV-002370 | SV-222591r1117179

- Rule ID: SV-222591r1117179
- Severity: medium
- Rule Title: The application must maintain a separate execution domain for each executing process.

Status: Open
Confidence: 75/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must maintain a separate execution domain for each executing process.
- File: Dockerfile and docker-compose.yml — The application is containerized, which provides OS-level process isolation and separate execution domains via Linux namespaces and cgroups.
- File: .github/copilot-instructions.md — describes a runtime analysis tool `scripts/shell/run-ml-runtime-analysis.py` that monitors network, file access, and subprocess execution, indicating a capability to analyze processes in isolation.
- File: configuration/stigs/ML-Security-Checklist.json — Controls ML-013, ML-014, and ML-015 explicitly require that ML models be tested in 'sandboxed environments' to prevent cross-domain interference.
- While the capability for sandboxing and isolation is present via Docker and the ML runtime tool, full verification of separate execution domains for all application processes requires runtime observation of the process tree.
- Requirement: PARTIALLY SATISFIED — containerization and ML sandboxing capabilities are present, but global process domain separation is not fully verified statically.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements strict security boundaries to prevent unauthorized information transfer via shared resources.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Each scanner runs in isolated Docker container"
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Scan directories isolated per execution (unique timestamp)"
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Scanners run in isolated network namespaces"
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "No direct access to host filesystem outside scan target"
- Requirement: SATISFIED — Security boundaries are enforced through containerization, network namespace isolation, and unique filesystem paths per execution.

Remediation:
Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.

---

### 205. APSC-DV-002390 | SV-222593r961620

- Rule ID: SV-222593r961620
- Severity: medium
- Rule Title: XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application consumes XML-based STIG definitions but lacks explicit evidence of XML parser hardening against DoS attacks.
- File: configuration/stigs/U_ASD_STIG_V6R5_Manual-xccdf.xml — The application parses XCCDF XML files for STIG assessments.
- Evidence: A review of `scripts/shell/run-stig-assessment.py` and associated scripts shows no explicit configuration of XML parser options to mitigate recursive payloads, oversized payloads, or XML entity expansion (e.g., no use of `defusedxml` or explicit `lxml` settings to disable DTDs).
- Requirement: NOT SATISFIED — While the application uses XML, there is no static evidence of the required DoS protections (entity expansion, recursive payload validation) being implemented.

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

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements basic resource constraints but lacks a comprehensive anti-DoS strategy or verification results.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Memory and CPU limits enforced by container runtime"
- Evidence: While container-level resource limits prevent a single scanner from exhausting host resources, there is no evidence of application-level throttling, QoS, or documented penetration test results specifically addressing DoS susceptibility or weaponization.
- Requirement: PARTIALLY SATISFIED — Resource limits are in place, but comprehensive anti-DoS controls and verification testing are not documented.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Not Applicable
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application has not been designated as a high availability system in the provided documentation.
- Review of `documentation/STIG_COMPLIANCE_GUIDE.md` and `documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md` reveals no designation of the application as a high availability system.
- Per the check content: "If the application has not been designated as a high availability system, this requirement is not applicable."
- Requirement: NOT APPLICABLE — no high availability designation found in system documentation.

Remediation:
Build the application to address issues that are found in a redundant environment and utilize redundancy mechanisms to provide high availability.

---

### 208. APSC-DV-002440 | SV-222596r961632

- Rule ID: SV-222596r961632
- Severity: high
- Rule Title: The application must protect the confidentiality and integrity of transmitted information.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- No static evidence was found to confirm that the application enforces encryption for data in transit.
- Review of `Dockerfile` and the manifest (including `web/api/main.py` and `web/start.sh`) shows no explicit configuration for TLS/SSL certificates or enforcement of HTTPS within the application code.
- No manual documentation in the `documentation/` directory specifies the encryption settings or protocols used for transmitted information.
- While TLS is typically terminated at the infrastructure level (e.g., Load Balancer or Ingress Controller), this cannot be verified from the provided static source code artifacts.
- Requirement: NOT SATISFIED — evidence of TLS/encryption enforcement is missing from static analysis.

Remediation:
Configure all of the application systems to require TLS encryption in accordance with data protection requirements.

---

### 209. APSC-DV-002450 | SV-222597r1117180

- Rule ID: SV-222597r1117180
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- No static evidence was found to confirm the implementation of cryptographic integrity mechanisms for data during transmission.
- Review of the source code reveals no implementation of HMAC, digital signatures, or CRCs for runtime data streams.
- Partial evidence of integrity for static artifacts exists: `scripts/shell/verify-sbom-hashes.sh` (verifies SBOM hashes) and `scripts/shell/sign-image-cosign.sh` (signs container images), but these apply to files at rest or during deployment, not to data in transit.
- Integrity for transmission is typically provided by TLS, but as noted in APSC-DV-002440, TLS configuration is not present in the provided static artifacts.
- Requirement: NOT SATISFIED — evidence of transmission integrity mechanisms is missing from static analysis.

Remediation:
Configure the application to use cryptographic protections to prevent unauthorized disclosure of application data based upon the application architecture.

---

### 210. APSC-DV-002460 | SV-222598r961638

- Rule ID: SV-222598r961638
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application contains a web component (web/api/main.py), but no configuration files (e.g., nginx.conf, caddyfile) or code implementing TLS/SSL redirection were provided in the source.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — mentions Epyon is a "locally executed CLI pipeline tool", but the presence of a web API requires verification of transmission security.
- No evidence of `ssl_certificate` or `listen 443 ssl` found in provided artifacts.
- Requirement: NOT SATISFIED — no evidence of TLS enforcement for the web component.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 211. APSC-DV-002470 | SV-222599r961641

- Rule ID: SV-222599r961641
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during reception.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application contains a web component (web/api/main.py), but no configuration files or code implementing TLS/SSL for reception were provided in the source.
- No evidence of TLS termination or encrypted communication channels between tiers (e.g., API to Database) was found in the provided source code.
- Requirement: NOT SATISFIED — no evidence of TLS enforcement for incoming requests.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 212. APSC-DV-002480 | SV-222600r961638

- Rule ID: SV-222600r961638
- Severity: medium
- Rule Title: The application must not disclose unnecessary information to users.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application includes a static analysis rule to detect the disclosure of technical error details, but the actual implementation of generic error pages is not visible in the provided source.
- File: configuration/semgrep-rules/epyon-webapp.yml — rule `epyon.express-error-message-disclosure` flags patterns like `res.json({..., $K: $E.message, ...})` or `res.json({..., $K: $E.stack, ...})` to prevent leaking internals.
- No global error handling middleware or custom error page configurations were found in `web/api/main.py` or other API files to confirm that generic responses are enforced at runtime.
- Requirement: PARTIALLY SATISFIED — detection rules exist to prevent disclosure, but the enforcement implementation is not provided.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Open
Confidence: 0/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must not store sensitive information in hidden fields.
- No HTML templates or frontend source files (e.g., `web/static/index.html`) were provided in the source code context to verify the presence or absence of hidden input fields.
- Without access to the rendered UI code, it cannot be confirmed that sensitive authentication or session data is excluded from hidden fields.
- Requirement: NOT SATISFIED — lack of static evidence from frontend artifacts

Remediation:
Design and configure the application to not store sensitive information in hidden fields.  

Encrypt sensitive information stored in hidden fields using DoD-approved encryption and use server side session management techniques for user session management.

---

### 214. APSC-DV-002490 | SV-222602r961158

- Rule ID: SV-222602r961158
- Severity: high
- Rule Title: The application must protect from Cross-Site Scripting (XSS) vulnerabilities.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect from Cross-Site Scripting (XSS) vulnerabilities.
- File: `tests/python/test_finding_search.py` — `test_invalid_queries_rejected_without_echo` verifies that the input string `<script>` is rejected by `finding_search.validate_query(bad)`, which raises a `ValueError`.
- This indicates that input validation is implemented for the search query functionality to prevent the injection of script tags.
- However, comprehensive XSS protection requires evidence of output encoding/escaping in the frontend, and the contents of `web/static/app.js` and `web/static/index.html` were not provided for review.
- Requirement: PARTIALLY SATISFIED — input validation is present for search queries, but output encoding cannot be verified

Remediation:
Verify user input is validated and encode or escape user input to prevent embedded script code from executing.

Develop your application using a web template system or a web application development framework that provides auto escaping features rather than building your own escape logic.

---

### 215. APSC-DV-002500 | SV-222603r961158

- Rule ID: SV-222603r961158
- Severity: medium
- Rule Title: The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.

Status: Open
Confidence: 0/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.
- No evidence of CSRF mitigation techniques (such as anti-CSRF tokens, SameSite cookie configurations, or custom header validation) was found in the provided source code.
- While the application appears to be a REST API (using FastAPI as seen in `tests/python/test_finding_search.py`), there is no evidence of the authentication mechanism (e.g., stateless JWTs) that would justify a 'Not Applicable' status.
- Requirement: NOT SATISFIED — no static evidence of CSRF protection found

Remediation:
Configure the application to use unpredictable challenge tokens and check the HTTP referrer to ensure the request was issued from the site itself.  Implement mitigating controls as required such as using web reputation services.

---

### 216. APSC-DV-002510 | SV-222604r961158

- Rule ID: SV-222604r961158
- Severity: high
- Rule Title: The application must protect from command injection.

Status: Open
Confidence: 65/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application claims to implement input validation to prevent command injection, and uses basic shell quoting in scripts.
- File: documentation/SECURITY.md — "Input Validation: All scan inputs are validated before processing"
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "Comprehensive input validation and sanitization"
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/portable-app-scanner.sh — uses quoted variables (e.g., "$target_dir") when passing arguments to docker run commands to mitigate simple shell injection
- Requirement: PARTIALLY SATISFIED — while documented as a security priority and basic quoting is used, a centralized sanitization framework or explicit escaping logic for all system calls is not evident in the provided source code.

Remediation:
Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.

---

### 217. APSC-DV-002520 | SV-222605r961158

- Rule ID: SV-222605r961158
- Severity: medium
- Rule Title: The application must protect from canonical representation vulnerabilities.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application specifies a standard character encoding but lacks explicit evidence of input canonicalization.
- File: sonar-project.properties — "sonar.sourceEncoding=UTF-8"
- No evidence found of path normalization (e.g., os.path.realpath) or input canonicalization performed prior to authorization or security decisions
- Requirement: NOT SATISFIED — no specific artifacts demonstrate protection against canonical representation vulnerabilities.

Remediation:
A suitable canonical form should be chosen and all user input canonicalized into that form before any authorization decisions are performed.

Security checks should be carried out after decoding is completed. Moreover, it is recommended to check that the encoding method chosen is a valid canonical encoding for the symbol it represents.

---

### 218. APSC-DV-002530 | SV-222606r961158

- Rule ID: SV-222606r961158
- Severity: medium
- Rule Title: The application must validate all input.

Status: Open
Confidence: 75/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements basic input validation for target directories and claims comprehensive validation in its security documentation.
- File: documentation/SECURITY.md — "Input Validation: All scan inputs are validated before processing"
- File: _archive/cleanup-2026-05-27/scripts/backup/backup-20251115-194319/portable-app-scanner.sh — the `validate_target` function performs checks for non-empty input, directory existence (`[ ! -d "$target_dir" ]`), and readability (`[ ! -r "$target_dir" ]`)
- Requirement: PARTIALLY SATISFIED — basic validation for directory inputs is implemented and general validation is documented, but full validation of all application inputs cannot be confirmed from the provided static artifacts.

Remediation:
Design and configure the application to validate input prior to executing commands.

---

### 219. APSC-DV-002540 | SV-222607r961158

- Rule ID: SV-222607r961158
- Severity: high
- Rule Title: The application must not be vulnerable to SQL Injection.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements a vulnerability scanning pipeline, but specific evidence of SQL injection remediation or a clean scan report is not provided in the static artifacts.
- File: scripts/shell/run-trivy-scan.sh — implements automated vulnerability scanning using Trivy (`--scanners vuln,misconfig,secret`)
- File: .github/workflows/ci.yml — integrates security scans into the CI/CD pipeline to detect vulnerabilities
- Artifact: web/api/db.py (listed in manifest) — contains database logic, but the provided source code does not include the content of this file to verify the use of parameterized queries or ORM protections
- Requirement: PARTIALLY SATISFIED — scanning infrastructure is present, but specific evidence of SQLi absence (scan results or code review of DB interactions) is missing

Remediation:
Modify the application and remove SQL injection vulnerabilities.

---

### 220. APSC-DV-002550 | SV-222608r961158

- Rule ID: SV-222608r961158
- Severity: high
- Rule Title: The application must not be vulnerable to XML-oriented attacks.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application explicitly utilizes the defusedxml library to protect against XML-oriented attacks.
- File: pyproject.toml — dependencies: ["defusedxml>=0.7.1"]
- Technical Detail: defusedxml is specifically designed to prevent XML vulnerabilities such as Billion Laughs (DoS) and XML External Entity (XXE) attacks by disabling dangerous XML features
- Requirement: SATISFIED — cryptographic/secure XML parsing is enforced via the use of the defusedxml library

Remediation:
Design the application to utilize components that are not vulnerable to XML attacks.

Patch the application components when vulnerabilities are discovered.

---

### 221. APSC-DV-002560 | SV-222609r961656

- Rule ID: SV-222609r961656
- Severity: high
- Rule Title: The application must not be subject to input handling vulnerabilities.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application has a security scanning framework in place to identify input validation vulnerabilities, but specific sanitization SOPs or clean scan results are not cited.
- File: .github/workflows/ci.yml — enforces security gates (`FAIL_ON_CRITICAL=true`, `FAIL_ON_HIGH=true`) to prevent vulnerable code from reaching production
- File: scripts/shell/run-trivy-scan.sh — performs filesystem and image scans to identify known vulnerabilities
- Artifact: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md (listed in manifest) — likely contains the requested development process documentation, but the content was not provided in the source snippets
- Requirement: PARTIALLY SATISFIED — vulnerability detection process is implemented, but explicit evidence of input sanitization standards and current scan results for input handling is missing

Remediation:
Follow best practice when accepting user input and verify that all input is validated before the application processes the input.

Remediate identified vulnerabilities and obtain documented risk acceptance for those issues that cannot be remediated immediately.

---

### 222. APSC-DV-002570 | SV-222610r961167

- Rule ID: SV-222610r961167
- Severity: medium
- Rule Title: The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application uses generic error messages in its CLI entry point, but no global error scrubbing mechanism is evident for the web API.
- File: epyon.sh — contains generic, non-revealing error messages such as `echo "❌ ERROR: Epyon requires bash 4.0 or later"` and `echo "❌ ERROR: Epyon requires bash but it was not found on your system."`
- File: web/api/main.py — No global exception handler or middleware is present in the provided source to ensure that internal tracebacks, SQL strings, or system paths are stripped from API responses before being sent to the user.
- Requirement: PARTIALLY SATISFIED — CLI errors are generic, but API error handling cannot be verified as secure from static analysis.

Remediation:
Configure the server to not send error messages containing system information or sensitive data to users.

Use generic error messages.

---

### 223. APSC-DV-002580 | SV-222611r961170

- Rule ID: SV-222611r961170
- Severity: medium
- Rule Title: The application must reveal error messages only to the ISSO, ISSM, or SA.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence of a role-based access control (RBAC) system to differentiate between privileged and non-privileged users for error reporting.
- File: web/api/main.py — No authentication or authorization decorators (e.g., @login_required, @admin_only) are implemented to restrict detailed error messages to privileged roles (ISSO, ISSM, SA).
- File: web/api/jobs.py — API endpoints for job management do not show evidence of identity-based filtering for error detail levels.
- Requirement: NOT SATISFIED — The application lacks the necessary identity management infrastructure to restrict detailed error messages to privileged users.

Remediation:
Configure the server to only send error messages containing system information or sensitive data to privileged users.

Use generic error messages for non-privileged users.

---

### 224. APSC-DV-002590 | SV-222612r961665

- Rule ID: SV-222612r961665
- Severity: high
- Rule Title: The application must not be vulnerable to overflow attacks.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is developed using memory-safe languages that perform automatic bounds checking, preventing classic overflow attacks.
- Language: Python — used for the web API and analysis tools (e.g., File: web/api/main.py, File: scripts/shell/run-picklescan.py). Python manages memory automatically and prevents buffer/stack overflows.
- Language: Bash — used for orchestration and CLI (e.g., File: epyon.sh). Bash does not allow direct memory manipulation associated with overflow vulnerabilities.
- Requirement: SATISFIED — The use of Python and Bash satisfies the requirement to use languages that perform automatic bounds checking.

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

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not provide static evidence of an automated mechanism to remove old software components after updates are installed.
- Observation: The repository contains an `_archive/cleanup-2026-05-27/` directory, but this appears to be a manual archive of previous scan results rather than a system-level component removal process.
- No scripts or configuration files (e.g., in `.github/workflows/` or `scripts/shell/`) were found that explicitly handle the deletion of previous application versions upon deployment.
- Requirement: NOT SATISFIED — no automated cleanup of old application versions identified in source code.

Remediation:
Configure or design the application to remove old components when updating.

---

### 226. APSC-DV-002630 | SV-222614r1117151

- Rule ID: SV-222614r1117151
- Severity: medium
- Rule Title: Security-relevant software updates and patches must be kept up to date.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements tools to detect end-of-life software but lacks static evidence of a mandated weekly update process for its own components.
- File: `scripts/shell/run-xeol-scan.sh` — implements EOL detection using the `noqcks/xeol:latest` image and explicitly runs `db update` to ensure the EOL database is current.
- File: `.github/workflows/ci.yml` — ensures that security scans and tests are run on every commit, but does not define a scheduled weekly trigger for checking upstream patches.
- Observation: There is no evidence of a cron job or scheduled GitHub Action that enforces a weekly check for application updates in accordance with IAVMs or CTOs.
- Requirement: PARTIALLY SATISFIED — EOL detection is implemented, but a weekly update cadence for the application itself is not documented or enforced in static artifacts.

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements a comprehensive automated test suite to verify the correct operation of its security and compliance functions.
- File: `tests/python/test_suppression_parity.py` — verifies that security findings are correctly suppressed based on the `.epyon-ignore.yml` configuration.
- File: `tests/python/test_stig_records.py` and `tests/python/test_stig_citations.py` — verify the correctness of the STIG assessment logic and the accuracy of the citations generated.
- File: `tests/python/test_full_scan_acceptance.py` — performs end-to-end verification of the security scanning workflow.
- File: `tests/fixtures/golden-scan/` — utilizes 'golden' result sets to ensure that security scans produce deterministic and correct findings against known baselines.
- Requirement: SATISFIED — security function testing is integrated into the development lifecycle via automated tests and golden-image verification.

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to verify the correct operation of security functions on startup, restart, privileged command, or every 30 days.
- Search of `src/`, `scripts/`, and `web/` directories reveals no implementation of a security function self-test or verification routine.
- No evidence of startup checks in `epyon.sh` or `web/api/main.py` that validate the integrity or operation of security controls (e.g., cryptographic modules, access control lists).
- No privileged API endpoints or CLI commands found that trigger a security function verification test.
- Requirement: NOT SATISFIED — no static evidence of security function verification implementation.

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must notify the ISSO and ISSM of failed security verification tests.
- No configuration files or code artifacts were found that define ISSO or ISSM contact information or notification preferences.
- While `scripts/shell/send-webhook-notification.sh` provides a general notification mechanism, there is no logic linking this utility to the failure of security verification tests.
- No evidence of an alerting workflow specifically designed to notify security officials upon the failure of internal security function tests.
- Requirement: NOT SATISFIED — no evidence of ISSO/ISSM notification for security verification failures.

Remediation:
Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.

---

### 230. APSC-DV-002870 | SV-222618r961083

- Rule ID: SV-222618r961083
- Severity: medium
- Rule Title: Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must not use unsigned Category 1A mobile code.
- The application is a web-based security scanner consisting of a Python (FastAPI) backend and a JavaScript/HTML frontend.
- File: `web/static/app.js` and `web/static/index.html` — the application's client-side logic executes entirely within the browser, which is explicitly listed as a condition for non-applicability in the control check content.
- The application does not utilize or distribute Category 1A mobile code such as Java Applets, ActiveX controls, or Flash.
- Note: Files located in `tests/fixtures/mobile-code/` (e.g., `tests/fixtures/mobile-code/category-1a/java-applet-unsigned.html`) are test fixtures used to verify the scanner's detection logic and are not part of the application's delivered code.
- Requirement: NOT APPLICABLE — the application does not utilize Category 1A mobile code.

Remediation:
Configure the application so Category 1A mobile code is signed.

---

### 231. APSC-DV-002880 | SV-222619r961863

- Rule ID: SV-222619r961863
- Severity: medium
- Rule Title: The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement an internal user account or identity management system.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no user accounts, user management, password system, or identity store."
- The control requires a process for user account creation, termination, and expiration, which is architecturally impossible for an application without a user store.
- Requirement: SATISFIED — Control is Not Applicable as the application lacks an identity store or user management functionality.

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- Network segmentation for DoD DMZ deployment cannot be verified from the provided static artifacts.
- No network diagrams, infrastructure-as-code (IaC) files (e.g., Terraform, CloudFormation), or network configuration files are present in the repository to verify the separation of web, application, and database tiers.
- There is no documentation confirming whether the application is hosted within a DoD DMZ, which is the prerequisite for this control.
- Requirement: NOT SATISFIED — Evidence of network segmentation and DMZ hosting status is missing.

Remediation:
Separate web server from other application tiers and place it on a separate network segment apart from the application and database servers in accordance with DoD DMZ data access controls requirements.

---

### 233. APSC-DV-002900 | SV-222621r1136913

- Rule ID: SV-222621r1136913
- Severity: medium
- Rule Title: The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence of a defined or implemented audit log retention policy.
- A review of the repository (including documentation/ and scripts/shell/) reveals no configuration settings or documented processes for retaining audit trails for 30 months (non-SAMI) or 5 years (SAMI).
- While scan results are stored in directories (e.g., scans/{app_name}_{timestamp}/ as noted in documentation/ANCHORE_CONFIGURATION_GUIDE.md), there is no logic for automated archival to cold storage or enforcement of the required retention durations.
- Requirement: NOT SATISFIED — Audit log retention periods and cold storage processes are not evidenced.

Remediation:
Retain application audit log files for 30 months (12 months active + 18 months cold storage) for non-SAMI data and five years for SAMI data.

---

### 234. APSC-DV-002910 | SV-222622r961863

- Rule ID: SV-222622r961863
- Severity: medium
- Rule Title: The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires system documentation specifying the frequency of audit log reviews and evidence of the last review.
- No system documentation, SOPs, or configuration files were found in the repository that define a schedule for audit log reviews.
- No records of audit log review dates or timestamps were identified in the provided source code or documentation.
- Requirement: NOT SATISFIED — no static evidence of a defined log review policy or execution history.

Remediation:
Establish a scheduled process for reviewing logs.

Maintain a log or records of dates and times audit logs are reviewed.

---

### 235. APSC-DV-002920 | SV-222623r961863

- Rule ID: SV-222623r961863
- Severity: medium
- Rule Title: The ISSO must report all suspected violations of IA policies in accordance with DoD information system IA procedures.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires a policy or SOP for reporting suspected violations of Information Assurance (IA) policies.
- A search of the repository for 'IA policy', 'violation reporting', and 'SOP' yielded no results related to the reporting of security policy violations.
- No organizational policy documents are present in the provided files to verify the reporting procedure.
- Requirement: NOT SATISFIED — no static evidence of an IA violation reporting policy.

Remediation:
Create and maintain a policy to report IA violations.

---

### 236. APSC-DV-002930 | SV-222624r1051272

- Rule ID: SV-222624r1051272
- Severity: medium
- Rule Title: The ISSO must ensure active vulnerability testing is performed.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires active vulnerability and fuzz testing, including procedures, results, and verification that critical vulnerabilities are remediated within 21 business days.
- Evidence of vulnerability scanning is present: File `_archive/cleanup-2026-05-27/scans/iris_2026-04-25_23-58-59/consolidated-reports/README.md` lists the use of SonarQube, TruffleHog, ClamAV, Helm, Checkov, Trivy, Grype, and Xeol.
- Automated scanning is integrated into the pipeline via `.github/workflows/epyon-scan.yml` and `scripts/shell/run-target-security-scan.sh`.
- No evidence of 'fuzz testing' was found in the provided source code or documentation.
- No specific 'vulnerability test procedures' or 'settings' documents were provided.
- The 21-day remediation window for critical vulnerabilities cannot be verified statically without access to the timestamps of the vulnerabilities identified in the scan reports.
- Requirement: PARTIALLY SATISFIED — vulnerability scanning is implemented, but fuzz testing and remediation timelines are not evidenced.

Remediation:
Perform active vulnerability and fuzz testing of the application.

Verify the vulnerability scanning tool is configured to test all application components and functionality.

Address discovered vulnerabilities.

---

### 237. APSC-DV-002950 | SV-222625r961863

- Rule ID: SV-222625r961863
- Severity: medium
- Rule Title: Execution flow diagrams and design documents must be created to show how deadlock and recursion issues in web services are being mitigated.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application provides a web API but lacks documented execution flow diagrams detailing deadlock and recursion mitigation.
- File: web/api/main.py — implements the web API entry point
- Search: No files matching 'flow diagram', 'deadlock', or 'recursion' were found in the repository documentation
- Manual STIG documentation for other controls (e.g., APSC-DV-000220 in documentation/STIG_COMPLIANCE_GUIDE.md) states the app 'does not implement SOAP web services', but the current control applies to 'web services' generally, including the REST API implemented in the web/api directory
- Requirement: NOT SATISFIED — no design documents or diagrams provided to demonstrate mitigation of deadlock and recursion issues

Remediation:
Develop web services to account for deadlock issues.

---

### 238. APSC-DV-002960 | SV-222626r961863

- Rule ID: SV-222626r961863
- Severity: medium
- Rule Title: The designer must ensure the application does not store configuration and control files in the same directory as user data.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application separates configuration and control files from user data using distinct directory mappings in the container orchestration.
- File: docker-compose.yml — configuration is mapped to `./configuration:/app/configuration`
- File: docker-compose.yml — user data (scan results) is mapped to `./scans:/app/scans`
- File: docker-compose.yml — application data is mapped to `./web/data:/app/web/data`
- The use of separate host-bind mounts ensures that configuration files and user-generated scan data are stored in different physical and logical directories
- Requirement: SATISFIED — configuration and user data are stored in separate directories

Remediation:
Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.

---

### 239. APSC-DV-002970 | SV-222627r961863

- Rule ID: SV-222627r961863
- Severity: medium
- Rule Title: The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence that the Epyon application itself was configured according to a specific DoD STIG, NSA guide, or documented third-party vendor lock-down guide.
- File: documentation/SYSTEM_ARCHITECTURE.md — describes a 'STIG Compliance Engine' used to assess *target* repositories, but does not cite the guidance used to secure the Epyon deployment itself
- File: configuration/stigs/U_ASD_STIG_V6R5_Manual-xccdf.xml — contains STIG definitions for assessment, not configuration guidance for the app
- No vendor literature or commercially accepted practice guides are cited in the repository for the application's own hardening
- Requirement: NOT SATISFIED — no evidence of configuration guidance (STIG or third-party) used for the application's deployment

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
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that all application ports, protocols, and services be submitted to and compliant with the DoD Ports, Protocols, and Services Management (DoD PPSM) guidance.
- No System Security Plan (SSP), accreditation documentation, or formal port submission records were found in the repository.
- While the application contains logic to parse network discovery results (File: web/api/parsers.py — function: `parse_network_discovery_dir`), this is a feature of the scanner and does not constitute evidence that the scanner's own operational ports have been approved by the DoD PPSM.
- Requirement: NOT SATISFIED — No evidence of submission or approval for ports/protocols found in static artifacts.

Remediation:
Verify the accreditation documentation lists all interfaces and the ports, protocols, and services used.

Verify that all ports, protocols, and services are used in accordance with the DoD PPSM.

---

### 241. APSC-DV-002990 | SV-222629r961863

- Rule ID: SV-222629r961863
- Severity: medium
- Rule Title: The application must be registered with the DoD Ports and Protocols Database.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires verification that the application and its ports are registered with the DoD Ports and Protocols Database.
- A search of the repository for registration IDs, database entries, or compliance certificates related to the DoD Ports and Protocols Database yielded no results.
- This is an administrative registration requirement that cannot be verified through static source code analysis without accompanying accreditation documentation.
- Requirement: NOT SATISFIED — No evidence of registration found.

Remediation:
Register the application and ports in the Ports and Protocols Database.

---

### 242. APSC-DV-002995 | SV-222630r961863

- Rule ID: SV-222630r961863
- Severity: medium
- Rule Title: The Configuration Management (CM) repository must be properly patched and STIG compliant.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that the Configuration Management (CM) repository be properly patched and STIG compliant.
- The application utilizes GitHub for configuration management (evidenced by the presence of `.github/workflows/ci.yml` and `.github/workflows/release.yml`).
- There is no documentation provided in the repository (e.g., in `docs/` or `COMPLIANCE.md`) verifying that the CM environment or the organization's CM processes are STIG compliant or following a verified patch management schedule.
- Requirement: NOT SATISFIED — No evidence of CM repository STIG compliance or patching verification found.

Remediation:
Patch the CM system when new security patches are made available and apply the relevant STIGs.

---

### 243. APSC-DV-003000 | SV-222631r961863

- Rule ID: SV-222631r961863
- Severity: medium
- Rule Title: Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that access privileges to the Configuration Management (CM) repository be reviewed every three months.
- No documentation, policy files, or audit logs were found in the repository that evidence a recurring three-month review process for CM repository access.
- The application is developed in-house by MetroStar Systems (File: src/epyon/__init__.py — __author__ = "MetroStar Systems"), making this control applicable.
- Requirement: NOT SATISFIED — no static evidence of the required quarterly access review process exists.

Remediation:
Review access privileges to the CM repository at least every three months.

---

### 244. APSC-DV-003010 | SV-222632r961863

- Rule ID: SV-222632r961863
- Severity: medium
- Rule Title: A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires a maintained Software Configuration Management (SCM) plan describing configuration control, change management, and roles/responsibilities.
- A search of the repository manifest and provided files reveals no SCM plan document (e.g., SCM_PLAN.md, CONFIG_MGMT.md) that defines the required procedures, roles, tools, or baselines.
- While a CHANGELOG.md exists, it records changes but does not constitute a formal SCM plan describing the management process.
- Requirement: NOT SATISFIED — no formal SCM plan document was found in the source code or documentation.

Remediation:
Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.

---

### 245. APSC-DV-003020 | SV-222633r961863

- Rule ID: SV-222633r961863
- Severity: medium
- Rule Title: A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires the establishment of a Configuration Control Board (CCB) that meets at least every release cycle.
- No CCB charter, meeting minutes, or documentation evidencing the existence and activity of a Configuration Control Board was found in the repository.
- The application is developed in-house, making the requirement for a CCB applicable.
- Requirement: NOT SATISFIED — no evidence of a CCB or its charter exists in the provided artifacts.

Remediation:
Setup and maintain a Configuration Control Board.

---

### 246. APSC-DV-003030 | SV-222634r987685

- Rule ID: SV-222634r987685
- Severity: medium
- Rule Title: The application services and interfaces must be compatible with and ready for IPv6 networks.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application's compatibility with IPv6 networks cannot be verified from the provided static source code.
- No IPv6-specific configurations or socket options were found in the API source code (e.g., `web/api/main.py`).
- The `Dockerfile` and `docker-compose.yml` do not specify network configurations that explicitly enable or restrict IPv6.
- No documentation regarding DoD IPv6 Standards Profile compliance is present in the repository.
- Requirement: PARTIALLY SATISFIED — The application uses standard networking libraries, but explicit IPv6 readiness is not documented or configured in static artifacts.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The hosting environment's criticality and the presence of other applications on the host machine cannot be determined from the source code.
- The application is designed for containerized deployment as evidenced by the `Dockerfile` and `docker-compose.yml`.
- There is no documentation (e.g., in `README.md` or deployment guides) specifying whether the target host is a general-purpose machine or if it is shared with non-mission critical applications.
- Requirement: NOT SATISFIED — Host-level deployment details and criticality designations are not available in the static repository.

Remediation:
Deploy mission critical applications on servers that are not shared by other less critical applications.

---

### 248. APSC-DV-003050 | SV-222636r1051323

- Rule ID: SV-222636r1051323
- Severity: medium
- Rule Title: A contingency plan must exist in accordance with DOD policy based on the application's availability requirements.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- No contingency plan or disaster recovery documentation was found in the repository.
- A search of the file manifest and provided documentation (including `.github/README.md` and the `documentation/` directory) reveals no files related to contingency planning, business continuity, or availability requirements.
- No evidence exists to verify the transfer of functions to an alternate site or resumption timelines for high, moderate, or low availability levels.
- Requirement: NOT SATISFIED — No contingency plan is present in the source code or documentation.

Remediation:
Create and maintain a contingency plan that identifies essential mission and business functions and associated contingency requirements.

---

### 249. APSC-DV-003060 | SV-222637r961863

- Rule ID: SV-222637r961863
- Severity: medium
- Rule Title: Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires a documented disaster recovery plan including special considerations for trusted recovery.
- Search of repository manifest and provided files found no documents related to disaster recovery (e.g., no 'DR_PLAN.md', 'recovery.md', or similar).
- Manual STIG documentation in 'documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md' mentions 'Air-gapped deployment capability' under FedRAMP support, but this does not constitute a comprehensive disaster recovery plan.
- Requirement: NOT SATISFIED — no disaster recovery plan or trusted recovery procedures are present in the static source code or documentation.

Remediation:
Create and maintain a disaster recovery plan.

---

### 250. APSC-DV-003070 | SV-222638r961863

- Rule ID: SV-222638r961863
- Severity: medium
- Rule Title: Data backup must be performed at required intervals in accordance with DoD policy.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires documented backup procedures performed at intervals based on risk level, including off-site storage and reliability testing.
- Search of repository manifest found no backup policy, SLA, or MOU documentation.
- Files located in '_archive/cleanup-2026-05-27/scripts/backup/' appear to be archived versions of scripts rather than documented organizational backup procedures or schedules.
- No evidence of backup intervals (weekly/daily) or verification of media reliability was found.
- Requirement: NOT SATISFIED — no documented backup procedures or evidence of backup execution intervals are present.

Remediation:
Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.

---

### 251. APSC-DV-003080 | SV-222639r961863

- Rule ID: SV-222639r961863
- Severity: medium
- Rule Title: Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that back-up copies of application software or source code be stored in a fire-rated container or stored separately (offsite).
- While the source code is hosted in a remote Git repository (GitHub), there is no documented policy or evidence that a separate backup copy is maintained in a fire-rated container or a designated offsite location as required by the STIG.
- No evidence of a source code backup strategy separate from the primary version control system was found in the provided files.
- Requirement: NOT SATISFIED — no evidence of fire-rated or separate offsite backup storage for source code.

Remediation:
Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.

---

### 252. APSC-DV-003090 | SV-222640r961863

- Rule ID: SV-222640r961863
- Severity: medium
- Rule Title: Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires documented procedures to ensure the physical and technical protection of backup and restoration assets.
- No documentation (e.g., Backup Policy, Disaster Recovery Plan) was found in the repository that describes the protection of backup directories, software, or restoration equipment.
- While backup scripts exist in `_archive/cleanup-2026-05-27/scripts/backup/`, these are implementation artifacts and not the required protection procedures.
- Requirement: NOT SATISFIED — No documented procedures for the protection of backup and restoration assets were identified.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires encryption for key exchange and endpoint authentication prior to establishing a communication channel.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — "Epyon has no remote access sessions; it is a locally executed CLI pipeline tool."
- The application is a CLI tool that invokes container-based scanners and makes outbound HTTPS requests; it does not implement its own key exchange mechanism or manage communication channels requiring key exchange.
- Requirement: NOT APPLICABLE — The application does not implement key exchange.

Remediation:
Use encryption for key exchange.

---

### 254. APSC-DV-003110 | SV-222642r961863

- Rule ID: SV-222642r961863
- Severity: high
- Rule Title: The application must not contain embedded authentication data.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control prohibits the inclusion of embedded authentication data (passwords, certificates, etc.) in source code or configuration files.
- File: documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md — "GitHub Secrets used for sensitive configuration"
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-25_23-58-59/consolidated-reports/README.md — "Secret Detection: 0 verified secrets detected across all targets"
- Review of provided source files and configuration manifests shows no hardcoded credentials; sensitive data is handled via external secrets management.
- Requirement: SATISFIED — No embedded authentication data found in source code or configuration.

Remediation:
Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.

---

### 255. APSC-DV-003120 | SV-222643r1136915

- Rule ID: SV-222643r1136915
- Severity: high
- Rule Title: The application must have the capability to mark sensitive/classified output when required.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application is required to have the capability to mark sensitive or classified output (e.g., CUI, Secret) on screens and reports.
- No evidence of classification marking logic, headers, or footers was found in the source code or documentation.
- No classification guide or data element classification documentation was identified in the repository.
- Requirement: NOT SATISFIED — no static evidence of classification marking capabilities found.

Remediation:
Enable the application to adequately mark sensitive/classified output.

---

### 256. APSC-DV-003130 | SV-222644r961863

- Rule ID: SV-222644r961863
- Severity: low
- Rule Title: Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application must have test plans and procedures created and executed prior to each release or patch.
- Evidence of automated testing exists: `.github/workflows/ci.yml` and `.github/workflows/release.yml` define the CI/CD pipeline.
- A comprehensive test suite is present in the `tests/` directory (e.g., `tests/python/test_full_scan_acceptance.py`).
- However, no formal 'test plan' or 'test procedure' documentation was found that describes the strategy and required results for each release.
- Requirement: PARTIALLY SATISFIED — automated tests and pipelines are implemented, but formal test plan documentation is missing.

Remediation:
Execute tests plans prior to release or patch update.

---

### 257. APSC-DV-003140 | SV-222645r961863

- Rule ID: SV-222645r961863
- Severity: medium
- Rule Title: Application files must be cryptographically hashed prior to deploying to DoD operational networks.

Status: Not a Finding
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements cryptographic hashing to ensure the integrity of files prior to deployment.
- File: documentation/SECURITY.md — "Integrity verification: File hashing and manifest validation"
- Implementation: The repository contains scripts specifically for hash validation, including `scripts/shell/verify-scan-manifest.sh` and `scripts/shell/verify-sbom-hashes.sh`.
- Requirement: SATISFIED — cryptographic hashing and manifest validation are explicitly documented as a security feature and implemented via shell scripts.

Remediation:
Developers/release managers create cryptographic hash values of application files and/or application packages prior to transitioning the application from test to a production environment. They protect cryptographic hash information so it cannot be altered and make a read copy of the hash information available to application Admins so they can validate application packages and files after they download the files.

Application Admins validate cryptographic hashes prior to deploying the application to production.

---

### 258. APSC-DV-003150 | SV-222646r961863

- Rule ID: SV-222646r961863
- Severity: medium
- Rule Title: At least one tester must be designated to test for security flaws in addition to functional testing.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires the designation of at least one personnel member to perform security testing in addition to functional testing.
- No organization chart, personnel list, or role assignment documentation was found in the repository manifest or provided files.
- While `pyproject.toml` lists "MetroStar Systems" as the author, it does not designate specific individuals or roles for security testing.
- Requirement: NOT SATISFIED — No designated security tester identified in static artifacts.

Remediation:
Designate personnel to conduct security testing on the applications.

---

### 259. APSC-DV-003160 | SV-222647r961863

- Rule ID: SV-222647r961863
- Severity: low
- Rule Title: Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires documented and annually executed test procedures for system initialization, shutdown, and aborts to ensure a secure state.
- File: `tests/shell/README.md` — Documents unit tests for shell scripts using `bats-core` (107 tests), but these are functional tests for the scanner's logic, not security state tests for the application's lifecycle (initialization/shutdown/abort).
- No documentation exists regarding annual execution dates or specific security checks for credential-less access during system transitions.
- Requirement: NOT SATISFIED — No evidence of annual security testing procedures for system initialization, shutdown, or aborts.

Remediation:
Create test procedures to test the security state of the application and exercise test procedures annually.

---

### 260. APSC-DV-003170 | SV-222648r961863

- Rule ID: SV-222648r961863
- Severity: medium
- Rule Title: An application code review must be performed on the application.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires a security-focused code review to be performed on the application.
- File: `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` — Explicitly documents a "Manual Security Review" with "Code Review Findings: ✅ All Clear".
- The documented review specifically verified: "No hardcoded credentials", "Proper error handling throughout", "Safe file operations with validation", and "Defense-in-depth architecture".
- File: `sonar-project.properties` — Indicates the use of SonarCloud for automated code quality and security analysis (`sonar.projectKey=MetroStar_epyon`).
- Requirement: SATISFIED — Manual and automated code reviews are documented and performed.

Remediation:
Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.

---

### 261. APSC-DV-003180 | SV-222649r961863

- Rule ID: SV-222649r961863
- Severity: low
- Rule Title: Code coverage statistics must be maintained for each release of the application.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application utilizes tooling for code analysis, but specific coverage statistics for releases are not present in the source code.
- File: scripts/shell/run-sonar-analysis.sh — implements SonarQube analysis, which is typically used to track code coverage and quality gates.
- No literal coverage percentage reports (e.g., .coverage, coverage.xml, or SonarQube export files) are present in the repository manifest.
- Requirement: PARTIALLY SATISFIED — Tooling for coverage tracking is implemented, but the actual statistics for each release are not maintained within the static artifacts provided.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Not a Finding
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements a defect tracking system via Jira integration to capture and track security flaws.
- File: web/api/jira_client.py — provides the programmatic interface to interact with the Jira API for issue management.
- File: scripts/shell/create-jira-tickets.sh — automates the creation of Jira tickets based on security scan findings.
- File: scripts/shell/stig_jira.py — specifically handles the tracking of STIG-related findings within the Jira system.
- Requirement: SATISFIED — Flaws and security findings are tracked in a formal defect tracking system (Jira).

Remediation:
Track software defects in a defect tracking system.

---

### 263. APSC-DV-003200 | SV-222651r961863

- Rule ID: SV-222651r961863
- Severity: medium
- Rule Title: The changes to the application must be assessed for IA and accreditation impact prior to implementation.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no static evidence of a formal IA impact assessment process for application changes.
- No Change Control Board (CCB) documentation, IA impact assessment templates, or mandatory IA review checklists were found in the documentation/ or .github/ directories.
- While .github/pull_request_template.md exists in the manifest, its content was not provided to verify if IA impact is a required field for PR approval.
- Requirement: NOT SATISFIED — No evidence of a process to assess IA and accreditation impact prior to implementation.

Remediation:
Review IA impact to the system prior to implementing changes.

---

### 264. APSC-DV-003210 | SV-222652r961863

- Rule ID: SV-222652r961863
- Severity: medium
- Rule Title: Security flaws must be fixed or addressed in the project plan.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- Security flaws must be integrated into the project plan for tracking and management.
- File: `scripts/shell/create-jira-tickets.sh` — provides automation to convert security findings into Jira tickets for tracking.
- File: `web/api/jira_client.py` — implements the technical integration with Jira to facilitate flaw reporting.
- Missing: There is no evidence of a formal 'Project Plan' document or a documented organizational process that describes how these Jira tickets are prioritized and integrated into the project's development lifecycle/timeline.
- Requirement: PARTIALLY SATISFIED — technical mechanisms for tracking flaws exist, but the integration into a project plan is not demonstrated.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application development team must follow a documented set of coding standards.
- File: `pyproject.toml` — exists as a configuration file for Python tools, but does not explicitly define or reference a specific coding standard (e.g., PEP 8, Google Style Guide).
- Search: No files such as `CODING_STANDARDS.md`, `CONTRIBUTING.md` (with standards section), or comprehensive linting configurations (e.g., `.eslintrc`, `.flake8`) were found in the repository manifest.
- Requirement: NOT SATISFIED — no documented coding standards or evidence of their enforcement were found in the source code.

Remediation:
Create and maintain a coding standard process and documentation for developers to follow. 

Include programming best practices based on the languages being used for application development. Include items that should be standardized across the team that deals with how developers write their application code.

---

### 266. APSC-DV-003220 | SV-222654r961863

- Rule ID: SV-222654r961863
- Severity: low
- Rule Title: The designer must create and update the Design Document for each release of the application.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- A comprehensive Design Document must be maintained for each release, covering interfaces, roles, and security requirements.
- File: `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` — documents security boundaries including 'Process Isolation', 'Filesystem Isolation', 'Network Isolation', and 'Credential Isolation'.
- Missing: A formal Design Document that explicitly addresses the following required elements: external interfaces, nature of information exchanged, user roles and access privileges, restoration priority of subsystems, and a detailed application incident response plan.
- Requirement: PARTIALLY SATISFIED — some architectural security boundaries are documented, but the full scope of the Design Document requirement is not met.

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
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires a documented threat model containing identified threats, potential vulnerabilities, countermeasures, and mitigations.
- Search of repository manifest and provided files reveals no document dedicated to threat modeling (e.g., no 'threat-model.md' or similar).
- Review of `documentation/SECURITY.md` and `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` shows security processes and test coverage, but no threat model analysis.
- Requirement: NOT SATISFIED — No threat model documentation exists in the repository.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires verification that the application is not subject to error handling vulnerabilities and that testing includes error handling checks.
- File: `documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md` — states "Unit Tests: 304/304 passing (100%)" and "Structural validation: All scripts have proper shebang, error handling".
- While the project implements a wide array of static analysis tools (Trivy, Grype, Checkov, etc.) as evidenced in `scripts/shell/compare-self-assessment.py`, there is no specific evidence or report provided that explicitly tests for and validates the absence of error handling vulnerabilities (e.g., improper exception handling leading to information disclosure).
- Requirement: PARTIALLY SATISFIED — General claims of error handling validation exist in documentation, but specific test results for error handling vulnerabilities are missing.

Remediation:
Ensure proper return code and exception handling is implemented throughout the application.

---

### 269. APSC-DV-003236 | SV-222657r961863

- Rule ID: SV-222657r961863
- Severity: medium
- Rule Title: The application development team must provide an application incident response plan.

Status: Open
Confidence: 85/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires an application incident response plan that tracks vulnerabilities, confirms them, tracks remediation, and notifies users.
- File: `documentation/SECURITY.md` — defines a "Security Response Process" consisting of: "1. Triage", "2. Investigation", "3. Development", "4. Disclosure", "5. Release", "6. Advisory".
- This process maps to the requirements: Triage/Investigation (Tracking/Confirmation), Development (Remediation), and Disclosure/Advisory (Notification).
- However, this is a high-level process summary rather than a comprehensive Incident Response Plan (which typically includes roles, responsibilities, and communication matrices).
- Requirement: PARTIALLY SATISFIED — A security response process is documented, but a formal, detailed incident response plan is not present.

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

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires verification that all software components are supported by a vendor or the development team.
- File: pyproject.toml — authors: [{ name = "MetroStar Systems", email = "opensource@metrostar.com" }]
- File: pyproject.toml — dependencies: ["openai>=1.0.0", "pyyaml>=6.0", "defusedxml>=0.7.1", "fastapi>=0.100.0", "uvicorn[standard]>=0.23.0", "jinja2>=3.1.0", "python-multipart>=0.06", "pytest>=7.0.0", "pytest-cov>=4.0.0"]
- The development team is identified as MetroStar Systems, and the dependencies are widely supported open-source libraries.
- Static analysis cannot verify current vendor support status via external websites or conduct the required interviews with the application administrator.
- Requirement: PARTIALLY SATISFIED — components are identified, but support verification is an administrative/runtime task.

Remediation:
Remove or decommission all unsupported software products in the application.

---

### 271. APSC-DV-003250 | SV-222659r961863

- Rule ID: SV-222659r961863
- Severity: high
- Rule Title: The application must be decommissioned when maintenance or support is no longer available.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that the application be decommissioned when maintenance or support is no longer available.
- No maintenance contracts, support agreements, or decommissioning policies were found in the provided source code or documentation.
- The check requires an interview with the application representative to determine if components are under maintenance contract.
- Requirement: NOT SATISFIED — no static evidence of maintenance contracts or decommissioning policies exists in the repository.

Remediation:
Ensure there is maintenance for the application.

---

### 272. APSC-DV-003260 | SV-222660r961863

- Rule ID: SV-222660r961863
- Severity: low
- Rule Title: Procedures must be in place to notify users when an application is decommissioned.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires procedures to be in place to notify users when an application is decommissioned.
- No user notification procedures, communication plans, or decommissioning workflows were found in the repository.
- The check requires an interview with the application representative to verify these provisions.
- Requirement: NOT SATISFIED — no static evidence of user notification procedures for decommissioning was found.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application's static artifacts do not explicitly define a list of built-in accounts, but compliance cannot be fully verified without a runtime account audit.
- File: Dockerfile — No USER instructions creating built-in vendor accounts found.
- File: docker-compose.yml — No environment variables defining default administrative accounts found.
- Search: No evidence of hardcoded account lists or vendor-specific accounts (e.g., Oracle, Tivoli) in the provided source code.
- Requirement: PARTIALLY SATISFIED — No obvious built-in accounts found in static files, but a full account list review is required to confirm no unnecessary accounts exist at runtime.

Remediation:
Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Open
Confidence: 60/100

Evidence:
- Static repository review completed on 2026-11-15.
- No hardcoded default passwords were identified in the provided source code, but the control requires runtime verification.
- Search: No literal strings matching common default password patterns found in configuration files or source code.
- File: Dockerfile — No default passwords passed as build arguments or environment variables.
- File: docker-compose.yml — No default passwords defined in the environment section.
- Requirement: PARTIALLY SATISFIED — No static evidence of default passwords, but the required runtime authentication attempt cannot be performed via static analysis.

Remediation:
Configure the application to use strong authenticators instead of passwords when possible. Otherwise, change default passwords to a DoD-approved strength password and follow all guidance for passwords.

---

### 275. APSC-DV-003285 | SV-222663r961863

- Rule ID: SV-222663r961863
- Severity: medium
- Rule Title: An Application Configuration Guide must be created and included with the application.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The repository contains several specialized guides, but lacks a single, comprehensive Application Configuration Guide covering all mandatory STIG criteria.
- File: documentation/ANCHORE_CONFIGURATION_GUIDE.md — Provides tool-specific configuration for Anchore.
- File: documentation/CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md — Provides guidance on Dockerfile discovery and build evidence.
- File: documentation/ML_SECURITY_GUIDE.md — Provides guidance on ML security layers.
- Missing: A centralized guide covering Encryption Settings, PKI Certificate Configuration, Password Settings, Auditing configuration, AD configuration, and Backup/DR settings as required by the control.
- Requirement: NOT SATISFIED — No comprehensive Application Configuration Guide meeting the minimum STIG requirements is present.

Remediation:
Create the application configuration guide in accordance with configuration examples provided in the vulnerability discussion and check.

Verify the application configuration guide is distributed along  with the application.

---

### 276. APSC-DV-003290 | SV-222664r1051277

- Rule ID: SV-222664r1051277
- Severity: medium
- Rule Title: If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.

Status: Not Applicable
Confidence: 95/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not process or store classified information.
- Architecture: Epyon is a static source-code review and vulnerability scanning tool designed to analyze repositories and generate security reports.
- Documentation: No references to classified data handling, security classification guides, or classified environment requirements are found in `README.md`, `documentation/SECURITY.md`, or `documentation/STIG_COMPLIANCE_GUIDE.md`.
- Requirement: NOT APPLICABLE — the application does not process classified information.

Remediation:
Create and maintain a security classification guide.

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application implements a technical mechanism to detect and categorize mobile code, but evidence of authorization/waivers for the mobile code actually used is missing.
- Implementation: `scripts/shell/run-mobile-code-scan.py` is a dedicated scanner specifically designed to satisfy `APSC-DV-003300`.
- Detection Capabilities: The scanner identifies `inline_javascript`, `external_javascript`, `java_applet`, `flash`, `activex`, `vbscript`, `browser_extension`, `java_webstart`, and `downloadable_executable` via the `MOBILE_CODE_PATTERNS` dictionary.
- Policy Enforcement: The script includes a `load_policy` function and `check_approval_status` method to verify if detected mobile code is approved per a policy file.
- Current Usage: The application uses JavaScript in its web interface (e.g., `web/static/app.js`), which is a form of mobile code.
- Missing Evidence: No documented waiver or risk acceptance for the JavaScript used in the web UI is present in the repository.
- Requirement: PARTIALLY SATISFIED — detection and categorization mechanism is implemented, but authorization for used mobile code is not documented.

Remediation:
Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- No evidence of a process for sanitizing production database exports was found.
- Database Presence: The application utilizes a database as indicated by `web/api/db.py`.
- Missing Artifacts: There are no scripts, configuration files, or documentation (e.g., in `documentation/` or `scripts/shell/`) describing the process for exporting production data to test/dev environments or the removal of sensitive data/credentials during such exports.
- Requirement: NOT SATISFIED — no evidence of database export sanitization procedures exists in the static source code.

Remediation:
Remove sensitive data from production database exports.

---

### 279. APSC-DV-003320 | SV-222667r961863

- Rule ID: SV-222667r961863
- Severity: medium
- Rule Title: Protections against DoS attacks must be implemented.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires verification of DoS mitigations against a threat model document.
- No threat model document was found in the repository manifest or provided source files.
- No explicit DoS mitigation implementations (e.g., rate limiting middleware, request size constraints, or connection timeouts) were identified in the provided source code.
- Requirement: NOT SATISFIED — No threat model is present to identify DoS threats, and no corresponding mitigations are visible in the static artifacts.

Remediation:
Implement mitigations from the threat model for DOS attacks.

---

### 280. APSC-DV-003330 | SV-222668r961863

- Rule ID: SV-222668r961863
- Severity: medium
- Rule Title: The system must alert an administrator when low resource conditions are encountered.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires automated monitoring and alerting for low resource conditions.
- File: .github/workflows/performance-monitoring.yml — Evidence of a performance monitoring workflow exists.
- File: .github/README.md — Documentation provides examples for sending notifications to Slack, Teams, or email via GitHub Actions.
- Missing: There are no static configuration files (e.g., Prometheus alert rules, CloudWatch alarm definitions, or application-level resource monitors) that explicitly define thresholds or alerts for 'low resource conditions'.
- Requirement: PARTIALLY SATISFIED — Monitoring and notification capabilities exist, but specific low-resource alert configurations are not documented in the source code.

Remediation:
Implement mechanisms to alert system administrators about a low resource condition.

---

### 281. APSC-DV-003340 | SV-222669r961863

- Rule ID: SV-222669r961863
- Severity: low
- Rule Title: At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.

Status: Open
Confidence: 70/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires that at least one administrator is registered to receive update notifications or security alerts.
- File: .github/README.md — Describes the capability to send results to Slack, Teams, or email using custom notifications.
- File: .github/TARGET_REPO_SETUP.md — Describes the workflow for configuring target repositories to receive webhook notifications from Epyon.
- Missing: There is no static evidence (e.g., a configuration file, admin list, or registration record) identifying a specific registered administrator or deployment personnel assigned to receive these alerts.
- Requirement: PARTIALLY SATISFIED — The technical mechanism for notifications is implemented and documented, but the registration of specific personnel cannot be verified from static source code.

Remediation:
Register administrators to receive update notifications so they can patch and update applications and application components.

---

### 282. APSC-DV-003345 | SV-222670r961863

- Rule ID: SV-222670r961863
- Severity: low
- Rule Title: The application must provide notifications or alerts when product update and security related patches are available.

Status: Open
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application lacks a documented or implemented automated notification system to alert users of security patches and product updates.
- File: CHANGELOG.md — exists as a record of changes, but does not constitute an active notification or alert mechanism.
- File: .github/workflows/release-notes.yml — implements automated release note generation, but there is no evidence of a distribution mechanism (e.g., email, in-app alert, webhook) that pushes these notifications to users with risk descriptions and mitigations.
- Requirement: NOT SATISFIED — no evidence of a process that provides active notifications including issue descriptions, risks, and mitigation steps.

Remediation:
Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.

---

### 283. APSC-DV-003350 | SV-222671r961863

- Rule ID: SV-222671r961863
- Severity: medium
- Rule Title: Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.

Status: Open
Confidence: 80/100

Evidence:
- Static repository review completed on 2026-11-15.
- There is no evidence in the provided source code or infrastructure-as-code files defining the network topology or the presence of a DMZ for public access.
- File: docker-compose.yml — defines container orchestration but does not specify external network routing or DMZ architecture.
- File: tests/fixtures/self-assessment/iac/main.tf — contains network configurations, but is explicitly labeled as a 'scan fixture' and 'intentionally misconfigured' for testing purposes, not representing production architecture.
- Requirement: PARTIALLY SATISFIED — the application can be deployed, but the routing through a DMZ is an environmental configuration not visible in the static source code.

Remediation:
Setup a DMZ between DoD and public networks.

---

### 284. APSC-DV-003360 | SV-222672r961833

- Rule ID: SV-222672r961833
- Severity: low
- Rule Title: The application must generate audit records when concurrent logons from different workstations occur.

Status: Not Applicable
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not implement a user authentication or logon mechanism, making the tracking of concurrent logons architecturally impossible.
- File: documentation/STIG_COMPLIANCE_GUIDE.md — explicitly states for control APSC-DV-000460: 'Epyon is a CLI-based DevSecOps pipeline tool with no user authentication layer, no session management, no user accounts, no login/logoff mechanism'.
- Since there is no logon process, the requirement to generate audit records for concurrent logons from different workstations does not apply.
- Requirement: SATISFIED — control is Not Applicable due to the absence of an authentication layer.

Remediation:
Configure the application to log concurrent logons from different workstations.

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Open
Confidence: 100/100

Evidence:
- Static repository review completed on 2026-11-15.
- The control requires verification that all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.
- No evidence of training certificates, class rosters, or security training policies was found within the repository source code or documentation.
- Per `documentation/MANUAL_STIG_DOCUMENTATION_GUIDE.md`, this is a 'Policy-Based Control' that is typically satisfied by organizational policies rather than code and should be documented in manual STIG documentation.
- No manual assessment for APSC-DV-003400 exists in the provided manual documentation files.
- Requirement: NOT SATISFIED — No static evidence of annual security training is present in the repository.

Remediation:
Provide application development/operational related security specific annual training for managers, designers, developers, and testers.

---

### 286. APSC-DV-002010 | SV-265634r1117183

- Rule ID: SV-265634r1117183
- Severity: medium
- Rule Title: The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

Status: Not Applicable
Confidence: 90/100

Evidence:
- Static repository review completed on 2026-11-15.
- The application does not process classified data.
- File: _archive/cleanup-2026-05-27/scans/iris_2026-04-26_03-14-11/security-findings-summary-filtered.json — "classification": "INTERNAL USE ONLY"
- The application is designed for internal DevSecOps orchestration and does not handle classified information as defined by federal laws or Executive Orders.
- Requirement: NOT APPLICABLE — Application does not process classified data.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
