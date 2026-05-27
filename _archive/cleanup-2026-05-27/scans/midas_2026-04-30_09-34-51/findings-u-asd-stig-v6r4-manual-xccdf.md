# midas STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 212 |
| Not a Finding | 10 |
| Not Applicable | 61 |
| Not Reviewed | 3 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a mechanism to limit the number of logon sessions per user.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No configuration setting, environment variable, or code artifact found that enforces or limits the number of concurrent sessions per user (e.g., no 'max_sessions_per_user', no session-count tracking in security/middleware.py or token_authority.py).
- Session management is present (OAuth2/OIDC, Bearer tokens, session validation), but no evidence of per-user session count enforcement.
- Requirement: NOT SATISFIED — No static evidence of session count limitation per user; session management exists but does not enforce a maximum concurrent session policy.

Remediation:
Design and configure the application to specify the number of logon sessions that are allowed per user.

---

### 2. APSC-DV-000060 | SV-222388r1043182

- Rule ID: SV-222388r1043182
- Severity: medium
- Rule Title: The application must clear temporary storage and cookies when the session is terminated.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires clearing temporary storage and cookies on session termination and prohibits storing authentication data in cookies/local storage.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No code or configuration found that manages browser cookies, local storage, or explicitly clears client-side storage on logout/session termination.
- Authentication is handled via OAuth2/OIDC Bearer tokens (see security/middleware.py, security/oauth_proxy.py), but no evidence of cookie management or explicit clearing of sensitive data from client storage.
- Requirement: NOT SATISFIED — No static evidence that cookies or local storage are cleared on logout or that sensitive data is never stored client-side.

Remediation:
Design and configure the application to clear sensitive data from cookies and local storage when the user logs out of the application.

---

### 3. APSC-DV-000070 | SV-222389r1043182

- Rule ID: SV-222389r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic termination of non-privileged user sessions after 15 minutes of inactivity.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No configuration setting or code artifact found specifying a session idle timeout (e.g., no 'SESSION_TIMEOUT', 'idle_timeout', or similar in config or code).
- OAuth2/OIDC Bearer token expiry is enforced (see security/token_authority.py: VerifiedToken.expires_at), but token TTL is not statically set to 15 minutes for non-privileged users.
- Requirement: NOT SATISFIED — No static evidence of a 15-minute idle timeout for non-privileged user sessions.

Remediation:
Design and configure the application to terminate the non-privileged users session after 15 minutes of inactivity.

---

### 4. APSC-DV-000080 | SV-222390r1043182

- Rule ID: SV-222390r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic termination of admin user sessions after 10 minutes of inactivity.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No configuration setting or code artifact found specifying a session idle timeout for admin users (e.g., no 'ADMIN_SESSION_TIMEOUT', 'idle_timeout', or similar).
- OAuth2/OIDC Bearer token expiry is enforced (see security/token_authority.py: VerifiedToken.expires_at), but no evidence of a 10-minute idle timeout for admin sessions or role-based timeout differentiation.
- Requirement: NOT SATISFIED — No static evidence of a 10-minute idle timeout for admin user sessions.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a user-initiated logoff capability.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No explicit MCP tool, HTTP endpoint, or UI element for user-initiated logoff found in code or configuration. No 'logoff', 'logout', or session termination handler present in the provided files.
- OAuth2/OIDC flows are present (security/oauth_proxy.py), but no evidence of a user-accessible logoff function.
- Requirement: NOT SATISFIED — No static evidence of a user-initiated logoff capability.

Remediation:
Design and configure the application to provide all users with the capability to manually terminate their application session.

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires displaying an explicit logoff message to users upon session termination.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No code or configuration found that provides a logoff message or feedback to the user upon session termination. No 'logoff', 'logout', or message display logic present.
- Requirement: NOT SATISFIED — No static evidence of an explicit logoff message to users.

Remediation:
Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires associating security attributes (e.g., data markings) with information in storage if required by organizational policy (e.g., classified, CUI).
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence found of data marking, security attribute assignment, or storage of such attributes in project resource or storage models (core/project_resource.py: ProjectState, ProjectMetadata, etc.).
- No fields for classification, CUI, or custom security attributes in storage models.
- Requirement: PARTIALLY SATISFIED — Data models are extensible (additional_metadata fields exist), but no static evidence of actual security attribute assignment or enforcement.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires retaining security attributes (e.g., data markings) with information in process if required by organizational policy.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence found of security attribute propagation or enforcement during data processing. No code handling data markings or security attributes in process.
- Requirement: NOT SATISFIED — No static evidence of security attribute retention during processing.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires retaining security attributes (e.g., data markings) with information in transmission if required by organizational policy.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence found of security attribute transmission or enforcement. No code for attaching or transmitting data markings with outbound data.
- Requirement: NOT SATISFIED — No static evidence of security attribute retention during transmission.

Remediation:
Design and configure the application to retain the data marking when transmitting data.

---

### 10. APSC-DV-000160 | SV-222396r960759

- Rule ID: SV-222396r960759
- Severity: medium
- Rule Title: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires DoD-approved encryption (TLS) to protect confidentiality of remote access sessions.
- Searched: etc/atlas/config.yaml, pyproject.toml, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- pyproject.toml: 'uvicorn', 'starlette', and 'httpx' are present, which support TLS, but no static configuration for TLS (no 'ssl_certfile', 'ssl_keyfile', or enforced HTTPS URLs in config).
- README.md: Server runs on 'http://localhost:8000' by default; no mention of HTTPS or TLS configuration for production.
- security/safe_http_client.py: SSRF protection is present, but does not enforce HTTPS.
- Requirement: PARTIALLY SATISFIED — Libraries support TLS, but no static evidence of TLS being enforced or configured for remote access sessions.

Remediation:
Design and configure applications to use TLS encryption to protect the confidentiality of remote access sessions.

---

### 11. APSC-DV-000170 | SV-222397r960762

- Rule ID: SV-222397r960762
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires cryptographic mechanisms (TLS) to protect integrity of remote access sessions.
- Searched: etc/atlas/config.yaml, pyproject.toml, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- pyproject.toml: TLS-capable libraries present (uvicorn, httpx), but no static configuration for TLS enforcement.
- README.md: Default server runs on 'http://localhost:8000' (not HTTPS).
- No evidence of enforced HTTPS/TLS for all remote sessions.
- Requirement: PARTIALLY SATISFIED — Libraries support TLS, but no static evidence of TLS being enforced for session integrity.

Remediation:
Design and configure applications to use TLS encryption to protect the integrity of remote access sessions.

---

### 12. APSC-DV-000180 | SV-222398r960762

- Rule ID: SV-222398r960762
- Severity: medium
- Rule Title: Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses SOAP messages requiring integrity with Message ID, Service Request, Timestamp, SAML Assertion, and digital signatures.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SOAP message handling, WS-Security, or SAML assertion processing in any provided code or configuration.
- Requirement: NOT APPLICABLE — Application does not utilize SOAP messages or WS-Security.

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

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses WS-Security tokens in SOAP messages.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of WS-Security token usage or SOAP message processing.
- Requirement: NOT APPLICABLE — Application does not utilize WS-Security tokens.

Remediation:
Design and configure applications using WS-Security messages to use time stamps with creation and expiration times and sequence numbers.

---

### 14. APSC-DV-000200 | SV-222400r960759

- Rule ID: SV-222400r960759
- Severity: high
- Rule Title: Validity periods must be verified on all application messages using WS-Security or SAML assertions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses WS-Security or SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of WS-Security or SAML assertion usage.
- Requirement: NOT APPLICABLE — Application does not utilize WS-Security or SAML assertions.

Remediation:
Design and configure the application to use validity periods, ensure validity periods are verified on all WS-Security token profiles and SAML Assertions.

---

### 15. APSC-DV-000210 | SV-222401r960759

- Rule ID: SV-222401r960759
- Severity: medium
- Rule Title: The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SAML assertion usage or processing.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
Design and configure each SAML assertion authority to use unique assertion identifiers.

---

### 16. APSC-DV-000220 | SV-222402r960759

- Rule ID: SV-222402r960759
- Severity: medium
- Rule Title: The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses WS-Security tokens and transmits assertion data through intermediaries.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of WS-Security token usage or assertion data transmission.
- Requirement: NOT APPLICABLE — Application does not utilize WS-Security tokens.

Remediation:
Encrypt assertions or use equivalent confidentiality when sensitive assertion data is passed through an intermediary.

---

### 17. APSC-DV-000230 | SV-222403r960759

- Rule ID: SV-222403r960759
- Severity: high
- Rule Title: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses the SubjectConfirmation element in SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SAML assertion or SubjectConfirmation element usage.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
Design and configure the application to use the <NotOnOrAfter> condition when using the <SubjectConfirmation> element in a SAML assertion.

---

### 18. APSC-DV-000240 | SV-222404r960759

- Rule ID: SV-222404r960759
- Severity: high
- Rule Title: The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses the Conditions element in SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SAML assertion or Conditions element usage.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
Design and configure the application to implement the use of the <NotBefore> and <NotOnOrAfter> or <OneTimeUse> when using the <Conditions> element in a SAML assertion.

---

### 19. APSC-DV-000250 | SV-222405r960759

- Rule ID: SV-222405r960759
- Severity: medium
- Rule Title: The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses OneTimeUse elements in SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SAML assertion or OneTimeUse element usage.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
When using OneTimeUse elements in a SAML assertion only allow one, OneTimeUse element to be used in the conditions element of a SAML assertion.

---

### 20. APSC-DV-000260 | SV-222406r960759

- Rule ID: SV-222406r960759
- Severity: medium
- Rule Title: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application uses SessionIndex tied to privacy data in SAML assertions.
- Searched: etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/oauth_proxy.py, security/token_authority.py, README.md
- No evidence of SAML assertion or SessionIndex usage.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
Encrypt messages when the SessionIndex is tied to privacy data.

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automated mechanisms for account management (creation, disabling, removal, etc.).
- File: etc/atlas/config.yaml — No evidence of local user account management or automated account lifecycle controls; authentication is configured via OIDC/OAuth2 (see 'plugins.security' block), e.g.:
- issuer_url: "http://localhost:8082/realms/midas-mcp"
- mcp_audience: "http://localhost:8000/mcp"
- introspection_client_id: "mcp-service-client"
- File: README.md — Describes OIDC IdP integration and use of external identity providers (Keycloak, Cognito, Okta, etc.), but does not document any local user account management or automated account lifecycle enforcement.
- File: core/project_resource.py — Defines project/resource management, but not user account management.
- No static evidence of automated disabling/removal of inactive, suspended, or terminated user accounts within the application code or configuration.
- Requirement: PARTIALLY SATISFIED — OIDC/OAuth2 integration suggests external account management, but no explicit evidence that all user account activity is conducted via the external IdP and no local user accounts exist. Cannot confirm full automation of account lifecycle actions from static artifacts alone.

Remediation:
Use automated processes and mechanisms for account management functions.

---

### 22. APSC-DV-000290 | SV-222408r1015683

- Rule ID: SV-222408r1015683
- Severity: medium
- Rule Title: Shared/group account credentials must be terminated when members leave the group.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires procedures for terminating shared/group account credentials when members leave the group.
- File: etc/atlas/config.yaml — No mention of shared or group accounts in authentication configuration.
- File: README.md — No documentation of shared/group accounts; authentication is described as OIDC/OAuth2-based.
- File: core/project_resource.py — Only project/resource management, not user accounts.
- No static evidence of shared or group application accounts being supported or required.
- Requirement: NOT APPLICABLE — No evidence of shared/group accounts in application architecture or configuration.

Remediation:
Create a procedure for deleting either member accounts or the entire group account when members leave the group.

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires temporary user accounts to be automatically removed or disabled after 72 hours.
- File: etc/atlas/config.yaml — No configuration for temporary user accounts or account expiration.
- File: README.md — No mention of temporary user accounts; authentication is via external IdP.
- File: core/project_resource.py — No user account management.
- No static evidence of temporary user accounts being supported or required.
- Requirement: NOT APPLICABLE — No support for temporary user accounts in application design.

Remediation:
Configure temporary accounts to be automatically removed or disabled after 72 hours after account creation.

---

### 24. APSC-DV-000310 | SV-222410r961863

- Rule ID: SV-222410r961863
- Severity: low
- Rule Title: The application must have a process, feature or function that prevents removal or disabling of emergency accounts.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a process to prevent removal/disabling of emergency accounts during a crisis.
- File: etc/atlas/config.yaml — No mention of emergency accounts in authentication configuration.
- File: README.md — No documentation of emergency accounts.
- File: core/project_resource.py — No user account management.
- No static evidence of emergency accounts being supported or required.
- Requirement: NOT APPLICABLE — No support for emergency accounts in application design.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic disabling of accounts after 35 days of inactivity.
- File: etc/atlas/config.yaml — No configuration for account inactivity timeout or disabling.
- File: README.md — No mention of inactivity-based disabling; authentication is via external IdP.
- File: core/project_resource.py — No user account management.
- No static evidence of inactivity tracking or automatic disabling of user accounts.
- Requirement: NOT SATISFIED — No evidence of inactivity-based disabling in application or configuration.

Remediation:
Design and configure the application to expire user accounts after 35 days of inactivity.

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires disabling or deleting unnecessary application accounts.
- File: etc/atlas/config.yaml — No evidence of local application user accounts; authentication is via OIDC/OAuth2.
- File: README.md — No mention of local user accounts; all authentication appears to be delegated to external IdP.
- File: core/project_resource.py — Only manages project resources, not user accounts.
- Cannot confirm that no unnecessary application user accounts exist, nor that there is a process for disabling/deleting them, from static artifacts alone.
- Requirement: PARTIALLY SATISFIED — External IdP integration suggests no local accounts, but cannot confirm absence of unnecessary accounts without runtime/user enumeration.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing (logging) of account creation events.
- File: etc/atlas/config.yaml — No configuration for audit logging of user account creation.
- File: README.md — No mention of audit logging for user account events.
- File: core/project_resource.py — No user account management or audit logging.
- No static evidence of audit log entries for account creation.
- Requirement: NOT SATISFIED — No evidence of account creation audit logging in application code or configuration.

Remediation:
Configure the application to write a log entry when a new user account is created.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 28. APSC-DV-000350 | SV-222414r960780

- Rule ID: SV-222414r960780
- Severity: medium
- Rule Title: The application must automatically audit account modification.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing (logging) of account modification events.
- File: etc/atlas/config.yaml — No configuration for audit logging of user account modification.
- File: README.md — No mention of audit logging for user account events.
- File: core/project_resource.py — No user account management or audit logging.
- No static evidence of audit log entries for account modification.
- Requirement: NOT SATISFIED — No evidence of account modification audit logging in application code or configuration.

Remediation:
Configure the application to write a log entry when a user account is modified.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 29. APSC-DV-000360 | SV-222415r960783

- Rule ID: SV-222415r960783
- Severity: medium
- Rule Title: The application must automatically audit account disabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing (logging) of account disabling actions.
- File: etc/atlas/config.yaml — No configuration for audit logging of user account disabling.
- File: README.md — No mention of audit logging for user account events.
- File: core/project_resource.py — No user account management or audit logging.
- No static evidence of audit log entries for account disabling.
- Requirement: NOT SATISFIED — No evidence of account disabling audit logging in application code or configuration.

Remediation:
Configure the application to write a log entry when a user account is disabled.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 30. APSC-DV-000370 | SV-222416r960786

- Rule ID: SV-222416r960786
- Severity: medium
- Rule Title: The application must automatically audit account removal actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing (logging) of account removal actions.
- File: etc/atlas/config.yaml — No configuration for audit logging of user account removal.
- File: README.md — No mention of audit logging for user account events.
- File: core/project_resource.py — No user account management or audit logging.
- No static evidence of audit log entries for account removal.
- Requirement: NOT SATISFIED — No evidence of account removal audit logging in application code or configuration.

Remediation:
Configure the application to write a log entry when a user account is removed.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 31. APSC-DV-000380 | SV-222417r1015684

- Rule ID: SV-222417r1015684
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are created.
- File: etc/atlas/config.yaml — No configuration for notifications to SAs/ISSOs on account creation.
- File: README.md — No mention of such notifications; authentication is via external IdP.
- File: core/project_resource.py — No user account management or notification logic.
- No static evidence of notification mechanism for account creation events.
- Requirement: NOT SATISFIED — No evidence of SA/ISSO notification on account creation.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are created.

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are modified.
- File: etc/atlas/config.yaml — No configuration for notifications to SAs/ISSOs on account modification.
- File: README.md — No mention of such notifications; authentication is via external IdP.
- File: core/project_resource.py — No user account management or notification logic.
- No static evidence of notification mechanism for account modification events.
- Requirement: NOT SATISFIED — No evidence of SA/ISSO notification on account modification.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are modified.

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are disabled.
- File: etc/atlas/config.yaml — No configuration for notifications to SAs/ISSOs on account disabling.
- File: README.md — No mention of such notifications; authentication is via external IdP.
- File: core/project_resource.py — No user account management or notification logic.
- No static evidence of notification mechanism for account disabling events.
- Requirement: NOT SATISFIED — No evidence of SA/ISSO notification on account disabling.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are disabled.

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are removed.
- File: etc/atlas/config.yaml — No configuration for notifications to SAs/ISSOs on account removal.
- File: README.md — No mention of such notifications; authentication is via external IdP.
- File: core/project_resource.py — No user account management or notification logic.
- No static evidence of notification mechanism for account removal events.
- Requirement: NOT SATISFIED — No evidence of SA/ISSO notification on account removal.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing (logging) of account enabling actions.
- File: etc/atlas/config.yaml — No configuration for audit logging of user account enabling.
- File: README.md — No mention of audit logging for user account events.
- File: core/project_resource.py — No user account management or audit logging.
- No static evidence of audit log entries for account enabling.
- Requirement: NOT SATISFIED — No evidence of account enabling audit logging in application code or configuration.

Remediation:
Configure the application to write a log entry when a user account is enabled. 

At a minimum, ensure account name, date and time of the event are recorded.

---

### 36. APSC-DV-000430 | SV-222422r1015688

- Rule ID: SV-222422r1015688
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are enabled.
- File: etc/atlas/config.yaml — No configuration for notifications to SAs/ISSOs on account enabling.
- File: README.md — No mention of such notifications; authentication is via external IdP.
- File: core/project_resource.py — No user account management or notification logic.
- No static evidence of notification mechanism for account enabling events.
- Requirement: NOT SATISFIED — No evidence of SA/ISSO notification on account enabling.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are enabled.

---

### 37. APSC-DV-000440 | SV-222423r961302

- Rule ID: SV-222423r961302
- Severity: medium
- Rule Title: Application data protection requirements must be identified and documented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires documentation of application data protection requirements.
- File: etc/atlas/config.yaml — Contains configuration for data storage (vectorstores, context, cortex, etc.), but does not document data protection requirements or controls.
- File: README.md — No explicit documentation of data protection requirements for application data elements.
- No evidence of a data protection requirements document or section.
- Requirement: NOT SATISFIED — No documentation of data protection requirements found in provided artifacts.

Remediation:
Identify and document the application data elements and the data protection requirements.

---

### 38. APSC-DV-000450 | SV-222424r961305

- Rule ID: SV-222424r961305
- Severity: medium
- Rule Title: The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires implementation of data mining detection techniques if required by the organization.
- File: etc/atlas/config.yaml — No configuration for data mining detection, query rate limiting, or automated alarming on atypical query events.
- File: README.md — No mention of data mining protections, query limits, or anti-mining controls.
- File: core/project_resource.py — No data mining detection logic.
- No static evidence of data mining detection or prevention mechanisms.
- Requirement: NOT SATISFIED — No evidence of data mining detection techniques implemented.

Remediation:
Utilize and implement data mining protections when requirements specify it.

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of approved authorizations for logical access to information and system resources.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'plugins.security' block), e.g.:
- issuer_url: "http://localhost:8082/realms/midas-mcp"
- mcp_audience: "http://localhost:8000/mcp"
- introspection_client_id: "mcp-service-client"
- File: README.md — Describes OIDC IdP integration and use of external identity providers, but does not document access control policies or RBAC.
- File: core/project_resource.py — No access control enforcement for application resources.
- No static evidence of RBAC, ACLs, or other access control enforcement for application resources.
- Requirement: PARTIALLY SATISFIED — OIDC/OAuth2 integration suggests authentication is enforced, but no evidence of fine-grained authorization or access control policies for application resources.

Remediation:
Design or configure the application to enforce access to application resources.

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires discretionary access control (DAC) policies allowing users to set permissions on application data/objects.
- File: etc/atlas/config.yaml — No configuration for user-managed permissions or DAC.
- File: README.md — No mention of discretionary access controls or user-managed permissions.
- File: core/project_resource.py — No support for user-managed permissions on resources.
- No static evidence of DAC implementation or user-controlled sharing/authorization.
- Requirement: NOT APPLICABLE — Application does not implement discretionary access controls; only system-level (OIDC/OAuth2) authentication is present.

Remediation:
Design and configure the application to enforce discretionary access control policies.

---

### 41. APSC-DV-000480 | SV-222427r1117168

- Rule ID: SV-222427r1117168
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of information flow control policies (rulesets, data labels, policies) within the application.
- File: README.md — No mention of data labeling, information flow control, or policy enforcement for data movement within the system. The architecture and plugin/facet system focus on code analysis, context management, and AI-driven tooling, but do not describe any mechanism for labeling data (e.g., PII) or restricting its flow based on policy.
- File: etc/atlas/config.yaml — No configuration keys for data labels, information flow policies, or enforcement rules. Plugin configurations focus on AI personas, context storage, ingestion pipelines, and code/project resource management, but not on information flow control.
- File: core/facet.py — Defines plugin/facet system, but no evidence of data labeling or flow control logic.
- File: core/project_resource.py — Project resource management (e.g., Git, GitHub, Jira), but no data flow control or labeling.
- File: plugins/github_bookstore.py — Context storage via GitHub Issues, but no data labeling or flow control.
- Requirement: PARTIALLY SATISFIED — The application provides resource/project management and context storage, but there is no evidence of data labeling or enforcement of information flow control policies. No static artifacts implement or configure such controls.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 42. APSC-DV-000490 | SV-222428r1117169

- Rule ID: SV-222428r1117169
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of information flow control policies between interconnected systems (rulesets, data labels, policies, system boundaries).
- File: README.md — No mention of data labeling, information flow control, or policy enforcement for data movement between systems. Interconnected systems (e.g., GitHub, Git, Jira) are referenced as resource types, but no flow control is described.
- File: etc/atlas/config.yaml — No configuration for data flow policies or enforcement between systems. Resource/project management is present, but not flow control.
- File: core/project_resource.py — Supports multiple resource types (Git, GitHub Issues, etc.), but no evidence of data labeling or flow control between them.
- File: plugins/github_bookstore.py — Manages context entries via GitHub Issues, but no flow control or data labeling.
- Requirement: PARTIALLY SATISFIED — The application integrates with multiple systems, but there is no evidence of data labeling or enforcement of information flow control policies between them.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 43. APSC-DV-000500 | SV-222429r961353

- Rule ID: SV-222429r961353
- Severity: medium
- Rule Title: The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires prevention of non-privileged users from executing privileged functions, including file/directory permissions and OS/database account rights.
- File: README.md — No documentation of application user accounts, OS group memberships, or privilege separation. No mention of privileged vs non-privileged user roles.
- File: Makefile — No OS-level user or group configuration; all commands assume the current user context.
- File: etc/atlas/config.yaml — No configuration for application user accounts, privilege separation, or OS/database rights. OAuth2/OIDC configuration is present, but does not specify privilege enforcement at the OS or database level.
- File: core/facet.py, core/project_resource.py — No code for privilege separation or enforcement of privileged function access.
- Requirement: PARTIALLY SATISFIED — The application uses OAuth2/OIDC for authentication, but there is no evidence of static enforcement of OS/database privilege separation or prevention of non-privileged users executing privileged functions. No static artifacts define or restrict privileged operations at the OS or database level.

Remediation:
Modify the application to limit access and prevent the disabling or circumvention of security safeguards.

---

### 44. APSC-DV-000510 | SV-222430r961359

- Rule ID: SV-222430r961359
- Severity: high
- Rule Title: The application must execute without excessive account permissions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the application to execute without excessive account permissions (OS, database, etc.).
- File: README.md — No mention of dedicated application accounts, OS group memberships, or database roles. No documentation of least-privilege configuration.
- File: Makefile — All commands run as the invoking user; no user switching or privilege dropping.
- File: etc/atlas/config.yaml — No configuration for application OS/database accounts or privilege levels. OAuth2/OIDC configuration is present, but does not address OS/database privilege minimization.
- File: core/project_resource.py — Project resource management, but no evidence of privilege minimization for application accounts.
- Requirement: PARTIALLY SATISFIED — The application does not statically define or enforce least-privilege execution for OS or database accounts. No static artifacts configure or document minimal privilege operation.

Remediation:
Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.

---

### 45. APSC-DV-000520 | SV-222431r961362

- Rule ID: SV-222431r961362
- Severity: medium
- Rule Title: The application must audit the execution of privileged functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires auditing the execution of privileged functions (logging admin actions, configuration changes, etc.).
- File: README.md — No mention of privileged function auditing or log entries for admin actions.
- File: etc/atlas/config.yaml — No configuration for audit logging of privileged functions. Audit log retention is not configured; only usage log retention for event logs is present (usage_log_retention_days: 7).
- File: core/facet.py — No code for privileged function auditing or log generation for admin actions.
- File: security/oauth_proxy.py — Uses security.audit_log.emit for token proxy events, but not for privileged function execution within the application.
- Requirement: PARTIALLY SATISFIED — Audit logging is present for OAuth2 token proxy events, but there is no evidence of privileged function execution auditing (e.g., user management, configuration changes) within the application.

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of a limit of three consecutive invalid logon attempts within 15 minutes (account lockout).
- File: README.md — No mention of account lockout, failed login attempt tracking, or lockout thresholds.
- File: etc/atlas/config.yaml — No configuration for failed login attempt limits, lockout duration, or lockout policy. OAuth2/OIDC configuration is present, but does not specify lockout behavior.
- File: core/facet.py, security/oauth_proxy.py — No code for tracking failed login attempts or enforcing lockout after three failures.
- Requirement: NOT SATISFIED — No evidence of account lockout or failed login attempt enforcement in static configuration or code.

Remediation:
Configure the application to enforce an account lock after 3 failed logon attempts occurring within a 15-minute window.

---

### 47. APSC-DV-000540 | SV-222433r961368

- Rule ID: SV-222433r961368
- Severity: medium
- Rule Title: The application administrator must follow an approved process to unlock locked user accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires an approved process for unlocking locked user accounts (manual or automated, with identity validation).
- File: README.md — No documentation of account unlock process or procedures for unlocking locked accounts.
- File: etc/atlas/config.yaml — No configuration for account unlock process, admin approval, or identity validation for unlocking accounts.
- File: core/facet.py, security/oauth_proxy.py — No code for account unlock workflows or admin unlock procedures.
- Requirement: NOT SATISFIED — No evidence of an account unlock process or controls for unlocking locked user accounts.

Remediation:
Create a standard approved process for unlocking locked application accounts which includes validating user identity prior to unlocking the account.

Use that process when unlocking application user accounts.

---

### 48. APSC-DV-000550 | SV-222434r960843

- Rule ID: SV-222434r960843
- Severity: low
- Rule Title: The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires display of the Standard Mandatory DoD Notice and Consent Banner before granting access to the application (interactive UI).
- File: README.md — The application is described as a backend MCP server with AI assistant integration (VS Code, Copilot, etc.), not as an interactive user interface. No mention of a login screen or UI banner.
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- File: etc/atlas/config.yaml — No configuration for login banners or consent notices.
- Requirement: NOT APPLICABLE — The application does not provide an interactive user interface; it is a backend service for AI assistants and code analysis.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the DoD banner to remain on screen until user acknowledges usage conditions (interactive UI).
- File: README.md — No interactive user interface; application is a backend MCP server for AI assistants (VS Code, Copilot, etc.).
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- File: etc/atlas/config.yaml — No configuration for login banners or consent notices.
- Requirement: NOT APPLICABLE — The application does not provide an interactive user interface.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only to publicly accessible applications with interactive UI, requiring the DoD banner before access.
- File: README.md — Application is a backend MCP server for AI assistants, not a public-facing interactive application.
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- File: etc/atlas/config.yaml — No configuration for login banners or consent notices.
- Requirement: NOT APPLICABLE — The application is not a publicly accessible interactive application.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires display of the user's last successful logon date/time in the user interface.
- File: README.md — No interactive user interface; application is a backend MCP server for AI assistants.
- File: core/facet.py, core/project_resource.py — No UI code or display of last logon information.
- File: etc/atlas/config.yaml — No configuration for displaying last logon information.
- Requirement: NOT APPLICABLE — The application does not provide a user interface for displaying last logon information.

Remediation:
Design and configure the application to display the date and time when the user was last successfully granted access to the application.

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires non-repudiation (digital signatures) for actions if required by application design or organization.
- File: README.md — No mention of non-repudiation, digital signatures, or requirements for user action attestation. Application is not described as an email or transaction system requiring non-repudiation.
- File: etc/atlas/config.yaml — No configuration for digital signatures or non-repudiation services.
- File: core/facet.py, core/project_resource.py — No code for digital signature generation or verification.
- Requirement: NOT APPLICABLE — The application is not required to provide non-repudiation services by design or organizational policy.

Remediation:
Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.

---

### 53. APSC-DV-000600 | SV-222439r960873

- Rule ID: SV-222439r960873
- Severity: medium
- Rule Title: For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only to applications providing audit record aggregation from multiple system components.
- File: README.md — No mention of audit record aggregation or system-wide audit trail correlation. Application focuses on code analysis, context management, and AI tooling.
- File: etc/atlas/config.yaml — No configuration for audit record aggregation or time correlation.
- File: core/facet.py, core/project_resource.py — No code for audit record aggregation.
- Requirement: NOT APPLICABLE — The application does not provide audit record aggregation services.

Remediation:
Configure the application to correlate time stamps when aggregating audit records.

---

### 54. APSC-DV-000620 | SV-222441r960879

- Rule ID: SV-222441r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the creation of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for creation of session IDs (log session creation events).
- File: README.md — No mention of session ID creation logging or audit record generation for session events.
- File: etc/atlas/config.yaml — No configuration for session ID creation event logging or audit settings for session management.
- File: core/facet.py — Defines Chronicle for client state, but does not log session creation events.
- File: security/oauth_proxy.py — Handles OAuth2 token and authorization endpoints, but does not log session ID creation events.
- Requirement: NOT SATISFIED — No evidence of session ID creation event auditing in static configuration or code.

Remediation:
Enable session ID creation event auditing.

---

### 55. APSC-DV-000630 | SV-222442r960879

- Rule ID: SV-222442r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the destruction of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for destruction of session IDs (log session termination events).
- File: README.md — No mention of session ID destruction logging or audit record generation for session termination.
- File: etc/atlas/config.yaml — No configuration for session ID destruction event logging or audit settings for session management.
- File: core/facet.py — Defines Chronicle for client state, but does not log session destruction events.
- File: security/oauth_proxy.py — Handles OAuth2 token and authorization endpoints, but does not log session ID destruction events.
- Requirement: NOT SATISFIED — No evidence of session ID destruction event auditing in static configuration or code.

Remediation:
Enable session ID destruction event auditing.

---

### 56. APSC-DV-000640 | SV-222443r960879

- Rule ID: SV-222443r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the renewal of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for renewal of session IDs (log session renewal events, e.g., privilege escalation).
- File: README.md — No mention of session ID renewal logging or audit record generation for session renewal events.
- File: etc/atlas/config.yaml — No configuration for session ID renewal event logging or audit settings for session management.
- File: core/facet.py — Defines Chronicle for client state, but does not log session renewal events.
- File: security/oauth_proxy.py — Handles OAuth2 token and authorization endpoints, but does not log session ID renewal events.
- Requirement: NOT SATISFIED — No evidence of session ID renewal event auditing in static configuration or code.

Remediation:
Design or reconfigure the application to log session renewal events on those application events that provide changes in the users privileges or permissions to the application.

---

### 57. APSC-DV-000650 | SV-222444r960879

- Rule ID: SV-222444r960879
- Severity: medium
- Rule Title: The application must not write sensitive data into the application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires that sensitive data (passwords, session IDs, encryption keys, etc.) are not written to application logs.
- File: README.md — No mention of sensitive data logging or log sanitization.
- File: etc/atlas/config.yaml — No configuration for log redaction, sensitive data filtering, or log sanitization.
- File: core/facet.py — Uses Clio logger for logging, but no evidence of log filtering or redaction of sensitive data.
- File: security/oauth_proxy.py — Logs token proxy events and audit logs, but does not log sensitive data such as passwords or session IDs. However, no explicit filtering or redaction is present in the logging code.
- Requirement: PARTIALLY SATISFIED — No evidence of sensitive data being logged, but also no explicit filtering or redaction mechanisms are present. Cannot confirm full compliance without reviewing all log statements and runtime behavior.

Remediation:
Design or reconfigure the application to not write sensitive data to the logs.

---

### 58. APSC-DV-000660 | SV-222445r960879

- Rule ID: SV-222445r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for session timeouts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for session timeouts (log session timeout events).
- File: README.md — No mention of session timeout logging or audit record generation for session timeouts.
- File: etc/atlas/config.yaml — No configuration for session timeout event logging or audit settings for session management.
- File: core/facet.py — Defines Chronicle for client state, but does not log session timeout events.
- File: security/oauth_proxy.py — Handles OAuth2 token and authorization endpoints, but does not log session timeout events.
- Requirement: NOT SATISFIED — No evidence of session timeout event auditing in static configuration or code.

Remediation:
Configure the application to record session timeout events in the logs.

---

### 59. APSC-DV-000670 | SV-222446r960879

- Rule ID: SV-222446r960879
- Severity: medium
- Rule Title: The application must record a time stamp indicating when the event occurred.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires that audit records include a time stamp indicating when the event occurred.
- File: security/oauth_proxy.py — Audit log entries for token proxy events include a timestamp field (e.g., in _audit calls and log_queue.put in AsyncJob), but this is limited to OAuth2 token proxy events, not general application events.
- File: core/facet.py — AsyncJob.log() includes 'timestamp': datetime.now().isoformat() in log messages, but this is for async job progress, not general audit records.
- File: README.md, etc/atlas/config.yaml — No mention of general audit record time stamping.
- Requirement: PARTIALLY SATISFIED — Some log/audit events include timestamps (OAuth2 proxy, async jobs), but there is no evidence that all audit records/events throughout the application include a time stamp.

Remediation:
Configure the application to record the time the event occurred when recording the event.

---

### 60. APSC-DV-000680 | SV-222447r960879

- Rule ID: SV-222447r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for HTTP headers (User-Agent, Referer, GET, POST, etc.).
- File: README.md — No mention of HTTP header logging or audit record generation for HTTP requests.
- File: etc/atlas/config.yaml — No configuration for HTTP header logging or audit settings for HTTP requests.
- File: security/oauth_proxy.py — Handles OAuth2 token and authorization endpoints, but does not log HTTP headers (User-Agent, Referer, etc.) in audit logs or elsewhere.
- File: core/facet.py — No code for HTTP header logging.
- Requirement: NOT SATISFIED — No evidence of HTTP header logging or audit record generation for HTTP requests in static configuration or code.

Remediation:
Configure the web application and/or the web server to log HTTP headers.

---

### 61. APSC-DV-000690 | SV-222448r960879

- Rule ID: SV-222448r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for connecting system IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs to record connecting system IP addresses.
- File: security/middleware.py — BearerMiddleware extracts client IP from ASGI scope: `client_ip: str = (scope.get("client") or ("unknown", 0))[0]`
- File: security/middleware.py — On authentication events (success/failure), emits audit logs with `client_ip` field: `_audit(..., client_ip=client_ip, ...)`
- File: security/audit_log.py (not included) — Implements `emit` function for structured audit logging, but log storage location and format are not shown in provided files.
- File: README.md — No explicit documentation of audit log storage or log format.
- Requirement: PARTIALLY SATISFIED — IP addresses are captured and included in structured audit log events, but the actual persistence of these logs (file path, retention, log format) cannot be confirmed from static artifacts alone.

Remediation:
Configure the application or application server to log all connecting IP address information

---

### 62. APSC-DV-000700 | SV-222449r960879

- Rule ID: SV-222449r960879
- Severity: medium
- Rule Title: The application must record the username or user ID of the user associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires that logs record the username or user ID associated with each event.
- File: security/middleware.py — On authentication events, emits audit logs with `sub` field (subject from JWT): `_audit(..., sub=verified.sub, ...)`
- File: security/token_authority.py — `VerifiedToken` exposes `sub` (subject) from the JWT, which is used as the user identifier.
- File: security/audit_log.py (not included) — Implements `emit` function for audit logs, but log storage and format are not shown.
- File: README.md — No explicit documentation of log format or user ID field in logs.
- Requirement: PARTIALLY SATISFIED — User ID (JWT subject) is included in audit log events, but the actual log output and storage cannot be confirmed from static artifacts alone.

Remediation:
Configure the application to record the user ID of the user responsible for the log event entry.

---

### 63. APSC-DV-000710 | SV-222450r960885

- Rule ID: SV-222450r960885
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to grant privileges.
- File: core/project_resource.py — ProjectResource and ProjectRegistry support resource registration and privilege management, but no explicit audit logging for privilege grants is present.
- File: security/middleware.py — Only authentication and scope checks are audited, not privilege grants.
- File: README.md — No mention of privilege grant logging in audit or logging sections.
- Requirement: NOT SATISFIED — No static evidence of audit records for privilege grant attempts.

Remediation:
Configure the application to audit successful and unsuccessful attempts to grant privileges.

---

### 64. APSC-DV-000720 | SV-222451r961791

- Rule ID: SV-222451r961791
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to access security objects.
- File: core/project_resource.py — Defines resource access and state, but no explicit audit logging for access attempts to security objects.
- File: security/middleware.py — Audits authentication, not object access.
- File: README.md — No documentation of audit logging for security object access.
- Requirement: NOT SATISFIED — No static evidence of audit records for access attempts to security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.

---

### 65. APSC-DV-000730 | SV-222452r961794

- Rule ID: SV-222452r961794
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to access security levels.
- File: core/project_resource.py — No explicit concept of security levels or audit logging for access attempts to different security levels.
- File: security/middleware.py — Only authentication and scope checks are audited.
- File: README.md — No documentation of security level access or related audit logging.
- Requirement: NOT SATISFIED — No static evidence of audit records for access attempts to security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for access to categories of information (e.g., classification levels), but only if the application implements compartmentalized data or classification.
- File: README.md — No mention of data classification, compartmentalized data, or information categories.
- File: etc/atlas/config.yaml — No configuration for data categories or classification levels.
- Requirement: NOT APPLICABLE — Application does not implement compartmentalized data or classification levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access protected categories of information.

---

### 67. APSC-DV-000750 | SV-222454r961800

- Rule ID: SV-222454r961800
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to modify privileges.
- File: core/project_resource.py — ProjectResource and ProjectRegistry manage resources and projects, but no explicit audit logging for privilege modification events.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for privilege modification attempts.

Remediation:
Configure the application to audit successful and unsuccessful attempts to modify privileges.

---

### 68. APSC-DV-000760 | SV-222455r961803

- Rule ID: SV-222455r961803
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to modify security objects.
- File: core/project_resource.py — No explicit audit logging for modification of security objects.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for modification attempts to security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security objects.

---

### 69. APSC-DV-000770 | SV-222456r961806

- Rule ID: SV-222456r961806
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to modify security levels.
- File: core/project_resource.py — No explicit concept of security levels or audit logging for modification attempts.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for modification attempts to security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for modification of categories of information (e.g., classification levels), but only if the application implements compartmentalized data or classification.
- File: README.md — No mention of data classification, compartmentalized data, or information categories.
- File: etc/atlas/config.yaml — No configuration for data categories or classification levels.
- Requirement: NOT APPLICABLE — Application does not implement compartmentalized data or classification levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify protected categories of information.

---

### 71. APSC-DV-000790 | SV-222458r961812

- Rule ID: SV-222458r961812
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to delete privileges.
- File: core/project_resource.py — No explicit audit logging for privilege deletion events.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for privilege deletion attempts.

Remediation:
Configure the application to audit successful and unsuccessful attempts to delete privileges.

---

### 72. APSC-DV-000800 | SV-222459r961815

- Rule ID: SV-222459r961815
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to delete security levels.
- File: core/project_resource.py — No explicit concept of security levels or audit logging for deletion attempts.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for deletion attempts to security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.

---

### 73. APSC-DV-000810 | SV-222460r961818

- Rule ID: SV-222460r961818
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to delete application database security objects.
- File: core/project_resource.py — No explicit audit logging for deletion of database security objects.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for deletion attempts to database security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for deletion of categories of information (e.g., classification levels), but only if the application implements compartmentalized data or classification.
- File: README.md — No mention of data classification, compartmentalized data, or information categories.
- File: etc/atlas/config.yaml — No configuration for data categories or classification levels.
- Requirement: NOT APPLICABLE — Application does not implement compartmentalized data or classification levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete protected categories of information.

---

### 75. APSC-DV-000830 | SV-222462r961824

- Rule ID: SV-222462r961824
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful logon attempts occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful logon attempts.
- File: security/middleware.py — On authentication, emits audit logs for both success (`auth_grant`) and failure (`auth_deny`) events, including user ID and client IP.
- File: security/audit_log.py (not included) — Implements `emit` function for audit logs, but log storage and format are not shown.
- File: README.md — No explicit documentation of logon event logging or log storage.
- Requirement: PARTIALLY SATISFIED — Audit events for logon attempts are emitted, but actual log persistence and reviewability cannot be confirmed from static artifacts alone.

Remediation:
Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.

---

### 76. APSC-DV-000840 | SV-222463r961827

- Rule ID: SV-222463r961827
- Severity: medium
- Rule Title: The application must generate audit records for privileged activities or other system-level access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for privileged activities or system-level access.
- File: security/middleware.py — Only authentication and scope checks are audited; no evidence of privileged activity logging (e.g., admin actions, service control).
- File: core/project_resource.py — No explicit audit logging for privileged activities.
- Requirement: NOT SATISFIED — No static evidence of audit records for privileged activities or system-level access.

Remediation:
Configure the application to write a log entry when privileged activities or other system-level events occur.

---

### 77. APSC-DV-000850 | SV-222464r961830

- Rule ID: SV-222464r961830
- Severity: medium
- Rule Title: The application must generate audit records showing starting and ending time for user access to the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records showing starting and ending time for user access (session start/end).
- File: security/middleware.py — Logs authentication events, but no evidence of session end (logout/termination) logging.
- File: core/facet.py — Chronicle tracks `connection_time` and `last_activity` in memory, but no evidence these are logged to audit records.
- Requirement: PARTIALLY SATISFIED — Session start (authentication) is logged, but session end is not evidenced in static artifacts.

Remediation:
Configure the application or application server to record the start and end time of user session activity.

---

### 78. APSC-DV-000860 | SV-222465r961836

- Rule ID: SV-222465r961836
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful accesses to objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful accesses to application objects (files, modules, etc.).
- File: core/project_resource.py — Tracks resource access and state, but no explicit audit logging for object access events.
- File: security/middleware.py — Only authentication and scope checks are audited.
- Requirement: NOT SATISFIED — No static evidence of audit records for object access events.

Remediation:
Configure the application to log successful and unsuccessful access to application objects.

---

### 79. APSC-DV-000870 | SV-222466r961839

- Rule ID: SV-222466r961839
- Severity: medium
- Rule Title: The application must generate audit records for all direct access to the information system.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for all direct access to the information system (e.g., OS commands, file system navigation), but only if the application provides such features.
- File: README.md — No mention of direct OS access, shell execution, or system resource manipulation features.
- File: core/project_resource.py — No evidence of direct OS access features.
- Requirement: NOT APPLICABLE — Application does not provide direct access to the underlying OS.

Remediation:
Configure the application to log all direct access to the system.

---

### 80. APSC-DV-000880 | SV-222467r961842

- Rule ID: SV-222467r961842
- Severity: medium
- Rule Title: The application must generate audit records for all account creations, modifications, disabling, and termination events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for all account creations, modifications, disabling, and termination events.
- File: security/middleware.py — Only authentication events are audited; no evidence of user account management or related audit logging.
- File: README.md — No documentation of user account management or audit logging for account events.
- Requirement: NOT SATISFIED — No static evidence of audit records for account creation, modification, disabling, or termination.

Remediation:
Configure the application to log user account creation, modification, disabling, and termination events.

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application initiates session auditing (logging) upon startup, with log entries indicating application startup events.
- File: core/facet.py — Facet base class and all plugin facets use a logger (Clio) and log initialization events. Example: `self.logger.info("FacetMyTool initialized")` in the facet pattern, and `self.logger.info("AdviceFacet initialized")` in plugins/advice.py.
- File: core/kb.py — KnowledgeBase logs initialization: `self.logger.info("KnowledgeBase initialized")`.
- File: core/project_resource.py — ProjectRegistry logs initialization: `self.logger.info("ProjectRegistry initialized")`.
- File: plugins/advice.py — AdviceFacet logs initialization: `self.logger.info("AdviceFacet initialized")`.
- File: Makefile — The default `make dev` target starts the server and dev IdP, and the README.md instructs to run `make dev` or `python midas.py`, both of which trigger startup logging.
- Logging is performed via the Clio logger, which is used throughout the codebase for all major components and facets, ensuring that startup events are logged as soon as the application starts.
- Requirement: SATISFIED — Application startup events are logged immediately upon startup via Clio logger in all core components and facets.

Remediation:
Configure the application to begin logging application events as soon as the application starts up.

---

### 82. APSC-DV-000940 | SV-222469r960891

- Rule ID: SV-222469r960891
- Severity: medium
- Rule Title: The application must log application shutdown events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that application shutdown events are recorded in the logs.
- File: core/facet.py — Facet base class provides a `shutdown()` method, which logs shutdown events: `self.logger.info("AdviceFacet shutting down")` in plugins/advice.py, and `super().shutdown()` in facet shutdowns.
- File: plugins/advice.py — AdviceFacet overrides `shutdown()` and logs: `self.logger.info("AdviceFacet shutting down")`.
- File: core/kb.py — No explicit shutdown logging found.
- File: core/project_resource.py — No explicit shutdown logging found.
- However, there is no evidence in the provided files that the application server or main entrypoint (e.g., midas.py) calls the `shutdown()` method on all facets or logs a global shutdown event at process exit. The shutdown hooks exist at the facet level, but invocation at application shutdown is not statically confirmed from the provided files.
- Requirement: PARTIALLY SATISFIED — Facet-level shutdown logging is implemented, but global application shutdown event logging cannot be confirmed from static artifacts alone. Evidence of server-wide shutdown logging or invocation of all facet shutdown hooks is missing.

Remediation:
Configure the application or application server to record application shutdown events in the event logs.

---

### 83. APSC-DV-000950 | SV-222470r960891

- Rule ID: SV-222470r960891
- Severity: medium
- Rule Title: The application must log destination IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application logs destination IP addresses for outbound connections.
- File: README.md — No mention of logging destination IP addresses for outbound connections.
- File: core/project_resource.py — ProjectResource and ProjectRegistry track resource identifiers (e.g., repository URLs) but do not log destination IP addresses.
- File: plugins/advice.py — No evidence of logging destination IP addresses.
- File: Makefile — No evidence of logging destination IP addresses.
- File: etc/atlas/config.yaml — No configuration for logging destination IP addresses.
- File: security/middleware.py — Middleware logs client IPs for inbound requests (`client_ip: str = (scope.get("client") or ("unknown", 0))[0]`), but not destination IPs for outbound connections.
- There is no evidence in the provided files that outbound network connections (e.g., to GitHub, OIDC IdP, or other services) are logged with destination IP addresses.
- Requirement: NOT SATISFIED — No static evidence that destination IP addresses of outbound connections are logged. Outbound connection logging is not implemented or not visible in the provided files.

Remediation:
Configure the application to record the destination IP address of the remote system.

---

### 84. APSC-DV-000960 | SV-222471r960891

- Rule ID: SV-222471r960891
- Severity: medium
- Rule Title: The application must log user actions involving access to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires logging user actions involving access to data (e.g., database or sensitive data access).
- File: plugins/advice.py — The `knowledge_ask` handler logs queries and client IDs: `self.logger.info(f"Advice request from client {chronicle.client_id} for query: '{query}' (query_id={query_id})")`, but this logs tool usage, not direct data access.
- File: core/project_resource.py — ProjectResource and ProjectRegistry track resource state and metadata but do not log user data access events.
- File: core/facet.py — Chronicle tracks transaction history, but there is no evidence that data access events are logged.
- File: security/middleware.py — Logs authentication events, not data access.
- There is no evidence of audit logging for user access to specific data elements (e.g., reading database records, files, or sensitive information).
- Requirement: NOT SATISFIED — No static evidence that user actions involving access to data are logged. Logging is present for tool invocation, but not for data access events.

Remediation:
Identify the specific data elements requiring protection and audit access to the data.

---

### 85. APSC-DV-000970 | SV-222472r960891

- Rule ID: SV-222472r960891
- Severity: medium
- Rule Title: The application must log user actions involving changes to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires logging user actions involving changes to data (e.g., modifications to protected data elements).
- File: plugins/advice.py — The `knowledge_contribute` handler logs knowledge contributions: `self.logger.info(f"Knowledge contribution from client {chronicle.client_id}")` and logs successful creation of context records, but this is limited to knowledgebase contributions, not general data changes.
- File: core/project_resource.py — ProjectResource and ProjectRegistry track project state and history, but there is no evidence of audit logging for user-initiated data changes.
- File: core/facet.py — No evidence of logging user data modification events.
- File: security/middleware.py — Logs authentication events, not data modification.
- There is no evidence of audit logging for user actions that modify application data (e.g., database updates, file changes) outside of knowledgebase contributions.
- Requirement: NOT SATISFIED — No static evidence that user actions involving changes to data are logged. Logging is present for knowledge contributions, but not for general data modification events.

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records include date and time information for each event.
- File: plugins/advice.py — All logging via Clio logger includes timestamps (see logger usage throughout the facet, e.g., `self.logger.info(...)`).
- File: core/facet.py — AsyncJob and other logging calls use `datetime.now().isoformat()` for timestamps in job logs.
- File: security/middleware.py — All audit logs and JSONResponse logs include timestamps, e.g., `self.log("status", f"Job {self.job_id} started")` and audit logs in `_audit()`.
- File: core/project_resource.py — ProjectMetadata, ProjectState, and HistoryEntry include `created_at`, `timestamp`, and `checked_at` fields, all in ISO format.
- Logging infrastructure (Clio) and audit logs consistently include date and time for all events.
- Requirement: SATISFIED — Audit records and logs include date and time information for all events.

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records include information to establish which component, feature, or function triggered the event.
- File: plugins/advice.py — Logging statements include facet name and tool name (e.g., `self.logger.info(f"Advice request from client {chronicle.client_id} for query: '{query}' (query_id={query_id})")`).
- File: core/facet.py — Each facet is instantiated with a logger named after the facet (e.g., `Clio(f"facet_{self.name}")`), and logs include the facet/component name.
- File: core/project_resource.py — ProjectRegistry and ProjectResource log resource type and identifier for all resource operations.
- File: security/middleware.py — Logs include method, path, and event type (e.g., `auth_grant`, `auth_deny`).
- Logging consistently includes component/facet names, tool names, and function context, allowing traceability to the originating component or feature.
- Requirement: SATISFIED — Audit records include sufficient information to establish which component, feature, or function triggered the event.

Remediation:
Configure the application to log which component, feature or functionality of the application triggered the event.

---

### 88. APSC-DV-001000 | SV-222475r960900

- Rule ID: SV-222475r960900
- Severity: medium
- Rule Title: When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that, when using centralized logging, the application includes a unique identifier to distinguish itself from other application logs (e.g., application name and host/client name).
- File: README.md — No explicit mention of centralized logging or unique application identifiers in logs.
- File: core/facet.py — Loggers are named per facet (e.g., `facet_advice`), but there is no evidence of a global application identifier or host/client name in log records.
- File: core/project_resource.py — No evidence of application name or host/client name in logs.
- File: etc/atlas/config.yaml — No configuration for centralized logging or unique application identifiers in logs.
- File: security/middleware.py — Audit logs include `client_ip` for inbound requests, but not application name or host name for log records.
- There is no evidence that logs include both the application name and the host/client name as required for centralized log correlation.
- Requirement: NOT SATISFIED — No static evidence that logs include a unique application identifier and host/client name for centralized logging.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records include information to establish the outcome of events (e.g., SUCCESS, FAILURE, ERROR, PASS).
- File: plugins/advice.py — Logging statements indicate actions (e.g., knowledge contribution, advice request), but do not explicitly log the outcome (success/failure) of each event.
- File: core/facet.py — AsyncJob logs status changes (e.g., `self.log("status", f"Job {self.job_id} started")`, `self.log("status", f"Job {self.job_id} completed")`, `self.log("error", f"Job {self.job_id} failed: {error}")`), but this is limited to async jobs, not general audit events.
- File: security/middleware.py — Audit logs include `auth_grant` and `auth_deny` events, which indicate outcome for authentication events, but not for all application operations.
- There is no evidence that all audit records for application operations (e.g., data access, data modification, tool invocation) include explicit outcome information.
- Requirement: PARTIALLY SATISFIED — Some audit events (authentication, async jobs) include outcome, but general application operations do not consistently log outcome information.

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records include the identity of any individual or process associated with the event.
- File: plugins/advice.py — Logging statements include `chronicle.client_id` for all tool invocations (e.g., `self.logger.info(f"Advice request from client {chronicle.client_id} for query: '{query}' (query_id={query_id})")`).
- File: core/facet.py — Chronicle tracks `client_id` for each session, and all tool handlers receive the chronicle as the first argument.
- File: security/middleware.py — Audit logs include `sub` (subject) from the verified token for all authentication events.
- File: core/project_resource.py — ProjectResource and ProjectRegistry log resource operations, and user/process identity can be traced via chronicle and logger context.
- Logging infrastructure ensures that user/process identity is included in audit records for all tool invocations and authentication events.
- Requirement: SATISFIED — Audit records include the identity of the user or process associated with each event.

Remediation:
Configure the application to log the identity of the user and/or the process associated with the event.

---

### 91. APSC-DV-001030 | SV-222478r960909

- Rule ID: SV-222478r960909
- Severity: medium
- Rule Title: The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records include the full-text recording of privileged commands or the individual identities of group account users.
- File: plugins/advice.py — No evidence of privileged command logging or group account user identification.
- File: core/facet.py — No evidence of privileged command logging.
- File: core/project_resource.py — No evidence of privileged command logging or group account user identification.
- File: security/middleware.py — Logs authentication events, but not privileged commands.
- There is no evidence that privileged commands (if any) are logged in full text, or that group account user identities are recorded in audit logs.
- Requirement: NOT SATISFIED — No static evidence of privileged command logging or group account user identification in audit records.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires transaction recovery logs when the application is transaction-based.
- File: README.md — No evidence that the application is transaction-based (e.g., no database transaction management or ACID transaction support).
- File: core/project_resource.py — ProjectResource tracks project state and history, but does not implement transaction logging or recovery.
- File: etc/atlas/config.yaml — No configuration for transaction logging or recovery logs.
- The application is not architected as a transaction-based system (no evidence of transactional database operations or recovery logs).
- Requirement: NOT APPLICABLE — Application is not transaction-based; transaction recovery logs do not apply.

Remediation:
Configure the application database to utilize transactional logging.

---

### 93. APSC-DV-001050 | SV-222480r985972

- Rule ID: SV-222480r985972
- Severity: medium
- Rule Title: The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires centralized management and configuration of the content to be captured in audit records generated by all application components.
- File: etc/atlas/config.yaml — Centralized configuration for facets and plugins, but no evidence of centralized log management or configuration of audit record content.
- File: README.md — No mention of centralized log management or configuration interface for audit records.
- File: core/facet.py, core/kb.py, core/project_resource.py — Each component uses its own logger (Clio), but there is no evidence of a centralized log management interface or configuration for audit record content.
- Requirement: NOT SATISFIED — No static evidence of centralized management or configuration of audit record content across all application components.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that audit records are off-loaded onto a different system or media than the system being audited, unless a centralized logging solution is used.
- File: README.md — No evidence of local log off-loading; no mention of log rotation or transfer.
- File: etc/atlas/config.yaml — No configuration for log off-loading or transfer to external media.
- File: core/facet.py, core/kb.py, core/project_resource.py — No evidence of log off-loading.
- The application does not implement local log off-loading, and there is no evidence of a centralized logging solution. However, if the application is configured to use a centralized logging system, this requirement is not applicable.
- Requirement: NOT APPLICABLE — No evidence of local log off-loading, and centralized logging is not statically configured in the provided files.

Remediation:
Configure the application to off-load audit records onto a different system as per approved schedule.

---

### 95. APSC-DV-001080 | SV-222482r961860

- Rule ID: SV-222482r961860
- Severity: medium
- Rule Title: The application must be configured to write application logs to a centralized log repository.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application is configured to write application logs to a centralized log repository.
- File: etc/atlas/config.yaml — No configuration for centralized log repository or log forwarding.
- File: README.md — No mention of centralized log repository or log forwarding.
- File: core/facet.py, core/kb.py, core/project_resource.py — Each component uses its own logger (Clio), but there is no evidence of log forwarding or centralized log repository integration.
- Requirement: NOT SATISFIED — No static evidence that logs are written to a centralized log repository.

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application provides an immediate warning to the SA and ISSO when audit record storage volume reaches 75% of capacity, unless a centralized logging system provides this capability.
- File: etc/atlas/config.yaml — No configuration for log storage capacity monitoring or alarming.
- File: README.md — No mention of log storage capacity monitoring or alarming.
- File: core/facet.py, core/kb.py, core/project_resource.py — No evidence of log storage capacity monitoring or alarming.
- If a centralized logging system is used that provides storage capacity alarming, this requirement is not applicable. There is no evidence of such a system in the provided files.
- Requirement: NOT APPLICABLE — No evidence of local log storage capacity monitoring, and centralized logging is not statically configured in the provided files.

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires immediate real-time alerting to the SA and ISSO for all audit failure events for moderate/high impact applications, unless a centralized logging system provides this capability.
- File: etc/atlas/config.yaml — No configuration for audit failure alerting.
- File: README.md — No mention of audit failure alerting.
- File: core/facet.py, core/kb.py, core/project_resource.py — No evidence of audit failure alerting.
- If a centralized logging system is used that provides real-time alerting, this requirement is not applicable. There is no evidence of such a system in the provided files.
- Requirement: NOT APPLICABLE — No evidence of local audit failure alerting, and centralized logging is not statically configured in the provided files.

Remediation:
Configure the log alerts to send an alarm when the audit system is in danger of failing or has failed.  

Configure the log alerts to be immediately sent to the application admin/SA and ISSO.

---

### 98. APSC-DV-001110 | SV-222485r960912

- Rule ID: SV-222485r960912
- Severity: medium
- Rule Title: The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application alerts the ISSO and SA in the event of an audit processing failure, unless a centralized logging system provides this capability.
- File: etc/atlas/config.yaml — No configuration for audit processing failure alerting.
- File: README.md — No mention of audit processing failure alerting.
- File: core/facet.py, core/kb.py, core/project_resource.py — No evidence of audit processing failure alerting.
- If a centralized logging system is used that provides audit processing failure alarms, this requirement is not applicable. There is no evidence of such a system in the provided files.
- Requirement: NOT APPLICABLE — No evidence of local audit processing failure alerting, and centralized logging is not statically configured in the provided files.

Remediation:
Configure the application to send an alarm in the event the audit system has failed or is failing.

---

### 99. APSC-DV-001120 | SV-222486r1043188

- Rule ID: SV-222486r1043188
- Severity: medium
- Rule Title: The application must shut down by default upon audit failure (unless availability is an overriding concern).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that the application shuts down by default upon audit failure, or compensates to ensure audit events are not lost.
- File: core/facet.py, core/kb.py, core/project_resource.py — No evidence of application shutdown logic or configuration in response to audit/logging failures.
- File: security/middleware.py — Handles authentication failures and logs audit events, but does not implement application shutdown or compensatory logging mechanisms on audit failure.
- File: etc/atlas/config.yaml — No configuration for shutdown on audit failure or compensatory logging.
- Requirement: NOT SATISFIED — No static evidence that the application shuts down or compensates in the event of audit failure.

Remediation:
Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.

---

### 100. APSC-DV-001130 | SV-222487r960918

- Rule ID: SV-222487r960918
- Severity: medium
- Rule Title: The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the capability to centrally review and analyze audit records from multiple components within the system, unless a centralized logging system provides this capability.
- File: etc/atlas/config.yaml — No configuration for centralized log review or analysis.
- File: README.md — No mention of centralized log review or analysis.
- File: core/facet.py, core/kb.py, core/project_resource.py — Each component uses its own logger (Clio), but there is no evidence of a centralized log review or analysis capability.
- Requirement: NOT SATISFIED — No static evidence of centralized review and analysis of audit records from multiple components.

Remediation:
Configure the application so all of the applications logs are available for review from one centralized location.

---

### 101. APSC-DV-001140 | SV-222488r960924

- Rule ID: SV-222488r960924
- Severity: medium
- Rule Title: The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to provide filtering of audit records based on user, event type, date/time, system resource, IP, object, event level, and keywords.
- File: core/project_resource.py — ProjectRegistry class provides methods for listing resources and projects, but there is no evidence of an audit log filtering capability or audit log management utility in this file.
- File: README.md — No mention of audit log filtering or user-facing audit log management tools. The MCP tools reference does not include audit log filtering or querying.
- File: etc/atlas/config.yaml — No configuration for audit log filtering or audit log management utilities. No mention of audit log storage or filtering criteria.
- Requirement: PARTIALLY SATISFIED — Project/resource management is present, but there is no static evidence of audit log filtering capability as required by the control. Audit log filtering features are not documented or implemented in the provided files.

Remediation:
Configure the application filters to search event logs based on defined criteria.

---

### 102. APSC-DV-001150 | SV-222489r961056

- Rule ID: SV-222489r961056
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires on-demand reporting based on filtered audit event data (users, event types, dates, etc.).
- File: core/project_resource.py — ProjectRegistry supports listing resources and projects, but there is no evidence of audit log reporting or filtering features.
- File: README.md — No mention of audit log reporting or audit reduction tools. MCP tools reference does not include audit log reporting.
- File: etc/atlas/config.yaml — No configuration for audit log reporting or audit reduction.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or on-demand audit reporting capability for audit logs.

Remediation:
Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.

---

### 103. APSC-DV-001160 | SV-222490r961413

- Rule ID: SV-222490r961413
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit reduction capability for on-demand audit review and analysis (filtering and reporting on audit logs).
- File: core/project_resource.py — No audit log review or reduction features are implemented.
- File: README.md — No mention of audit log review or analysis tools.
- File: etc/atlas/config.yaml — No configuration for audit log review or reduction.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or on-demand audit review/analysis for audit logs.

Remediation:
Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.

---

### 104. APSC-DV-001170 | SV-222491r961416

- Rule ID: SV-222491r961416
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit reduction (event filtering) to support after-the-fact investigations.
- File: core/project_resource.py — No audit log filtering or reduction features are present.
- File: README.md — No mention of audit log investigation or filtering tools.
- File: etc/atlas/config.yaml — No configuration for audit log investigation or filtering.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or filtering for after-the-fact investigations.

Remediation:
Configure the application to provide an audit reduction capability that supports forensic investigations.

---

### 105. APSC-DV-001180 | SV-222492r961419

- Rule ID: SV-222492r961419
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires report generation capability for on-demand audit review and analysis.
- File: core/project_resource.py — No report generation or audit log reporting features are present.
- File: README.md — No mention of audit log report generation tools.
- File: etc/atlas/config.yaml — No configuration for audit log report generation.
- Requirement: NOT SATISFIED — No static evidence of audit log report generation capability.

Remediation:
Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 106. APSC-DV-001190 | SV-222493r961422

- Rule ID: SV-222493r961422
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires on-demand report generation for audit logs.
- File: core/project_resource.py — No audit log report generation features are present.
- File: README.md — No mention of audit log report generation tools.
- File: etc/atlas/config.yaml — No configuration for audit log report generation.
- Requirement: NOT SATISFIED — No static evidence of on-demand audit log report generation capability.

Remediation:
Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 107. APSC-DV-001200 | SV-222494r961425

- Rule ID: SV-222494r961425
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires report generation for after-the-fact investigations of security incidents (audit logs).
- File: core/project_resource.py — No audit log report generation or investigation features are present.
- File: README.md — No mention of audit log report generation for investigations.
- File: etc/atlas/config.yaml — No configuration for audit log report generation for investigations.
- Requirement: NOT SATISFIED — No static evidence of audit log report generation for after-the-fact investigations.

Remediation:
Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.

---

### 108. APSC-DV-001210 | SV-222495r961428

- Rule ID: SV-222495r961428
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit reduction (event filtering) that does not alter original content or time ordering of audit records.
- File: core/project_resource.py — No audit reduction or filtering features are present, so there is no evidence of preservation or alteration of audit records.
- File: README.md — No mention of audit log filtering or content preservation.
- File: etc/atlas/config.yaml — No configuration for audit log filtering or preservation.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or filtering, so preservation of original content/time ordering cannot be confirmed.

Remediation:
Configure the application to not alter original log content or time ordering of audit records.

---

### 109. APSC-DV-001220 | SV-222496r961431

- Rule ID: SV-222496r961431
- Severity: medium
- Rule Title: The application must provide a report generation capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires report generation that does not alter original content or time ordering of audit records.
- File: core/project_resource.py — No audit log report generation features are present, so there is no evidence of preservation or alteration of audit records.
- File: README.md — No mention of audit log report generation or content preservation.
- File: etc/atlas/config.yaml — No configuration for audit log report generation or preservation.
- Requirement: NOT SATISFIED — No static evidence of audit log report generation, so preservation of original content/time ordering cannot be confirmed.

Remediation:
Configure and design the application to not modify source logs when filtering events.

---

### 110. APSC-DV-001250 | SV-222497r960927

- Rule ID: SV-222497r960927
- Severity: medium
- Rule Title: The applications must use internal system clocks to generate time stamps for audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to use internal system clocks to generate time stamps for audit records.
- File: core/project_resource.py — ProjectState, HistoryEntry, and RemoteCheckResult use ISO timestamps (e.g., 'created_at', 'timestamp', 'checked_at'), and timestamps are generated via datetime.now(UTC).isoformat(). However, these are for project/resource state, not audit logs. There is no evidence of audit log timestamping.
- File: lib/ingestion/state.py — IngestionRecord and StalenessResult use datetime.now().isoformat() for timestamps, but this is for ingestion state, not audit logs.
- File: README.md — No mention of audit log timestamping.
- Requirement: PARTIALLY SATISFIED — Timestamps for project/resource/ingestion state use system clock, but there is no evidence of audit log timestamping as required by the control.

Remediation:
Configure the application to use the hosting systems internal clock for audit record generation.

---

### 111. APSC-DV-001260 | SV-222498r961443

- Rule ID: SV-222498r961443
- Severity: medium
- Rule Title: The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit record timestamps to be mappable to UTC/GMT.
- File: core/project_resource.py — Timestamps are generated using datetime.now(UTC).isoformat(), which is UTC. Example: 'created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())'.
- File: lib/ingestion/state.py — IngestionRecord uses datetime.now().isoformat(), which is local time unless explicitly set to UTC. No explicit UTC enforcement in this file.
- File: README.md — No mention of audit log timestamp mapping to UTC/GMT.
- Requirement: PARTIALLY SATISFIED — Project/resource state uses UTC timestamps, but ingestion state may use local time. No evidence for audit log timestamps.

Remediation:
Configure the application to use the underlying system clock that maps to relevant UTC or GMT timezone.

---

### 112. APSC-DV-001270 | SV-222499r961446

- Rule ID: SV-222499r961446
- Severity: medium
- Rule Title: The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit record timestamps to have at least one-second granularity.
- File: core/project_resource.py — Timestamps are generated using datetime.now(UTC).isoformat(), which includes seconds and microseconds. Example: 'created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())'.
- File: lib/ingestion/state.py — IngestionRecord uses datetime.now().isoformat(), which includes seconds and microseconds.
- File: README.md — No mention of audit log timestamp granularity.
- Requirement: PARTIALLY SATISFIED — Project/resource/ingestion state timestamps meet granularity, but no evidence for audit log timestamps.

Remediation:
Configure the application to leverage the underlying operating system as the time source when recording time stamps or design the application to ensure granularity of 1 second as the minimum degree of precision.

---

### 113. APSC-DV-001280 | SV-222500r960930

- Rule ID: SV-222500r960930
- Severity: medium
- Rule Title: The application must protect audit information from any type of unauthorized read access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit information to be protected from unauthorized read access.
- File: core/project_resource.py — No audit log storage or access control is implemented. Project/resource state is persisted to JSON files, but file permissions or access controls are not set in code.
- File: lib/ingestion/state.py — Ingestion state is persisted to a JSON file, but no file permission management is present.
- File: README.md — No mention of audit log access control or permissions.
- Requirement: NOT SATISFIED — No static evidence of audit log access control or protection from unauthorized read access.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish permissions that control access to the audit logs and audit configuration settings.

---

### 114. APSC-DV-001290 | SV-222501r960933

- Rule ID: SV-222501r960933
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized modification.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit information to be protected from unauthorized modification.
- File: core/project_resource.py — No audit log storage or access control is implemented. Project/resource state is persisted to JSON files, but file permissions or access controls are not set in code.
- File: lib/ingestion/state.py — Ingestion state is persisted to a JSON file, but no file permission management is present.
- File: README.md — No mention of audit log modification protection.
- Requirement: NOT SATISFIED — No static evidence of audit log modification protection or access control.

Remediation:
Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 115. APSC-DV-001300 | SV-222502r960936

- Rule ID: SV-222502r960936
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized deletion.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit information to be protected from unauthorized deletion.
- File: core/project_resource.py — No audit log storage or access control is implemented. Project/resource state is persisted to JSON files, but file permissions or access controls are not set in code.
- File: lib/ingestion/state.py — Ingestion state is persisted to a JSON file, but no file permission management is present.
- File: README.md — No mention of audit log deletion protection.
- Requirement: NOT SATISFIED — No static evidence of audit log deletion protection or access control.

Remediation:
Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 116. APSC-DV-001310 | SV-222503r960939

- Rule ID: SV-222503r960939
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application provides a distinct audit tool with the ability to view/manipulate log data.
- File: README.md — No mention of a distinct audit tool or audit tool functionality. No separate executable or UI for audit log management is described.
- File: core/project_resource.py — No audit tool functionality is implemented.
- File: etc/atlas/config.yaml — No configuration for audit tools.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality is present in the application.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 117. APSC-DV-001320 | SV-222504r960942

- Rule ID: SV-222504r960942
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized modification.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application provides a distinct audit tool with the ability to view/manipulate log data.
- File: README.md — No mention of a distinct audit tool or audit tool functionality. No separate executable or UI for audit log management is described.
- File: core/project_resource.py — No audit tool functionality is implemented.
- File: etc/atlas/config.yaml — No configuration for audit tools.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality is present in the application.

Remediation:
Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 118. APSC-DV-001330 | SV-222505r960945

- Rule ID: SV-222505r960945
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized deletion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application provides a distinct audit tool with the ability to view/manipulate log data.
- File: README.md — No mention of a distinct audit tool or audit tool functionality. No separate executable or UI for audit log management is described.
- File: core/project_resource.py — No audit tool functionality is implemented.
- File: etc/atlas/config.yaml — No configuration for audit tools.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality is present in the application.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application includes a built-in backup capability for its own audit records.
- File: README.md — No mention of audit log backup or built-in backup features for audit logs.
- File: core/project_resource.py — No backup functionality for audit logs is implemented.
- File: etc/atlas/config.yaml — No configuration for audit log backup.
- Requirement: NOT APPLICABLE — No built-in audit log backup capability is present in the application.

Remediation:
Configure application backup settings to backup application audit logs every 7 days.

---

### 120. APSC-DV-001350 | SV-222507r960951

- Rule ID: SV-222507r960951
- Severity: medium
- Rule Title: The application must use cryptographic mechanisms to protect the integrity of audit information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires cryptographic mechanisms (e.g., hash, message digest) to protect the integrity of audit information.
- File: core/project_resource.py — No cryptographic integrity checks or hash generation for audit logs are implemented. Project/resource state is persisted as plain JSON.
- File: lib/ingestion/state.py — Ingestion state is persisted as plain JSON. No cryptographic hash or integrity check is performed.
- File: README.md — No mention of cryptographic integrity protection for audit logs.
- Requirement: NOT SATISFIED — No static evidence of cryptographic mechanisms to protect audit log integrity.

Remediation:
Configure the application to create an integrity check consisting of a cryptographic hash or one-way digest that can be used to establish the integrity when storing log files.

---

### 121. APSC-DV-001360 | SV-222508r961206

- Rule ID: SV-222508r961206
- Severity: medium
- Rule Title: Application audit tools must be cryptographically hashed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the presence of separate file-oriented audit tools (executables/libraries) for viewing/manipulating logs, and that their integrity is tracked via cryptographic hashes.
- No file in the manifest or README.md describes or implements a standalone audit tool for viewing or manipulating logs; audit logging is handled internally (see security/audit_log.py, not included here).
- No binaries, CLI tools, or scripts for log manipulation are present in the provided files or referenced in documentation.
- Requirement: NOT APPLICABLE — Application does not provide separate audit tools as standalone files; audit is internal.

Remediation:
Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.

---

### 122. APSC-DV-001370 | SV-222509r961206

- Rule ID: SV-222509r961206
- Severity: medium
- Rule Title: The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires periodic validation of cryptographic hashes for separate audit tool files.
- No standalone audit tool files exist in the application (see APSC-DV-001360 evidence).
- No process or configuration for periodic hash checking of audit tools is present in the provided files or documentation.
- Requirement: NOT APPLICABLE — No separate audit tool files exist; control does not apply.

Remediation:
Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.

---

### 123. APSC-DV-001390 | SV-222510r1015689

- Rule ID: SV-222510r1015689
- Severity: medium
- Rule Title: The application must prohibit user installation of software without explicit privileged status.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the application to prohibit user installation of software/components unless explicitly privileged.
- No plugin/extension/module installation capability is described in README.md or implemented in any provided file.
- All plugin/facet registration is performed statically in code (see README.md 'Creating a New Facet' and midas_facets.py, not included here), not via user interface or runtime installation.
- No user-facing UI or API for installing software is present.
- Requirement: NOT APPLICABLE — Application does not provide user-facing software/component installation capability.

Remediation:
Configure the application to prohibit user installation of software without explicit permission.

---

### 124. APSC-DV-001410 | SV-222511r961461

- Rule ID: SV-222511r961461
- Severity: medium
- Rule Title: The application must enforce access restrictions associated with changes to application configuration.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires access restrictions on application configuration changes.
- etc/atlas/config.yaml: Main configuration file, referenced in README.md and Makefile.
- README.md: 'For production or when using an external IdP, set the environment variables before running python midas.py directly' and 'Pass --config PATH to use a different file.'
- No explicit file permission settings or enforcement logic for config.yaml are present in the provided files.
- No code in core/facet.py or core/project_resource.py enforces OS-level file permissions or restricts configuration changes to privileged users.
- Requirement: PARTIALLY SATISFIED — Configuration is file-based and referenced in documentation, but static evidence of access restriction (e.g., file permissions, privilege checks) is missing.

Remediation:
Configure the application to limit access to configuration settings to only authorized users.

---

### 125. APSC-DV-001420 | SV-222512r1015690

- Rule ID: SV-222512r1015690
- Severity: medium
- Rule Title: The application must audit who makes configuration changes to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires auditing who makes configuration changes.
- etc/atlas/config.yaml: Configuration is file-based; changes are made via text editor as per README.md.
- No evidence in README.md, Makefile, or core/project_resource.py of audit logging for configuration file changes (e.g., inotify, auditd integration, or application-level logging of config edits).
- No code in core/facet.py or core/project_resource.py logs user identity on config changes.
- Requirement: NOT SATISFIED — No static evidence of audit logging for configuration changes or user identification.

Remediation:
Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.

---

### 126. APSC-DV-001430 | SV-222513r1015691

- Rule ID: SV-222513r1015691
- Severity: medium
- Rule Title: The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires preventing installation of unsigned patches/components or providing cryptographic hashes for manual verification.
- README.md and Makefile: All installation is via pip from requirements.lock or from GitHub releases; no patching or update mechanism is described.
- pyproject.toml: All dependencies are installed via pip; no digital signature or hash verification for packages is enforced in static configuration.
- No code or configuration in provided files enforces signature verification or provides hashes for manual verification of patches/components.
- Requirement: NOT SATISFIED — No static evidence of digital signature enforcement or hash verification for installed components.

Remediation:
Design and configure the application to have the capability to prevent unsigned patches and packages from being installed.

Provide a cryptographic hash value that can be verified by a system administrator prior to installation.

---

### 127. APSC-DV-001440 | SV-222514r960960

- Rule ID: SV-222514r960960
- Severity: medium
- Rule Title: The applications must limit privileges to change the software resident within software libraries.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires restricting privileges to change software libraries.
- Libraries are installed via pip into a virtual environment (see Makefile, pyproject.toml).
- No static evidence in Makefile, pyproject.toml, or README.md of OS-level file permission enforcement on installed libraries.
- No application-level logic in core/facet.py or core/project_resource.py to restrict library modification.
- Requirement: PARTIALLY SATISFIED — Libraries are managed via pip/venv, but no static enforcement of privilege restrictions is present in the provided files.

Remediation:
Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.

---

### 128. APSC-DV-001460 | SV-222515r961863

- Rule ID: SV-222515r961863
- Severity: medium
- Rule Title: An application vulnerability assessment must be conducted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires regular application vulnerability assessments and retention of scan results.
- README.md: 'Testing' and 'CI/CD' sections describe baseline and property testing, but do not mention vulnerability scanning.
- .github/workflows/ci.yml: No step for vulnerability scanning is present in the provided workflow (security-scan job references an external workflow MetroStar/epyon/.github/workflows/epyon-scan.yml@main, not included here).
- No static evidence of vulnerability scan configuration, tool invocation, or scan result retention in provided files.
- Requirement: PARTIALLY SATISFIED — CI pipeline references external security scan, but configuration and results are not statically available in this repository.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of organization-defined policies restricting program execution (e.g., via AppLocker, RBAC, etc.).
- No static policy files, RBAC configuration, or execution restriction logic is present in the provided files.
- This control is primarily enforced at the OS or deployment environment level, not within application source code.
- Requirement: NOT REVIEWED — No static artifacts; enforcement is external to application code.

Remediation:
Restrict application execution in accordance with the policy, terms, and conditions specified.

---

### 130. APSC-DV-001490 | SV-222517r961479

- Rule ID: SV-222517r961479
- Severity: medium
- Rule Title: The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires application whitelisting (deny-all, permit-by-exception) for execution, applicable only to configuration management or similar applications.
- README.md and all provided files: Application is not a configuration management system and does not manage execution of other applications or subcomponents.
- No whitelisting or execution policy logic is present in the codebase.
- Requirement: NOT APPLICABLE — Application is not a configuration management or process control system.

Remediation:
Configure the application to utilize a deny-all, permit-by-exception policy when allowing the execution of authorized software.

---

### 131. APSC-DV-001500 | SV-222518r960963

- Rule ID: SV-222518r960963
- Severity: medium
- Rule Title: The application must be configured to disable non-essential capabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires disabling non-essential capabilities.
- README.md: Describes available facets and plugins, but no configuration or code for disabling unused features is present.
- etc/atlas/config.yaml: All facets and plugins are enabled by default; no 'enabled' flags or feature toggles are present.
- No static evidence of a mechanism to disable non-essential plugins or capabilities.
- Requirement: NOT SATISFIED — No static mechanism for disabling non-essential capabilities is present.

Remediation:
Disable application extraneous application functionality that is not required in order to fulfill the application's mission.

---

### 132. APSC-DV-001510 | SV-222519r1043177

- Rule ID: SV-222519r1043177
- Severity: medium
- Rule Title: The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires restricting application to PPSM CAL-approved ports/protocols.
- etc/atlas/config.yaml: 'server_port: 8000' under plugins.security; dev IdP runs on port 8080 (Makefile).
- README.md: 'MIDAS listens on http://localhost:8000 by default.'
- No static evidence of protocol restriction or explicit PPSM CAL mapping in configuration.
- No documentation or code mapping used ports to PPSM CAL categories.
- Requirement: PARTIALLY SATISFIED — Ports are statically configured, but no evidence of PPSM CAL compliance or protocol restriction.

Remediation:
Configure the application to utilize application ports approved by the PPSM CAL.

---

### 133. APSC-DV-001520 | SV-222520r1050664

- Rule ID: SV-222520r1050664
- Severity: medium
- Rule Title: The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires reauthentication on privilege escalation or role change.
- No user role or privilege escalation logic is present in core/facet.py, core/project_resource.py, or etc/atlas/config.yaml.
- README.md: No mention of reauthentication on role change or privilege escalation.
- No static evidence of reauthentication enforcement in provided files.
- Requirement: NOT SATISFIED — No static enforcement of reauthentication on role/privilege change.

Remediation:
Configure the application to require reauthentication before user privilege is escalated and user roles are changed.

---

### 134. APSC-DV-001530 | SV-222521r985974

- Rule ID: SV-222521r985974
- Severity: medium
- Rule Title: The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires device reauthentication at defined intervals.
- No device authentication or reauthentication interval configuration is present in etc/atlas/config.yaml or any provided file.
- README.md: No mention of device authentication or reauthentication.
- No static evidence of device reauthentication enforcement.
- Requirement: NOT SATISFIED — No static enforcement or configuration for device reauthentication.

Remediation:
Configure the application to require reauthentication periodically.

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires unique identification and authentication of organizational users.
- etc/atlas/config.yaml: OAuth2/OIDC configuration under plugins.security (issuer_url, mcp_audience, client IDs).
- README.md: 'Run the server with dev authentication' and 'For production or when using an external IdP, set the environment variables before running python midas.py directly.'
- security/oauth_proxy.py: Implements OAuth2 proxy endpoints, but actual authentication enforcement logic is not included in provided files (security/middleware.py not present).
- No static evidence of unique user account enforcement or authentication checks in the provided code.
- Requirement: PARTIALLY SATISFIED — OAuth2/OIDC configuration is present, but enforcement and unique user mapping cannot be confirmed from static artifacts alone.

Remediation:
Configure the application to uniquely identify and authenticate users and user processes.

---

### 136. APSC-DV-001550 | SV-222523r960972

- Rule ID: SV-222523r960972
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires multifactor (Alt. Token) authentication for network access to privileged accounts.
- etc/atlas/config.yaml: OAuth2/OIDC configuration present, but no mention of Alt. Token or multifactor enforcement.
- README.md: No reference to Alt. Token or multifactor authentication for privileged accounts.
- security/oauth_proxy.py: Implements OAuth2 proxy, but no static enforcement of multifactor or Alt. Token authentication.
- Requirement: NOT SATISFIED — No static evidence of Alt. Token or multifactor authentication enforcement for privileged accounts.

Remediation:
Configure the application to use an Alt. Token when providing network access to privileged application accounts.

---

### 137. APSC-DV-001560 | SV-222524r961494

- Rule ID: SV-222524r961494
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires acceptance of PIV credentials (CAC authentication).
- etc/atlas/config.yaml: OAuth2/OIDC configuration present, but no mention of CAC/PIV or PKI authentication.
- README.md: No reference to CAC, PIV, or certificate-based authentication.
- security/oauth_proxy.py: OAuth2 proxy logic present, but no static evidence of CAC/PIV credential acceptance.
- Requirement: NOT SATISFIED — No static evidence of CAC/PIV credential acceptance.

Remediation:
Configure the application to require CAC authentication.

---

### 138. APSC-DV-001570 | SV-222525r961497

- Rule ID: SV-222525r961497
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires electronic verification of PIV credentials (CAC authentication).
- etc/atlas/config.yaml: OAuth2/OIDC configuration present, but no mention of CAC/PIV or certificate verification.
- README.md: No reference to CAC, PIV, or certificate-based authentication.
- security/oauth_proxy.py: OAuth2 proxy logic present, but no static evidence of CAC/PIV credential verification.
- Requirement: NOT SATISFIED — No static evidence of CAC/PIV credential verification.

Remediation:
Configure the application to require CAC authentication.

---

### 139. APSC-DV-001580 | SV-222526r960975

- Rule ID: SV-222526r960975
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires multifactor (CAC/Alt. Token) authentication for network access to non-privileged accounts.
- etc/atlas/config.yaml: OAuth2/OIDC configuration present, but no mention of CAC, Alt. Token, or multifactor enforcement for non-privileged accounts.
- README.md: No reference to CAC, Alt. Token, or multifactor authentication for non-privileged accounts.
- security/oauth_proxy.py: OAuth2 proxy logic present, but no static enforcement of multifactor authentication for non-privileged accounts.
- Requirement: NOT SATISFIED — No static evidence of multifactor authentication enforcement for non-privileged accounts.

Remediation:
Configure the application to require CAC or Alt. Token authentication for non-privileged network access to non-privileged accounts.

---

### 140. APSC-DV-001590 | SV-222527r1015693

- Rule ID: SV-222527r1015693
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires multifactor (Alt. Token) authentication for local access to privileged accounts.
- etc/atlas/config.yaml: OAuth2/OIDC configuration present, but no mention of Alt. Token or multifactor enforcement for local privileged access.
- README.md: No reference to Alt. Token or multifactor authentication for local privileged accounts.
- security/oauth_proxy.py: OAuth2 proxy logic present, but no static enforcement of multifactor authentication for local privileged accounts.
- Requirement: NOT SATISFIED — No static evidence of multifactor authentication enforcement for local privileged accounts.

Remediation:
Configure the application to only use Alt. Tokens when locally accessing privileged application accounts.

---

### 141. APSC-DV-001600 | SV-222528r1015694

- Rule ID: SV-222528r1015694
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires multifactor authentication (e.g., CAC, Alt. Token) for local access to nonprivileged accounts.
- File: etc/atlas/config.yaml — plugins.security.issuer_url: "http://localhost:8082/realms/midas-mcp"
- File: etc/keycloak/dev-realm.json — clients[].protocol: "openid-connect" (OIDC enabled)
- File: etc/keycloak/dev-realm.json — users[].credentials[].type: "password" (password authentication enabled)
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication for all endpoints except /.well-known/*, /authorize, /token, /health, /register, OPTIONS
- No evidence of CAC, PIV, or certificate-based authentication enforcement for nonprivileged accounts in any configuration or code artifact provided
- Requirement: PARTIALLY SATISFIED — OIDC token-based authentication is enforced, but there is no evidence of multifactor (CAC/Alt. Token) authentication for nonprivileged accounts

Remediation:
Configure the application to require CAC or Alt. Token authentication for nonprivileged network access.

---

### 142. APSC-DV-001610 | SV-222529r1015695

- Rule ID: SV-222529r1015695
- Severity: medium
- Rule Title: The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires individual authentication before group authenticator use; not applicable if no group/shared accounts exist.
- File: etc/keycloak/dev-realm.json — users[]: only individual user accounts defined ("dev-user", "dev-admin"); no group/shared accounts present
- File: README.md — No mention of group/shared accounts or group authenticators
- Requirement: NOT APPLICABLE — Application does not use group or shared accounts

Remediation:
Design and configure the application to individually authenticate group account members prior to allowing access.

---

### 143. APSC-DV-001620 | SV-222530r960993

- Rule ID: SV-222530r960993
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires replay-resistant authentication (e.g., TLS 1.2+, Kerberos, IPSEC, SSH) for privileged accounts.
- File: etc/atlas/config.yaml — plugins.security.issuer_url: "http://localhost:8082/realms/midas-mcp" (OIDC issuer)
- File: etc/keycloak/dev-realm.json — defaultSignatureAlgorithm: "RS256" (JWT tokens signed)
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication
- File: pyproject.toml — dependency: "PyJWT[crypto]>=2.8.0" (JWT signature verification)
- No evidence of TLS configuration (minimum version, enforcement) in application code or configuration
- No evidence of Kerberos, IPSEC, SSH, or mutual authentication for privileged accounts
- Requirement: PARTIALLY SATISFIED — JWT tokens are signed (replay-resistant at token level), but no evidence of TLS 1.2+ enforcement or additional replay-resistant mechanisms for privileged account authentication

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating privileged accounts.

---

### 144. APSC-DV-001630 | SV-222531r1015696

- Rule ID: SV-222531r1015696
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires replay-resistant authentication (e.g., TLS 1.2+, Kerberos, IPSEC, SSH) for nonprivileged accounts.
- File: etc/atlas/config.yaml — plugins.security.issuer_url: "http://localhost:8082/realms/midas-mcp"
- File: etc/keycloak/dev-realm.json — defaultSignatureAlgorithm: "RS256"
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication
- File: pyproject.toml — dependency: "PyJWT[crypto]>=2.8.0"
- No evidence of TLS configuration (minimum version, enforcement) in application code or configuration
- No evidence of Kerberos, IPSEC, SSH, or mutual authentication for nonprivileged accounts
- Requirement: PARTIALLY SATISFIED — JWT tokens are signed (replay-resistant at token level), but no evidence of TLS 1.2+ enforcement or additional replay-resistant mechanisms for nonprivileged account authentication

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating nonprivileged accounts.

---

### 145. APSC-DV-001640 | SV-222532r960999

- Rule ID: SV-222532r960999
- Severity: medium
- Rule Title: The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires mutual authentication (e.g., client certificate) when endpoint device non-repudiation is required.
- File: etc/atlas/config.yaml — No configuration for mutual TLS or client certificate authentication
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication only; no client certificate handling
- File: README.md — No mention of mutual authentication or client certificate requirements
- Requirement: NOT SATISFIED — No evidence of mutual authentication (client certificate) support or enforcement

Remediation:
Configure the application to utilize mutual authentication when specified by data protection requirements.

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires authentication of all network-connected endpoint devices before establishing any connection; Basic Auth is not allowed.
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication for all endpoints except /.well-known/*, /authorize, /token, /health, /register, OPTIONS
- File: etc/atlas/config.yaml — No evidence of device authentication or device identifier management
- File: README.md — No mention of device authentication
- Requirement: PARTIALLY SATISFIED — Bearer token authentication is enforced for users, but no evidence of device authentication mechanism for endpoint devices

Remediation:
Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires mutual SSL/TLS authentication for SOA applications handling non-releasable data.
- File: etc/atlas/config.yaml — No configuration for mutual SSL/TLS or client certificate authentication
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication only; no client certificate handling
- File: README.md — No mention of mutual SSL/TLS authentication
- Requirement: NOT SATISFIED — No evidence of mutual SSL/TLS authentication for endpoint devices

Remediation:
Configure the application to utilize mutual authentication when the application is processing non-releasable data.

---

### 148. APSC-DV-001670 | SV-222535r1015697

- Rule ID: SV-222535r1015697
- Severity: medium
- Rule Title: The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires device identifiers to be disabled after 35 days of inactivity unless cryptographic certificate is used.
- File: etc/atlas/config.yaml — No configuration for device authentication or device identifier management
- File: README.md — No mention of device authentication or device accounts
- Application is not designed to authenticate devices (no device ID/account management present)
- Requirement: NOT APPLICABLE — Application does not authenticate devices

Remediation:
Configure the application to disable device accounts after 35 days of inactivity or to utilize DOD PKI certificates that provide an expiration date.

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of a minimum 15-character password length.
- File: etc/keycloak/dev-realm.json — users[].credentials[].value: "dev-password", "dev-admin-password" (example passwords <15 characters)
- File: etc/keycloak/dev-realm.json — No password policy or minimum length setting present
- File: etc/atlas/config.yaml — No password policy configuration
- Requirement: NOT SATISFIED — No evidence of minimum password length enforcement

Remediation:
Configure the application to require 15 characters in the password.

---

### 150. APSC-DV-001690 | SV-222537r1015699

- Rule ID: SV-222537r1015699
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one uppercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires password complexity enforcement: at least one uppercase character.
- File: etc/keycloak/dev-realm.json — users[].credentials[].value: "dev-password", "dev-admin-password" (no uppercase character)
- File: etc/keycloak/dev-realm.json — No password policy or complexity setting present
- File: etc/atlas/config.yaml — No password policy configuration
- Requirement: NOT SATISFIED — No evidence of uppercase character requirement in passwords

Remediation:
Configure the application to require at least one uppercase character in the password.

---

### 151. APSC-DV-001700 | SV-222538r1015700

- Rule ID: SV-222538r1015700
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one lowercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires password complexity enforcement: at least one lowercase character.
- File: etc/keycloak/dev-realm.json — users[].credentials[].value: "dev-password", "dev-admin-password" (all lowercase)
- File: etc/keycloak/dev-realm.json — No password policy or complexity setting present
- File: etc/atlas/config.yaml — No password policy configuration
- Requirement: PARTIALLY SATISFIED — Example passwords contain lowercase, but no enforcement mechanism present

Remediation:
Configure the application to require at least one lowercase character in the password.

---

### 152. APSC-DV-001710 | SV-222539r1015701

- Rule ID: SV-222539r1015701
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one numeric character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires password complexity enforcement: at least one numeric character.
- File: etc/keycloak/dev-realm.json — users[].credentials[].value: "dev-password", "dev-admin-password" (no numeric character)
- File: etc/keycloak/dev-realm.json — No password policy or complexity setting present
- File: etc/atlas/config.yaml — No password policy configuration
- Requirement: NOT SATISFIED — No evidence of numeric character requirement in passwords

Remediation:
Configure the application to require at least one numeric character in the password.

---

### 153. APSC-DV-001720 | SV-222540r1015702

- Rule ID: SV-222540r1015702
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one special character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires password complexity enforcement: at least one special character.
- File: etc/keycloak/dev-realm.json — users[].credentials[].value: "dev-password", "dev-admin-password" (no special character)
- File: etc/keycloak/dev-realm.json — No password policy or complexity setting present
- File: etc/atlas/config.yaml — No password policy configuration
- Requirement: NOT SATISFIED — No evidence of special character requirement in passwords

Remediation:
Configure the application to require at least one special character in the password.

---

### 154. APSC-DV-001730 | SV-222541r1043189

- Rule ID: SV-222541r1043189
- Severity: medium
- Rule Title: The application must require the change of at least eight of the total number of characters when passwords are changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires at least eight characters to be changed when passwords are changed.
- File: etc/keycloak/dev-realm.json — No password change policy or enforcement mechanism present
- File: etc/atlas/config.yaml — No password change policy configuration
- Requirement: NOT SATISFIED — No evidence of password change character difference enforcement

Remediation:
Configure the application to require the change of at least eight characters in the password when passwords are changed.

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires only cryptographic representations of passwords to be stored (no plaintext, no MD5).
- File: etc/keycloak/dev-realm.json — users[].credentials[].type: "password", value: "dev-password" (plaintext password in realm import file)
- File: etc/keycloak/dev-realm.json — No evidence of password hashing algorithm or salt configuration
- File: etc/atlas/config.yaml — No password storage configuration
- Requirement: NOT SATISFIED — Passwords are present in plaintext in configuration; no evidence of cryptographic storage

Remediation:
Use strong cryptographic hash functions when creating password hash values.

Utilize random salt values when creating the password hash.

Ensure strong access control permissions on data files containing authentication data.

---

### 156. APSC-DV-001750 | SV-222543r961029

- Rule ID: SV-222543r961029
- Severity: high
- Rule Title: The application must transmit only cryptographically-protected passwords.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires passwords to be transmitted only over cryptographically protected channels (e.g., TLS/SSL).
- File: etc/keycloak/dev-realm.json — OIDC protocol enabled, but no evidence of HTTPS/TLS enforcement
- File: etc/atlas/config.yaml — issuer_url uses "http://" (not HTTPS)
- File: README.md — dev instructions use "http://localhost:8000" (no HTTPS)
- Requirement: NOT SATISFIED — No evidence of TLS/SSL enforcement for password transmission

Remediation:
Configure the application to encrypt passwords when they are being transmitted.

---

### 157. APSC-DV-001760 | SV-222544r1015705

- Rule ID: SV-222544r1015705
- Severity: medium
- Rule Title: The application must enforce 24 hours/1 day as the minimum password lifetime.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a minimum password lifetime of 24 hours (cannot change password more than once per day).
- File: etc/keycloak/dev-realm.json — No password lifetime or change frequency policy present
- File: etc/atlas/config.yaml — No password lifetime configuration
- Requirement: NOT SATISFIED — No evidence of minimum password lifetime enforcement

Remediation:
Configure the application to have a minimum password lifetime of 24 hours.

---

### 158. APSC-DV-001770 | SV-222545r1043190

- Rule ID: SV-222545r1043190
- Severity: medium
- Rule Title: The application must enforce a 60-day maximum password lifetime restriction.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a maximum password lifetime of 60 days (passwords must expire after 60 days).
- File: etc/keycloak/dev-realm.json — No password expiration or maximum lifetime policy present
- File: etc/atlas/config.yaml — No password expiration configuration
- Requirement: NOT SATISFIED — No evidence of maximum password lifetime enforcement

Remediation:
Configure the application to have a maximum password lifetime of 60 days.

---

### 159. APSC-DV-001780 | SV-222546r1015267

- Rule ID: SV-222546r1015267
- Severity: medium
- Rule Title: The application must prohibit password reuse for a minimum of five generations.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires prohibition of password reuse for a minimum of five generations.
- File: etc/keycloak/dev-realm.json — No password history or reuse policy present
- File: etc/atlas/config.yaml — No password reuse configuration
- Requirement: NOT SATISFIED — No evidence of password reuse prohibition

Remediation:
Configure the application to prohibit password reuse for up to five passwords.

---

### 160. APSC-DV-001790 | SV-222547r985976

- Rule ID: SV-222547r985976
- Severity: medium
- Rule Title: The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires support for temporary passwords with forced change on first use.
- File: etc/keycloak/dev-realm.json — users[].credentials[].temporary: false (no temporary password in use)
- File: etc/keycloak/dev-realm.json — No evidence of forced password change on first login
- File: etc/atlas/config.yaml — No configuration for temporary password or forced change
- Requirement: NOT SATISFIED — No evidence of temporary password support with forced change on first use

Remediation:
Configure the application to specify when a password is temporary and change the temporary password on the first use.

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not implement user password management or password change/reset functionality in any provided code or configuration.
- File: README.md — No mention of user password change/reset features; authentication is described as OIDC/OAuth2-based (see 'Run the server with dev authentication', 'For production or when using an external IdP', and 'security' plugin configuration).
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (issuer_url, mcp_audience, introspection_client_id), not via application-managed passwords.
- File: pyproject.toml — No dependencies for password management or user account modules.
- No files implement password change/reset endpoints, forms, or logic.
- Requirement: NOT APPLICABLE — The application does not utilize application-managed passwords; authentication is delegated to external OIDC/OAuth2 providers.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application supports user and project resource management, but there is no static evidence that user sessions are terminated upon account deletion.
- File: README.md — Describes OIDC/OAuth2 authentication and session management via external IdP; no mention of session termination on account deletion.
- File: etc/atlas/config.yaml — No configuration for session termination on user deletion; security section only configures OIDC endpoints.
- File: core/project_resource.py — Implements project resource and project management, but not user account/session management.
- File: security/oauth_proxy.py — Implements OAuth2 proxy endpoints, but does not handle user account deletion or session invalidation.
- No files implement user account deletion logic or session invalidation hooks.
- Requirement: PARTIALLY SATISFIED — Application uses external IdP for authentication, but there is no static evidence that user sessions are forcibly terminated upon account deletion. Dynamic testing or IdP configuration review is required.

Remediation:
Configure the application to terminate existing sessions of users whose accounts are deleted.

---

### 163. APSC-DV-001810 | SV-222550r961038

- Rule ID: SV-222550r961038
- Severity: high
- Rule Title: The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application supports OIDC/OAuth2 authentication, which typically includes certificate path validation when PKI is used, but there is no static evidence of explicit certificate path construction or validation in the provided code/configuration.
- File: etc/atlas/config.yaml — OIDC/OAuth2 issuer_url and endpoints are configured, but no explicit certificate validation logic is present.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints, but does not implement certificate validation logic; relies on upstream IdP and HTTP client libraries.
- File: pyproject.toml — No explicit certificate validation libraries are listed; relies on httpx and PyJWT, which use system trust stores by default.
- Requirement: PARTIALLY SATISFIED — Application delegates authentication to OIDC/OAuth2 providers, which may perform certificate path validation, but there is no static evidence that the application itself constructs or validates certificate paths. Confirmation requires runtime inspection or upstream IdP configuration review.

Remediation:
Design the application to construct a certification path to an accepted trust anchor when using PKI-based authentication.

---

### 164. APSC-DV-001820 | SV-222551r961041

- Rule ID: SV-222551r961041
- Severity: high
- Rule Title: The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application may use private keys for OIDC/OAuth2 token signing or GitHub App authentication, but there is no static evidence of enforced access controls on private key storage.
- File: etc/atlas/config.yaml — GitHub App authentication references 'private_key_path: /midas/customer_midas_github_app_key.pem' for github_issue_fetcher, but no file permissions or access controls are specified.
- File: security/oauth_proxy.py — No private key handling; proxies OAuth2 endpoints only.
- File: plugins/github_issue_fetcher.py — Reads private key from file for GitHub App authentication, but does not enforce or check file permissions.
- No code implements access control checks or restricts access to private key files.
- Requirement: PARTIALLY SATISFIED — Private keys are referenced for GitHub App authentication, but there is no static evidence of enforced access controls. File system permissions and deployment configuration must be reviewed.

Remediation:
Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses OIDC/OAuth2 for authentication, which can map identities to users/groups, but there is no static evidence of explicit mapping of PKI certificate data to user or group accounts in the application code.
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration (issuer_url, mcp_audience) is present, but no mapping logic for PKI certificates.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints; does not process or map certificate data.
- No code implements mapping of certificate subject/fields to user or group accounts.
- Requirement: PARTIALLY SATISFIED — Application relies on external IdP for authentication, but there is no static evidence of mapping PKI certificate data to user/group accounts within the application. Confirmation requires IdP configuration review or runtime inspection.

Remediation:
Configure the application to map certificate information to individual users or group accounts or create a process for automatically determining the individual user or group based on certificate information provided in the logs.

---

### 166. APSC-DV-001840 | SV-222553r1015707

- Rule ID: SV-222553r1015707
- Severity: medium
- Rule Title: The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application implements a local cache of revocation data (CRL) for PKI-based authentication.
- File: etc/atlas/config.yaml — No configuration for CRL, OCSP, or revocation data caching.
- File: security/oauth_proxy.py — No logic for certificate revocation checking or CRL caching; proxies OAuth2 endpoints only.
- No code implements CRL import, caching, or fallback to local revocation data.
- Requirement: NOT SATISFIED — No evidence of CRL caching or revocation data support for PKI-based authentication. If PKI is required, this is a finding.

Remediation:
Implement a CRL import process and configure the application to check the CRL if OCSP is not available.

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not implement any password or PIN entry UI or display logic.
- File: README.md — Authentication is handled via OIDC/OAuth2; no mention of password/PIN entry or display.
- File: etc/atlas/config.yaml — No password/PIN UI configuration; authentication is delegated to external IdP.
- No code implements password/PIN input forms or display logic.
- Requirement: NOT APPLICABLE — The application does not display or process passwords/PINs in any UI; authentication is handled externally.

Remediation:
Configure the application to obfuscate passwords and PINs when they are being entered so they cannot be read.

Design the application so obfuscated passwords cannot be copied and then pasted as clear text.

---

### 168. APSC-DV-001860 | SV-222555r961050

- Rule ID: SV-222555r961050
- Severity: high
- Rule Title: The application must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses cryptographic modules for OIDC/OAuth2 (PyJWT[crypto], cryptography) and GitHub App authentication, but there is no static evidence that only FIPS-approved modules are used or enforced.
- File: pyproject.toml — Dependencies include 'PyJWT[crypto]>=2.8.0', 'cryptography>=46.0.7', 'onnxruntime', 'sqlite-vec', etc., but no explicit FIPS enforcement or module validation.
- File: etc/atlas/config.yaml — No configuration for FIPS mode or cryptographic module selection.
- No code enforces or checks FIPS-approved module usage.
- Requirement: PARTIALLY SATISFIED — Application uses standard cryptographic libraries, but FIPS compliance is not statically enforced or documented. Confirmation requires runtime environment inspection and library configuration review.

Remediation:
Use FIPS-approved cryptographic modules.

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application uniquely identifies and authenticates non-organizational users.
- File: etc/atlas/config.yaml — OIDC/OAuth2 authentication is configured, but user base management and non-organizational user handling are not described.
- File: README.md — No mention of non-organizational user support or unique identification.
- No code implements user account management or unique identifier assignment for non-organizational users.
- Requirement: PARTIALLY SATISFIED — Application uses external IdP for authentication, but unique identification of non-organizational users is not statically verifiable. Requires review of IdP configuration and user provisioning.

Remediation:
Configure the application to identify and authenticate all non-organizational users.

---

### 170. APSC-DV-001880 | SV-222557r961527

- Rule ID: SV-222557r961527
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application accepts PIV credentials from other federal agencies.
- File: etc/atlas/config.yaml — OIDC/OAuth2 issuer_url is set to a local or configurable value; no explicit mention of PIV or cross-agency credential acceptance.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints; does not implement PIV-specific logic.
- No code or configuration references PIV, FIPS 201, or cross-agency credential support.
- Requirement: NOT SATISFIED — No evidence that PIV credentials from other agencies are accepted. Requires IdP and deployment configuration review.

Remediation:
Configure the application to accept PIV credentials when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 171. APSC-DV-001890 | SV-222558r961530

- Rule ID: SV-222558r961530
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application electronically verifies PIV credentials from other federal agencies.
- File: etc/atlas/config.yaml — No configuration for PIV verification or cross-agency credential validation.
- File: security/oauth_proxy.py — No logic for PIV credential verification; proxies OAuth2 endpoints only.
- No code or configuration references PIV verification mechanisms.
- Requirement: NOT SATISFIED — No evidence of electronic verification of PIV credentials from other agencies. Requires IdP and deployment configuration review.

Remediation:
Configure the application to verify the PIV credentials presented when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 172. APSC-DV-001900 | SV-222559r1015708

- Rule ID: SV-222559r1015708
- Severity: medium
- Rule Title: The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application accepts FICAM-approved third-party credentials.
- File: etc/atlas/config.yaml — OIDC/OAuth2 issuer_url is configurable, but no explicit mention of FICAM-approved credential acceptance.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints; does not implement FICAM-specific logic.
- No code or configuration references FICAM or third-party credential validation.
- Requirement: NOT SATISFIED — No evidence that FICAM-approved third-party credentials are accepted. Requires IdP and deployment configuration review.

Remediation:
Configure applications intended to be accessible to nonfederal government agencies to use FICAM-approved third-party credentials.

---

### 173. APSC-DV-001910 | SV-222560r1067800

- Rule ID: SV-222560r1067800
- Severity: medium
- Rule Title: The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application conforms to FICAM-issued profiles (e.g., SAML, OpenID).
- File: etc/atlas/config.yaml — OIDC/OAuth2 is used, which may support OpenID Connect, but no explicit FICAM profile conformance is documented.
- File: security/oauth_proxy.py — Implements OAuth2 proxy endpoints, but does not enforce or document FICAM profile conformance.
- No code or configuration references FICAM profiles or technical conformance.
- Requirement: PARTIALLY SATISFIED — Application uses OIDC/OAuth2, which may be compatible with FICAM profiles, but explicit conformance is not statically documented. Requires IdP and deployment configuration review.

Remediation:
Configure the application to conform to FICAM-issued technical profiles when providing services that rely on external (federal government) identity providers.

---

### 174. APSC-DV-001930 | SV-222561r961548

- Rule ID: SV-222561r961548
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to log when application maintenance functionality is executed remotely.

---

### 175. APSC-DV-001940 | SV-222562r961554

- Rule ID: SV-222562r961554
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 176. APSC-DV-001950 | SV-222563r961557

- Rule ID: SV-222563r961557
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 177. APSC-DV-001960 | SV-222564r961560

- Rule ID: SV-222564r961560
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to verify termination of remote maintenance sessions.

---

### 178. APSC-DV-001970 | SV-222565r961062

- Rule ID: SV-222565r961062
- Severity: medium
- Rule Title: The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to use strong authentication (CAC) when accessing the application for maintenance purposes.

---

### 179. APSC-DV-001980 | SV-222566r985978

- Rule ID: SV-222566r985978
- Severity: medium
- Rule Title: The application must terminate all sessions and network connections when nonlocal maintenance is completed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no evidence that the application provides non-local maintenance or diagnostic sessions.
- File: README.md — No mention of remote maintenance, admin, or diagnostic session features.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic access.
- File: core/project_resource.py — Manages project resources, not maintenance sessions.
- No code implements remote maintenance session functionality.
- Requirement: NOT APPLICABLE — The application does not provide non-local maintenance or diagnostic sessions.

Remediation:
Configure the application to expire idle user sessions after 10 minutes of inactivity for admin users and after 15 minutes of inactivity for regular users.

---

### 180. APSC-DV-001995 | SV-222567r961863

- Rule ID: SV-222567r961863
- Severity: medium
- Rule Title: The application must not be vulnerable to race conditions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- There is no static evidence that the application has been tested and is not susceptible to race conditions.
- File: README.md — Testing section describes baseline and property-based testing, but does not mention race condition analysis or results.
- File: pyproject.toml — No dependencies for concurrency or race condition analysis tools.
- No code or documentation references race condition testing or mitigation.
- Requirement: NOT SATISFIED — No evidence of race condition analysis or test results. Requires code review/test results for confirmation.

Remediation:
Be aware of potential timing issues related to application programming calls when designing and building the application.

Validate that variable values do not change while a switch event is occurring.

---

### 181. APSC-DV-002000 | SV-222568r961068

- Rule ID: SV-222568r961068
- Severity: medium
- Rule Title: The application must terminate all network connections associated with a communications session at the end of the session.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that all network connections associated with a communications session are terminated at the end of the session.
- File: security/middleware.py — BearerMiddleware enforces authentication for all endpoints except a small allowlist, but there is no explicit evidence of session or connection termination logic in the provided code.
- File: README.md — No mention of explicit session termination or connection teardown in the architecture or security sections.
- File: etc/atlas/config.yaml — No configuration options for session timeout or connection termination.
- Requirement: PARTIALLY SATISFIED — Authentication is enforced for all requests, but there is no static evidence that network connections are explicitly terminated at session end. Further review of server implementation and runtime behavior is required.

Remediation:
Configure or design the application to terminate application network sessions at the end of the session.

---

### 182. APSC-DV-002020 | SV-222570r1117181

- Rule ID: SV-222570r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when signing application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires FIPS-validated cryptographic modules for signing application components and prohibits SHA1/MD5.
- File: pyproject.toml — cryptography>=46.0.7 and PyJWT[crypto]>=2.8.0 are included, both of which can be FIPS-compliant if the underlying OpenSSL is FIPS-enabled, but there is no evidence of code signing or explicit FIPS mode enforcement.
- File: etc/keycloak/dev-realm.json — defaultSignatureAlgorithm: "RS256" (FIPS-approved), but this is for OIDC tokens, not application component signing.
- File: README.md — No mention of code signing for distributable components.
- Requirement: PARTIALLY SATISFIED — FIPS-eligible libraries are present, but there is no evidence of application component signing or explicit FIPS mode enforcement. Confirmation of signing process and FIPS mode at runtime is required.

Remediation:
Utilize FIPS-validated algorithms when signing application components.

---

### 183. APSC-DV-002030 | SV-222571r1117181

- Rule ID: SV-222571r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires FIPS-validated cryptographic modules for generating cryptographic hashes and prohibits SHA1/MD5.
- File: pyproject.toml — cryptography>=46.0.7 is present, which can be FIPS-compliant if the system OpenSSL is FIPS-enabled, but there is no evidence of explicit hash generation code or FIPS mode enforcement.
- File: README.md, etc/atlas/config.yaml — No mention of hash algorithm selection or FIPS enforcement for hashing.
- Requirement: PARTIALLY SATISFIED — FIPS-eligible libraries are present, but there is no evidence of explicit hash generation or FIPS mode enforcement. Cannot confirm hash algorithm selection or FIPS validation from static code alone.

Remediation:
Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.

---

### 184. APSC-DV-002040 | SV-222572r1117181

- Rule ID: SV-222572r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires FIPS-validated cryptographic modules for protecting unclassified information requiring cryptographic protection.
- File: pyproject.toml — cryptography>=46.0.7 and PyJWT[crypto]>=2.8.0 are present, which can be FIPS-compliant if the system OpenSSL is FIPS-enabled, but there is no evidence of explicit encryption or FIPS mode enforcement for data at rest or in transit.
- File: etc/atlas/config.yaml — No configuration for FIPS mode or encryption modules for data protection.
- Requirement: PARTIALLY SATISFIED — FIPS-eligible libraries are present, but there is no evidence of FIPS mode enforcement or explicit cryptographic protection of unclassified data. Cannot confirm FIPS validation from static code alone.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 185. APSC-DV-002050 | SV-222573r1117181

- Rule ID: SV-222573r1117181
- Severity: medium
- Rule Title: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application makes SAML assertions and generates SessionIndex in SAML AuthnStatement.
- File: README.md, pyproject.toml, etc/atlas/config.yaml — No mention of SAML, SAML assertions, or SessionIndex generation.
- File: security/middleware.py — Only OIDC/OAuth2 flows are referenced; no SAML logic present.
- Requirement: NOT APPLICABLE — The application does not implement SAML assertions or SessionIndex generation.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 186. APSC-DV-002150 | SV-222574r1117171

- Rule ID: SV-222574r1117171
- Severity: medium
- Rule Title: The application user interface must be either physically or logically separated from data storage and management interfaces.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires logical or physical separation between user interface and data storage/management interfaces.
- File: README.md — The architecture section describes a three-layer design (External Interface Layer, Intelligence Layer, Analysis Foundation), but does not explicitly state that user and management interfaces are separated.
- File: etc/atlas/config.yaml — No configuration for separate management interfaces or network separation.
- Requirement: PARTIALLY SATISFIED — The architecture suggests some layering, but there is no explicit evidence of interface separation for user and management traffic. Further architectural documentation or network configuration is needed.

Remediation:
Configure the application so user interface to the application and management interface to the application is separated.

---

### 187. APSC-DV-002210 | SV-222575r1043178

- Rule ID: SV-222575r1043178
- Severity: medium
- Rule Title: The application must set the HTTPOnly flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the HTTPOnly flag to be set on session cookies.
- File: security/middleware.py — Implements Bearer token authentication for all endpoints, but there is no evidence of session cookie creation or HTTPOnly flag setting in the provided code.
- File: README.md — No mention of session cookies or HTTPOnly flag.
- Requirement: PARTIALLY SATISFIED — The application appears to use token-based authentication rather than session cookies, but without explicit evidence of cookie handling, cannot confirm HTTPOnly flag usage or absence of cookies.

Remediation:
Configure the application to set the HTTPOnly flag on session cookies.

---

### 188. APSC-DV-002220 | SV-222576r1043178

- Rule ID: SV-222576r1043178
- Severity: medium
- Rule Title: The application must set the secure flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the secure flag to be set on session cookies.
- File: security/middleware.py — Implements Bearer token authentication, no evidence of session cookie creation or secure flag setting.
- File: README.md — No mention of session cookies or secure flag.
- Requirement: PARTIALLY SATISFIED — Application appears to use token-based authentication, but cannot confirm absence of cookies or secure flag usage from static code alone.

Remediation:
Configure the application to ensure the secure flag is set on session cookies.

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that session IDs are not exposed unencrypted over the network.
- File: security/middleware.py — All endpoints (except a small allowlist) require Bearer token authentication, but there is no explicit evidence of TLS enforcement or session ID protection in transit.
- File: README.md — No mention of TLS/SSL configuration or enforcement.
- File: etc/atlas/config.yaml — No configuration for HTTPS or TLS enforcement.
- Requirement: PARTIALLY SATISFIED — Authentication is enforced, but there is no static evidence of TLS/SSL enforcement to protect session IDs in transit.

Remediation:
Configure the application to protect session IDs from interception or from manipulation.

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires destruction of session ID values and/or cookies on logoff or browser close.
- File: security/middleware.py — Implements Bearer token authentication, but there is no evidence of session destruction or cookie invalidation logic.
- File: README.md — No mention of session destruction or logoff handling.
- Requirement: PARTIALLY SATISFIED — Application appears to use stateless token-based authentication, but cannot confirm session destruction or absence of cookies from static code alone.

Remediation:
Configure the application to destroy session ID cookies once the application session has terminated.

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires system-generated session identifiers that protect against session fixation.
- File: security/middleware.py — Bearer tokens are used for authentication, and tokens are verified for each request, but there is no explicit evidence of session ID generation logic or anti-fixation measures.
- File: etc/keycloak/dev-realm.json — OIDC tokens are issued by Keycloak with RS256, but session fixation protection is not explicitly documented.
- Requirement: PARTIALLY SATISFIED — Use of OIDC Bearer tokens suggests session fixation is mitigated, but cannot confirm session ID generation details from static code alone.

Remediation:
Design the application to generate new session IDs with unique values when authenticating user sessions.

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires validation of session identifiers.
- File: security/middleware.py — BearerMiddleware verifies tokens on every request using TokenAuthority, which validates signature, issuer, and expiry. Example: 'verified: VerifiedToken = await loop.run_in_executor(None, lambda: _authority.verify(raw_token))'.
- File: etc/keycloak/dev-realm.json — OIDC tokens are issued and validated, but session identifier validation is not explicitly documented for non-token sessions.
- Requirement: PARTIALLY SATISFIED — OIDC tokens are validated, but if any session cookies or other session mechanisms exist, their validation is not evidenced.

Remediation:
Configure the application to configure user session identifiers.

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that session IDs are not transmitted via URL embedding.
- File: security/middleware.py — No evidence of URL-based session ID transmission; authentication is via Bearer tokens in Authorization headers.
- File: README.md — No mention of URL-based session IDs.
- Requirement: PARTIALLY SATISFIED — No evidence of URL-embedded session IDs, but cannot confirm absence without reviewing all HTTP route handlers and frontend code.

Remediation:
Configure the application to transmit session ID information via cookies.

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that session IDs are not re-used or recycled after logout.
- File: security/middleware.py — Bearer tokens are validated per request, but there is no evidence of session ID lifecycle management or explicit invalidation on logout.
- File: etc/keycloak/dev-realm.json — OIDC tokens have accessTokenLifespan and ssoSessionMaxLifespan, but session ID re-use is not explicitly addressed.
- Requirement: PARTIALLY SATISFIED — OIDC tokens are short-lived, but cannot confirm session ID re-use/recycling policy from static code alone.

Remediation:
Design the application to not re-use session IDs.

---

### 195. APSC-DV-002290 | SV-222583r1051270

- Rule ID: SV-222583r1051270
- Severity: medium
- Rule Title: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires unique session identifiers generated using a FIPS 140-2/140-3 approved random number generator.
- File: security/middleware.py — No evidence of session ID generation logic; Bearer tokens are issued by the IdP (Keycloak), which uses RS256 signatures, but the RNG used for token generation is not evidenced.
- File: etc/keycloak/dev-realm.json — No explicit configuration for FIPS RNG or entropy source.
- Requirement: PARTIALLY SATISFIED — Session identifiers (tokens) are generated by Keycloak, but cannot confirm FIPS 140-2/3 RNG usage from static code alone.

Remediation:
Configure the application server to generate unique session identifiers and to use a FIPS 140-2/140-3 random number generator to generate the randomness of the session identifiers.

---

### 196. APSC-DV-002300 | SV-222584r961596

- Rule ID: SV-222584r961596
- Severity: medium
- Rule Title: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires use of DoD-approved certificate authorities for verification of protected sessions.
- File: security/middleware.py — Token verification is performed, but there is no evidence of certificate authority pinning or DoD CA enforcement.
- File: etc/atlas/config.yaml — No configuration for trusted CA roots or DoD CA enforcement.
- Requirement: PARTIALLY SATISFIED — Token signature verification is implemented, but cannot confirm CA trust store configuration or DoD CA enforcement from static code alone.

Remediation:
Configure the application to utilize DoD-approved PKI established CAs when verifying DoD-signed certificates.

---

### 197. APSC-DV-002310 | SV-222585r961122

- Rule ID: SV-222585r961122
- Severity: high
- Rule Title: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to fail to a secure state if initialization, shutdown, or aborts fail.
- File: README.md — No mention of secure failure handling or fail-closed logic.
- File: security/middleware.py — On authentication failure, requests are denied with 401/503, but there is no evidence of secure state handling for system initialization or shutdown failures.
- Requirement: PARTIALLY SATISFIED — Authentication failures are handled securely, but no evidence of secure state handling for broader system failures.

Remediation:
Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).

---

### 198. APSC-DV-002320 | SV-222586r961125

- Rule ID: SV-222586r961125
- Severity: medium
- Rule Title: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires preservation of information necessary to determine cause of failure and to return to operations with least disruption.
- File: README.md — The Testing section describes baseline and artifact logging for test failures, but there is no explicit mention of operational error logging or recovery information.
- File: Makefile — Test artifacts are saved for debugging, but this is for test failures, not operational failures.
- Requirement: PARTIALLY SATISFIED — Test failure information is preserved, but no evidence of operational failure logging or recovery data retention.

Remediation:
Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.

---

### 199. APSC-DV-002330 | SV-222587r1136910

- Rule ID: SV-222587r1136910
- Severity: medium
- Rule Title: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection of confidentiality and integrity of stored information when required by policy or data owner.
- File: etc/atlas/config.yaml — No configuration for encryption of stored data or integrity protection.
- File: pyproject.toml — cryptography and sqlite-vec are present, but no evidence of encryption at rest or integrity mechanisms for stored data.
- Requirement: PARTIALLY SATISFIED — Cryptographic libraries are present, but no evidence of data encryption or integrity protection for stored information.

Remediation:
Identify data elements that require protection. Document the data types and specify protection requirements and methods used.

---

### 200. APSC-DV-002340 | SV-222588r1067803

- Rule ID: SV-222588r1067803
- Severity: high
- Rule Title: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires approved cryptographic mechanisms to prevent unauthorized modification of information at rest.
- File: etc/atlas/config.yaml — No configuration for encryption or integrity protection of data at rest.
- File: pyproject.toml — cryptography and sqlite-vec are present, but no evidence of encryption or integrity mechanisms applied to stored data.
- Requirement: PARTIALLY SATISFIED — Cryptographic libraries are present, but no evidence of cryptographic protection for data at rest.

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

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that stored DoD information is protected with appropriate cryptography, commensurate with data classification and owner requirements.
- File: etc/atlas/config.yaml — No explicit configuration for encryption of stored application data (e.g., at-rest encryption, database encryption, or file encryption) is present in the provided configuration. The configuration covers AI personas, plugin settings, and pipeline definitions, but does not specify cryptographic storage for application data.
- File: pyproject.toml — No dependencies for cryptographic storage libraries (e.g., PyCryptodome, cryptography for at-rest encryption) are declared, only for JWT and TLS-related libraries (PyJWT[crypto], cryptography for token validation).
- File: README.md — No mention of at-rest encryption or storage encryption for application data. The documentation focuses on code analysis, AI, and MCP tools.
- Requirement: PARTIALLY SATISFIED — JWT and TLS cryptography are present for authentication and transmission, but there is no evidence of cryptographic protection for stored application data. Further evidence is needed to confirm at-rest encryption for DoD information.

Remediation:
Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt classified data using Type 1, Suite B, or other NSA-approved encryption solutions.

---

### 202. APSC-DV-002360 | SV-222590r961131

- Rule ID: SV-222590r961131
- Severity: medium
- Rule Title: The application must isolate security functions from non-security functions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires isolation of security functions from non-security functions, such as access controls and protection of security configuration.
- File: etc/atlas/config.yaml — Security configuration is isolated under the 'plugins.security' section, with explicit separation of OAuth2/OIDC settings, client IDs, and secret management. Comments specify that genuine secrets (e.g., INTROSPECTION_CLIENT_SECRET) are never stored in the YAML and must be loaded from environment variables.
- File: security/__init__.py — Security logic (token validation, issuer config, authority, and verification) is implemented in a dedicated security module, separate from application logic. The module imports and exposes only security-related classes and functions.
- File: core/facet.py — Facet plugin architecture enforces separation of concerns, with each plugin/facet responsible for its own domain. Security is not mixed with non-security logic in this base class.
- Requirement: SATISFIED — Security functions (authentication, token validation, configuration) are implemented in isolated modules and configuration sections, protecting them from unauthorized modification by non-security code.

Remediation:
Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.

---

### 203. APSC-DV-002370 | SV-222591r1117179

- Rule ID: SV-222591r1117179
- Severity: medium
- Rule Title: The application must maintain a separate execution domain for each executing process.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires separate execution domains for each executing process (e.g., process sandboxing).
- File: README.md — The application is described as a Python-based MCP server with plugin/facet architecture. There is no indication that the application runs untrusted code or user-supplied processes within the same process space. All facets and plugins are loaded as Python modules within a single server process.
- File: pyproject.toml — No dependencies or configuration for process sandboxing, containers, or OS-level isolation are present.
- Requirement: NOT APPLICABLE — The application is a monolithic Python server with no evidence of executing untrusted or user-supplied code in separate domains. Process isolation is not relevant to this architecture.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires prevention of unauthorized information transfer via shared system resources.
- File: etc/atlas/config.yaml — No explicit configuration for file sharing, shared memory, or resource boundaries is present. The configuration focuses on plugin and pipeline settings.
- File: README.md — No mention of file sharing protocols, shared system resources, or explicit boundaries between application data and other processes.
- File: core/project_resource.py — Project resources are managed via a registry, but there is no evidence of OS-level file permission enforcement or containerization to prevent unauthorized access to stored data.
- Requirement: PARTIALLY SATISFIED — No evidence of explicit sharing of system resources, but also no evidence of enforced boundaries (e.g., file permissions, containerization). Further review of runtime deployment and file access controls is needed.

Remediation:
Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.

---

### 205. APSC-DV-002390 | SV-222593r961620

- Rule ID: SV-222593r961620
- Severity: medium
- Rule Title: XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only to XML-based applications and requires mitigation of XML DoS attacks.
- File: README.md — No mention of XML processing, XML parsers, or XML-based APIs. Supported document types for conversion are PDF, DOCX, XLSX, CSV, Markdown, and plain text.
- File: pyproject.toml — No dependencies for XML parsing libraries (e.g., lxml, xml.etree, defusedxml) are present.
- File: etc/atlas/config.yaml — No configuration for XML processing or XML parser options.
- Requirement: NOT APPLICABLE — The application does not process XML and is not an XML-based application.

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

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to restrict the ability to launch DoS attacks against itself or other systems.
- File: security/oauth_proxy.py — Implements per-IP token-bucket rate limiting for the /token endpoint (20 tokens per 60 seconds), which mitigates DoS risk for authentication endpoints:
- Literal: 'rate_max_per_ip: int | None = _RATE_MAX_DEFAULT' (default 20)
- Literal: 'rate_window_secs: int = _RATE_WINDOW_DEFAULT' (default 60)
- Enforcement: 'if not self._check_rate_limit(ip): ... status_code=429, headers={"Retry-After": str(self._rate_window)}'
- File: README.md — No mention of global application-level throttling, request rate limiting for other endpoints, or anti-DoS protections outside of the OAuth2 proxy.
- File: etc/atlas/config.yaml — No configuration for global rate limiting, request throttling, or DoS mitigation for other application endpoints.
- Requirement: PARTIALLY SATISFIED — DoS mitigation is present for the /token endpoint, but there is no evidence of global application-level DoS protections or rate limiting for other endpoints. Further evidence is needed for comprehensive DoS controls.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies only if the application is designated as a high-availability system and requires redundancy mechanisms.
- File: README.md — No mention of high-availability designation, clustering, load balancers, or redundant deployment. The application is described as a single MCP server process.
- File: etc/atlas/config.yaml — No configuration for clustering, load balancing, or redundant systems.
- Requirement: NOT APPLICABLE — The application is not designated as a high-availability system and does not implement redundancy mechanisms.

Remediation:
Build the application to address issues that are found in a redundant environment and utilize redundancy mechanisms to provide high availability.

---

### 208. APSC-DV-002440 | SV-222596r961632

- Rule ID: SV-222596r961632
- Severity: high
- Rule Title: The application must protect the confidentiality and integrity of transmitted information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection of confidentiality and integrity of transmitted information (e.g., TLS, IPsec).
- File: etc/atlas/config.yaml — Security configuration specifies OIDC issuer URLs and audience, but does not explicitly require or enforce TLS for application endpoints:
- Literal: 'issuer_url: "http://localhost:8082/realms/midas-mcp"' (uses HTTP, not HTTPS)
- Literal: 'server_host: "0.0.0.0"', 'server_port: 8000' (no indication of TLS/SSL configuration)
- File: README.md — Application endpoints are documented as 'http://localhost:8000' and 'http://localhost:8080/realms/midas-mcp', with no mention of HTTPS or TLS enforcement.
- File: security/oauth_proxy.py — No evidence of TLS enforcement at the application layer; relies on deployment environment for HTTPS.
- Requirement: NOT SATISFIED — Application endpoints are configured for HTTP, not HTTPS. There is no evidence of TLS enforcement for transmitted information.

Remediation:
Configure all of the application systems to require TLS encryption in accordance with data protection requirements.

---

### 209. APSC-DV-002450 | SV-222597r1117180

- Rule ID: SV-222597r1117180
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires cryptographic mechanisms to prevent unauthorized disclosure and detect changes during transmission (e.g., TLS, message signing).
- File: etc/atlas/config.yaml — No explicit configuration for message signing, hashing, or TLS enforcement for application data transmission. OIDC and token validation are present, but do not cover all application data flows.
- File: README.md — Application endpoints are documented as 'http://localhost:8000' (no HTTPS). No mention of message-level encryption or integrity mechanisms for transmitted data.
- File: pyproject.toml — Dependencies include PyJWT[crypto] and cryptography for token validation, but no libraries for message signing or integrity checks on application data.
- Requirement: NOT SATISFIED — No evidence of cryptographic protections (TLS, message signing, or hashing) for all transmitted application data.

Remediation:
Configure the application to use cryptographic protections to prevent unauthorized disclosure of application data based upon the application architecture.

---

### 210. APSC-DV-002460 | SV-222598r961638

- Rule ID: SV-222598r961638
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires confidentiality and integrity of information during preparation for transmission (e.g., automatic HTTPS redirection, TLS by default).
- File: etc/atlas/config.yaml — Application endpoints are configured as 'http://localhost:8000' (no HTTPS). No configuration for TLS certificates, HTTPS redirection, or secure port usage.
- File: README.md — All documented endpoints use HTTP, not HTTPS. No mention of automatic redirection to secure ports or TLS configuration.
- File: security/oauth_proxy.py — No evidence of TLS enforcement or redirection logic in the OAuth2 proxy implementation.
- Requirement: NOT SATISFIED — Application does not enforce TLS or secure transmission during preparation for transmission.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 211. APSC-DV-002470 | SV-222599r961641

- Rule ID: SV-222599r961641
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during reception.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires confidentiality and integrity of information during reception (e.g., TLS for incoming connections).
- File: etc/atlas/config.yaml — Application listens on 'http://localhost:8000' (no HTTPS). No configuration for TLS certificates or secure port usage.
- File: README.md — All documented endpoints use HTTP, not HTTPS. No mention of TLS enforcement for incoming connections.
- File: security/oauth_proxy.py — No evidence of TLS enforcement for incoming requests.
- Requirement: NOT SATISFIED — Application does not enforce TLS for reception of information.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 212. APSC-DV-002480 | SV-222600r961638

- Rule ID: SV-222600r961638
- Severity: medium
- Rule Title: The application must not disclose unnecessary information to users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to avoid disclosing unnecessary information to users (e.g., technical details in error messages).
- File: README.md — No mention of custom error pages, error handling, or suppression of technical details in user-facing responses.
- File: security/oauth_proxy.py — Error responses for endpoints such as /token and /register return JSON with error codes and details (e.g., '{"error": "invalid_client_metadata", "error_description": ...}'), but do not include stack traces or internal server details. However, the error_description field may leak some implementation details depending on the error.
- File: core/facet.py — No evidence of user-facing error handling or custom error page configuration.
- Requirement: PARTIALLY SATISFIED — Error responses are structured and do not include stack traces, but there is no evidence of generic error pages or explicit suppression of technical details. Further review of all user-facing endpoints is needed.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies to web applications that store sensitive information in hidden fields (e.g., HTML forms).
- File: README.md — The application is a backend MCP server and does not render HTML forms or web pages with hidden fields. All interfaces are API-based (MCP, HTTP, OAuth2 proxy).
- File: core/facet.py — No evidence of HTML rendering or hidden field usage.
- Requirement: NOT APPLICABLE — The application does not use hidden fields in web forms.

Remediation:
Design and configure the application to not store sensitive information in hidden fields.  

Encrypt sensitive information stored in hidden fields using DoD-approved encryption and use server side session management techniques for user session management.

---

### 214. APSC-DV-002490 | SV-222602r961158

- Rule ID: SV-222602r961158
- Severity: high
- Rule Title: The application must protect from Cross-Site Scripting (XSS) vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection from Cross-Site Scripting (XSS) vulnerabilities.
- File: README.md — The application is described as an MCP server with plugin/facet architecture, not a traditional web application. There is no mention of user-supplied HTML content, web forms, or browser-based rendering.
- File: core/facet.py — No evidence of HTML rendering or user-supplied content being returned to clients.
- File: security/oauth_proxy.py — Returns JSON responses for all endpoints; no HTML content is generated.
- Requirement: PARTIALLY SATISFIED — The application does not render HTML or accept user-supplied content for browser rendering, reducing XSS risk. However, without a full review of all plugin/facet endpoints, complete absence of XSS vectors cannot be confirmed.

Remediation:
Verify user input is validated and encode or escape user input to prevent embedded script code from executing.

Develop your application using a web template system or a web application development framework that provides auto escaping features rather than building your own escape logic.

---

### 215. APSC-DV-002500 | SV-222603r961158

- Rule ID: SV-222603r961158
- Severity: medium
- Rule Title: The application must protect from Cross-Site Request Forgery (CSRF) vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection from Cross-Site Request Forgery (CSRF) vulnerabilities.
- File: README.md — The application is an API server (MCP, HTTP, OAuth2 proxy) and does not implement browser-based forms or session-based authentication. All authentication is via OAuth2/OIDC bearer tokens.
- File: security/oauth_proxy.py — All endpoints are protected by OAuth2 and require bearer tokens. No evidence of CSRF tokens or referrer checks, but also no evidence of session cookies or browser-based authentication flows.
- Requirement: PARTIALLY SATISFIED — The API design (token-based authentication, no session cookies) reduces CSRF risk, but explicit CSRF protections (tokens, referrer checks) are not present. Further review of all endpoints is needed to confirm absence of CSRF vectors.

Remediation:
Configure the application to use unpredictable challenge tokens and check the HTTP referrer to ensure the request was issued from the site itself.  Implement mitigating controls as required such as using web reputation services.

---

### 216. APSC-DV-002510 | SV-222604r961158

- Rule ID: SV-222604r961158
- Severity: high
- Rule Title: The application must protect from command injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection from command injection vulnerabilities.
- File: README.md — No mention of command execution, shell invocation, or user-supplied command processing.
- File: core/facet.py, core/project_resource.py — No evidence of direct use of os.system, subprocess, or shell command execution in the provided files.
- File: pyproject.toml — No dependencies for shell command execution libraries.
- Requirement: PARTIALLY SATISFIED — No evidence of command injection risk in the provided files, but a full static scan of all code paths (including plugins and ingestion sources) is required to confirm absence of command injection vulnerabilities.

Remediation:
Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.

---

### 217. APSC-DV-002520 | SV-222605r961158

- Rule ID: SV-222605r961158
- Severity: medium
- Rule Title: The application must protect from canonical representation vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection from canonical representation vulnerabilities (e.g., Unicode normalization, encoding issues).
- File: README.md — No mention of character set enforcement, Unicode normalization, or canonicalization of user input.
- File: core/facet.py, core/project_resource.py — No explicit handling of character encodings or normalization of input data.
- File: pyproject.toml — No dependencies for encoding libraries or Unicode normalization.
- Requirement: NOT SATISFIED — No evidence of canonicalization or encoding enforcement for user input. Further review is needed to confirm input is properly normalized before processing.

Remediation:
A suitable canonical form should be chosen and all user input canonicalized into that form before any authorization decisions are performed.

Security checks should be carried out after decoding is completed. Moreover, it is recommended to check that the encoding method chosen is a valid canonical encoding for the symbol it represents.

---

### 218. APSC-DV-002530 | SV-222606r961158

- Rule ID: SV-222606r961158
- Severity: medium
- Rule Title: The application must validate all input.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires validation of all input.
- File: core/facet.py — MCP tool specifications use Pydantic models for input validation (e.g., 'input_model: type[BaseModel] | None = None'), and ToolSpec.from_dict() converts parameter definitions to Pydantic models. However, not all tools may use input_model, and legacy tools may rely on untyped parameters.
- File: README.md — No explicit mention of input validation for all endpoints. The documentation describes MCP tool schemas but does not guarantee validation for every input path.
- File: etc/atlas/config.yaml — No configuration for global input validation or fuzzing tests.
- Requirement: PARTIALLY SATISFIED — Pydantic models are used for some input validation, but not all tools may enforce strict validation. Full coverage of input validation cannot be confirmed from static artifacts alone.

Remediation:
Design and configure the application to validate input prior to executing commands.

---

### 219. APSC-DV-002540 | SV-222607r961158

- Rule ID: SV-222607r961158
- Severity: high
- Rule Title: The application must not be vulnerable to SQL Injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires protection from SQL Injection vulnerabilities.
- File: README.md — No mention of direct SQL database usage or SQL queries in the application documentation.
- File: pyproject.toml — No dependencies for SQL database drivers (e.g., psycopg2, mysqlclient, sqlite3 is standard library). 'sqlite-vec' is present for vector store operations, but usage details are not shown.
- File: etc/atlas/config.yaml — Vectorstore and cortex facets use SQLite-based vector stores, but no evidence of direct SQL query construction or parameterization is present in the configuration.
- Requirement: PARTIALLY SATISFIED — No evidence of direct SQL query construction in the provided files, but full static analysis of all code paths (especially vectorstore usage) is required to confirm absence of SQL injection vulnerabilities.

Remediation:
Modify the application and remove SQL injection vulnerabilities.

---

### 220. APSC-DV-002550 | SV-222608r961158

- Rule ID: SV-222608r961158
- Severity: high
- Rule Title: The application must not be vulnerable to XML-oriented attacks.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control applies to applications that process XML and requires protection from XML-oriented attacks (e.g., XML injection, XPATH injection).
- File: README.md — No mention of XML processing, XML APIs, or XML-based web services. Supported document types are PDF, DOCX, XLSX, CSV, Markdown, and plain text.
- File: pyproject.toml — No dependencies for XML parsing libraries (e.g., lxml, xml.etree, defusedxml).
- File: etc/atlas/config.yaml — No configuration for XML processing or XML parser options.
- Requirement: NOT APPLICABLE — The application does not process XML and is not vulnerable to XML-oriented attacks.

Remediation:
Design the application to utilize components that are not vulnerable to XML attacks.

Patch the application components when vulnerabilities are discovered.

---

### 221. APSC-DV-002560 | SV-222609r961656

- Rule ID: SV-222609r961656
- Severity: high
- Rule Title: The application must not be subject to input handling vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires evidence that input handling vulnerabilities are mitigated, including documentation of input sanitization, vulnerability scan results, and remediation processes.
- File: pyproject.toml — dependency: "ruff>=0.14.0" (includes flake8-bandit 'S' rules for security linting, which covers some input validation issues)
- File: pyproject.toml — [tool.ruff.lint.select] includes "S" (flake8-bandit), "B" (bugbear), "C901" (cyclomatic complexity), and other security/quality rules
- File: pyproject.toml — [tool.ruff.lint.ignore] does NOT ignore S2XX (input validation) or S3XX (injection) rules
- File: README.md — Section: "Testing" describes baseline and property tests, but does not mention dynamic input fuzzing or runtime vulnerability scanning
- File: README.md — Section: "Best Practices" recommends writing baseline tests and using Clio for logging, but does not specify input validation SOPs
- File: README.md — Section: "Evaluation" describes code quality and security analysis via "eval_quality" tool, but does not provide scan results or remediation evidence
- No static evidence of input sanitization functions, decorators, or middleware enforcing input validation was found in the provided files
- No vulnerability scan results or risk acceptance documentation present in the static artifacts
- Requirement: PARTIALLY SATISFIED — Static analysis linting for security is present, but there is no evidence of comprehensive input validation, dynamic vulnerability scanning, or remediation documentation

Remediation:
Follow best practice when accepting user input and verify that all input is validated before the application processes the input.

Remediate identified vulnerabilities and obtain documented risk acceptance for those issues that cannot be remediated immediately.

---

### 222. APSC-DV-002570 | SV-222610r961167

- Rule ID: SV-222610r961167
- Severity: medium
- Rule Title: The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires error messages to avoid revealing sensitive information to end users.
- File: security/oauth_proxy.py — All error responses in OAuthProxy routes (e.g., /token, /register, /.well-known endpoints) return generic JSON error codes and descriptions (e.g., {"error": "not_configured", "detail": ...}, {"error": "invalid_client_metadata", ...})
- File: security/oauth_proxy.py — No evidence of variable names, SQL strings, or stack traces being included in error messages sent to clients
- File: README.md — Section: "Best Practices" recommends returning useful errors and never crashing, but does not specify error message content policies
- No explicit documentation or code was found that restricts error message detail based on user privilege level
- No evidence of error message filtering or redaction for non-privileged users
- Requirement: PARTIALLY SATISFIED — Error messages in OAuthProxy are generic and do not reveal sensitive data, but there is no evidence of a global policy or implementation ensuring this across the entire application

Remediation:
Configure the server to not send error messages containing system information or sensitive data to users.

Use generic error messages.

---

### 223. APSC-DV-002580 | SV-222611r961170

- Rule ID: SV-222611r961170
- Severity: medium
- Rule Title: The application must reveal error messages only to the ISSO, ISSM, or SA.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that detailed error messages are only revealed to privileged users (ISSO, ISSM, SA), and non-privileged users receive only generic errors.
- File: security/oauth_proxy.py — Error responses are generic and do not include sensitive details, but there is no logic to differentiate error message detail based on user privilege
- File: README.md — No mention of privilege-based error message handling
- No evidence of role-based error message filtering or conditional logic for privileged vs non-privileged users in the provided code
- Requirement: NOT SATISFIED — No static evidence that error messages are restricted to privileged users; all users appear to receive the same error detail

Remediation:
Configure the server to only send error messages containing system information or sensitive data to privileged users.

Use generic error messages for non-privileged users.

---

### 224. APSC-DV-002590 | SV-222612r961665

- Rule ID: SV-222612r961665
- Severity: high
- Rule Title: The application must not be vulnerable to overflow attacks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires evidence that the application is not vulnerable to overflow attacks (buffer, stack, heap, integer, format string overflows), including code analysis and test results.
- File: pyproject.toml — dependencies: Python 3.13+, no C/C++ code or unsafe memory operations in the provided files
- File: pyproject.toml — [tool.ruff.lint.select] includes 'B' (bugbear), 'S' (bandit), but no explicit overflow detection
- File: README.md — Section: "Testing" describes baseline and property tests, but does not mention fuzzing or overflow-specific analysis
- File: README.md — Section: "Evaluation" describes code quality and security analysis, but does not mention overflow testing
- No static evidence of buffer size checks, integer overflow checks, or use of canary mechanisms
- No dynamic analysis or fuzz test results present
- Requirement: PARTIALLY SATISFIED — Python's memory safety reduces overflow risk, but there is no evidence of overflow-specific testing or analysis

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

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires removal of old software components after updates.
- File: README.md — Section: "Installation" and "Releasing" describe updating dependencies and rebuilding the environment, but do not mention automated removal of old components
- File: Makefile — 'clean' target removes generated files, venv, and artifacts, but does not address removal of old application versions after update
- No evidence of scripts or configuration that automatically remove old versions after update
- Requirement: NOT SATISFIED — No static evidence that old components are removed after updates

Remediation:
Configure or design the application to remove old components when updating.

---

### 226. APSC-DV-002630 | SV-222614r1117151

- Rule ID: SV-222614r1117151
- Severity: medium
- Rule Title: Security-relevant software updates and patches must be kept up to date.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires security-relevant software updates and patches to be kept up to date, with at least weekly checks.
- File: README.md — Section: "CI/CD" describes reproducible builds and dependency locking, but does not specify a patching schedule or process
- File: Makefile — 'lock' and 'lock-upgrade-all' targets allow updating dependencies, but no evidence of scheduled or automated weekly checks
- No documentation of a patch management process or evidence of IAVM/CTO/DTM compliance
- Requirement: NOT SATISFIED — No static evidence of a documented or automated patching process

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the application to verify correct operation of security functions if it performs security functions.
- File: README.md — No mention of security function self-tests or verification routines
- File: security/oauth_proxy.py — Implements OAuth2 proxy logic, but no evidence of self-test or verification of security function operation
- No logs, test routines, or documentation describing security function verification
- Requirement: NOT SATISFIED — No static evidence of security function verification

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires verification of security functions on startup, restart, privileged command, or every 30 days.
- File: README.md — No mention of periodic or event-driven security function verification
- File: security/oauth_proxy.py — No evidence of startup or periodic security checks
- No logs, cron jobs, or code implementing scheduled security function tests
- Requirement: NOT SATISFIED — No static evidence of periodic or event-driven security function verification

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires notification to ISSO/ISSM of failed security verification tests.
- File: README.md — No mention of notification mechanisms for failed security tests
- File: security/oauth_proxy.py — No evidence of notification logic for failed security verification
- No configuration or code for alerting or notification to ISSO/ISSM
- Requirement: NOT SATISFIED — No static evidence of notification to ISSO/ISSM on failed security verification

Remediation:
Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.

---

### 230. APSC-DV-002870 | SV-222618r961083

- Rule ID: SV-222618r961083
- Severity: medium
- Rule Title: Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control prohibits unsigned Category 1A mobile code for client consumption.
- File: README.md — No mention of mobile code, browser plugins, or client-side code execution
- File: pyproject.toml — Python-only dependencies; no JavaScript, ActiveX, or Java applets
- No static evidence of mobile code (JavaScript, ActiveX, Java applets, Flash, etc.) being served to clients
- Requirement: NOT APPLICABLE — This is a server-side Python application with no client-side mobile code

Remediation:
Configure the application so Category 1A mobile code is signed.

---

### 231. APSC-DV-002880 | SV-222619r961863

- Rule ID: SV-222619r961863
- Severity: medium
- Rule Title: The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires a documented account management process for user creation, termination, and expiration.
- File: README.md — No mention of account management process or procedures
- File: etc/atlas/config.yaml — plugins.security section configures OAuth2/OIDC, but does not document account lifecycle management
- No documentation or code describing account deactivation or removal for inactive/suspended/terminated users
- Requirement: NOT SATISFIED — No static evidence of an account management process

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires web servers to be on a separate network segment from application and database servers if operating in the DoD DMZ.
- File: README.md — No mention of DMZ deployment or tiered network architecture
- File: etc/atlas/config.yaml — No network topology or segmentation configuration
- No evidence that the application is deployed in the DoD DMZ or is a tiered web application
- Requirement: NOT APPLICABLE — No evidence of DMZ or tiered web/database server architecture

Remediation:
Separate web server from other application tiers and place it on a separate network segment apart from the application and database servers in accordance with DoD DMZ data access controls requirements.

---

### 233. APSC-DV-002900 | SV-222621r1136913

- Rule ID: SV-222621r1136913
- Severity: medium
- Rule Title: The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit trails to be retained for at least 30 months (or 5 years for SAMI data).
- File: etc/atlas/config.yaml — usage_log_retention_days: 7 ("Number of days to keep PID-qualified usage-event JSONL files. On startup, files older than this are removed. 0 disables cleanup.")
- File: README.md — No mention of audit log retention policy or configuration
- No evidence of a process or configuration for 30-month or 5-year log retention
- Requirement: NOT SATISFIED — Log retention is set to 7 days, which is far below the required 30 months

Remediation:
Retain application audit log files for 30 months (12 months active + 18 months cold storage) for non-SAMI data and five years for SAMI data.

---

### 234. APSC-DV-002910 | SV-222622r961863

- Rule ID: SV-222622r961863
- Severity: medium
- Rule Title: The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires periodic review of audit trails based on system documentation.
- File: README.md — No mention of audit log review schedule or process
- File: etc/atlas/config.yaml — No configuration for audit log review or review tracking
- No documentation or code describing audit log review frequency or records
- Requirement: NOT SATISFIED — No static evidence of audit log review process or documentation

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
- Static repository review completed on 2026-04-30.
- The control requires a policy for reporting IA (Information Assurance) violations.
- File: README.md — No mention of IA policy or reporting procedures
- File: etc/atlas/config.yaml — No configuration or documentation for IA violation reporting
- No SOPs or policy documentation found in the provided files
- Requirement: NOT SATISFIED — No static evidence of an IA violation reporting policy

Remediation:
Create and maintain a policy to report IA violations.

---

### 236. APSC-DV-002930 | SV-222624r1051272

- Rule ID: SV-222624r1051272
- Severity: medium
- Rule Title: The ISSO must ensure active vulnerability testing is performed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires active vulnerability testing, including procedures and results.
- File: README.md — Section: "Testing" describes baseline and property tests, but does not mention vulnerability or fuzz testing
- File: README.md — Section: "Evaluation" describes code quality and security analysis, but not active vulnerability scanning
- No evidence of vulnerability scan procedures, configuration, or results
- Requirement: NOT SATISFIED — No static evidence of active vulnerability testing

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
- Static repository review completed on 2026-04-30.
- The control requires execution flow diagrams and design documents for deadlock/recursion mitigation in web services.
- File: README.md — No mention of web services, deadlock, or recursion mitigation
- File: pyproject.toml — No web service framework dependencies (e.g., no REST API or SOAP server libraries)
- No evidence of web service deployment or consumption in the provided files
- Requirement: NOT APPLICABLE — Application does not deploy or develop web services

Remediation:
Develop web services to account for deadlock issues.

---

### 238. APSC-DV-002960 | SV-222626r961863

- Rule ID: SV-222626r961863
- Severity: medium
- Rule Title: The designer must ensure the application does not store configuration and control files in the same directory as user data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires configuration and control files to be stored separately from user data.
- File: etc/atlas/config.yaml — configuration file path: etc/atlas/config.yaml
- File: etc/atlas/config.yaml — plugins.bookstore.directory: etc/bookstore (default context storage directory)
- File: etc/atlas/config.yaml — plugins.project_resource.persistence_path: midas-data/project_resources.json (project resource registry)
- File: etc/atlas/config.yaml — vectorstore.db_path: vectorstores/consolidated_context (vector database)
- File: etc/atlas/config.yaml — sylva.db_path: midas-data/knowledgebase/graph (graph store)
- File: etc/atlas/config.yaml — context storage and configuration files are in separate directories by default (e.g., etc/atlas, etc/bookstore, midas-data, vectorstores)
- No explicit file permission settings or enforcement found in the provided files
- No evidence of user data being stored in the same directory as configuration files, but also no explicit enforcement
- Requirement: PARTIALLY SATISFIED — Default configuration separates config and user data, but no static enforcement or permission controls are present

Remediation:
Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.

---

### 239. APSC-DV-002970 | SV-222627r961863

- Rule ID: SV-222627r961863
- Severity: medium
- Rule Title: The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires configuration according to DoD STIG/NSA guidance or, if unavailable, commercially accepted practices, independent testing, or vendor guidance.
- File: README.md — No mention of DoD STIG, NSA guides, or alternative configuration guidance
- File: etc/atlas/config.yaml — No references to STIG, NSA, or vendor lockdown guides
- No documentation of compliance with any authoritative or alternative guidance
- Requirement: NOT SATISFIED — No static evidence of configuration according to STIG, NSA, or alternative guidance

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
- Static repository review completed on 2026-04-30.
- The control requires all application ports, protocols, and services to be documented and in compliance with DoD PPSM guidance.
- File: etc/atlas/config.yaml — plugins.security.server_port: 8000 (application listens on port 8000)
- File: etc/atlas/config.yaml — plugins.security.issuer_url: "http://localhost:8082/realms/midas-mcp" (OIDC IdP on port 8082)
- File: etc/atlas/config.dev.yaml — plugins.security.issuer_url: "http://localhost:8080" (dev IdP on port 8080)
- File: README.md — No mention of PPSM compliance or port/protocol documentation
- No evidence of accreditation documentation or PPSM submission
- Requirement: NOT SATISFIED — Ports are statically configured, but there is no evidence of PPSM compliance or documentation

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
- Static repository review completed on 2026-04-30.
- Control requires evidence of registration in the DoD Ports and Protocols Database for production deployments.
- No static artifact (README.md, Makefile, pyproject.toml, etc/atlas/config.yaml) references DoD Ports and Protocols Database registration or any registration process.
- No documentation or configuration file includes a registration identifier, port registration, or process description for DoD P&P Database.
- Requirement: PARTIALLY SATISFIED — Application exposes default ports (see etc/atlas/config.yaml: server_port: 8000), but no evidence of DoD P&P Database registration is present in static artifacts.

Remediation:
Register the application and ports in the Ports and Protocols Database.

---

### 242. APSC-DV-002995 | SV-222630r961863

- Rule ID: SV-222630r961863
- Severity: medium
- Rule Title: The Configuration Management (CM) repository must be properly patched and STIG compliant.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the Configuration Management (CM) repository to be patched and STIG compliant.
- README.md: CI/CD section describes reproducible builds, dependency pinning, and lockfile management, but does not mention patch management or STIG compliance for the CM repository itself.
- Makefile: No references to patch management or STIG compliance for the CM system; focuses on reproducible builds and dependency management.
- No documentation or configuration file describes patch management processes or STIG compliance for the CM repository.
- Requirement: PARTIALLY SATISFIED — Dependency pinning and reproducible builds are enforced, but no explicit evidence of CM repository patch management or STIG compliance.

Remediation:
Patch the CM system when new security patches are made available and apply the relevant STIGs.

---

### 243. APSC-DV-003000 | SV-222631r961863

- Rule ID: SV-222631r961863
- Severity: medium
- Rule Title: Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires review of access privileges to the CM repository every three months.
- No static artifact (README.md, Makefile, etc/atlas/config.yaml) documents a process or schedule for reviewing CM repository access privileges.
- No evidence of access review logs, schedules, or procedures in the provided files.
- Requirement: NOT SATISFIED — No evidence of periodic access privilege review for the CM repository.

Remediation:
Review access privileges to the CM repository at least every three months.

---

### 244. APSC-DV-003010 | SV-222632r961863

- Rule ID: SV-222632r961863
- Severity: medium
- Rule Title: A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a Software Configuration Management (SCM) plan covering configuration control, change management, roles, tools, and audit mechanisms.
- No SCM plan or equivalent documentation is present in README.md, Makefile, or etc/atlas/config.yaml.
- core/project_resource.py implements project/resource tracking, metadata, and history, but does not constitute a documented SCM plan.
- No file describes roles, responsibilities, change request tracking, security classification, or controlled access mechanisms as required by the control.
- Requirement: NOT SATISFIED — No SCM plan or documentation meeting the control's requirements is present in static artifacts.

Remediation:
Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.

---

### 245. APSC-DV-003020 | SV-222633r961863

- Rule ID: SV-222633r961863
- Severity: medium
- Rule Title: A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires evidence of a Configuration Control Board (CCB) and charter documentation.
- No static artifact (README.md, Makefile, etc/atlas/config.yaml) references a CCB, its membership, meeting schedule, or charter documentation.
- No evidence of CCB activity, meeting records, or process documentation is present.
- Requirement: NOT SATISFIED — No evidence of a Configuration Control Board or its documentation.

Remediation:
Setup and maintain a Configuration Control Board.

---

### 246. APSC-DV-003030 | SV-222634r987685

- Rule ID: SV-222634r987685
- Severity: medium
- Rule Title: The application services and interfaces must be compatible with and ready for IPv6 networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires application services and interfaces to be compatible with DoD IPv6 Standards Profile.
- No explicit IPv6 configuration or documentation is present in README.md, Makefile, etc/atlas/config.yaml, or pyproject.toml.
- No code or configuration references IPv6 addresses, dual-stack support, or IPv6 readiness.
- Requirement: NOT SATISFIED — No evidence of IPv6 compatibility or readiness in static artifacts.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires review of server deployment and application criticality, which is a runtime/infrastructure property.
- No static artifact can confirm or refute whether the application is hosted on a general purpose machine or shared with non-mission critical applications.
- Requirement: NOT REVIEWED — Cannot be assessed from static source code or configuration alone.

Remediation:
Deploy mission critical applications on servers that are not shared by other less critical applications.

---

### 248. APSC-DV-003050 | SV-222636r1051323

- Rule ID: SV-222636r1051323
- Severity: medium
- Rule Title: A contingency plan must exist in accordance with DOD policy based on the application's availability requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a contingency plan based on availability requirements.
- No contingency plan or equivalent documentation is present in README.md, Makefile, or etc/atlas/config.yaml.
- No references to contingency planning, alternate site procedures, or operational continuity are found in any static artifact.
- Requirement: NOT SATISFIED — No contingency plan or related documentation present.

Remediation:
Create and maintain a contingency plan that identifies essential mission and business functions and associated contingency requirements.

---

### 249. APSC-DV-003060 | SV-222637r961863

- Rule ID: SV-222637r961863
- Severity: medium
- Rule Title: Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a disaster recovery plan with secure and verifiable recovery procedures.
- No disaster recovery plan or equivalent documentation is present in README.md, Makefile, or etc/atlas/config.yaml.
- No references to disaster recovery, trusted recovery, or related procedures are found in any static artifact.
- Requirement: NOT SATISFIED — No disaster recovery plan or documentation present.

Remediation:
Create and maintain a disaster recovery plan.

---

### 250. APSC-DV-003070 | SV-222638r961863

- Rule ID: SV-222638r961863
- Severity: medium
- Rule Title: Data backup must be performed at required intervals in accordance with DoD policy.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires documented backup procedures and evidence of backup frequency/testing based on risk level.
- No backup procedures, schedules, or references to backup or recovery are present in README.md, Makefile, or etc/atlas/config.yaml.
- No evidence of backup testing, offsite storage, or recovery media handling is present.
- Requirement: NOT SATISFIED — No backup procedures or related documentation present.

Remediation:
Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.

---

### 251. APSC-DV-003080 | SV-222639r961863

- Rule ID: SV-222639r961863
- Severity: medium
- Rule Title: Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires back-up copies of application software or source code to be stored in a fire-rated container or offsite.
- No documentation or configuration references backup storage locations, fire-rated containers, or offsite storage in README.md, Makefile, or etc/atlas/config.yaml.
- No evidence of backup copies or their storage method is present in static artifacts.
- Requirement: NOT SATISFIED — No evidence of compliant backup storage.

Remediation:
Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.

---

### 252. APSC-DV-003090 | SV-222640r961863

- Rule ID: SV-222640r961863
- Severity: medium
- Rule Title: Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires procedures for physical and technical protection of backup and restoration assets.
- No documentation or configuration references backup/recovery asset protection in README.md, Makefile, or etc/atlas/config.yaml.
- No evidence of procedures or controls for backup/restoration device protection is present.
- Requirement: NOT SATISFIED — No evidence of backup/restoration asset protection procedures.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires encryption for key exchange if the application implements key exchange.
- No evidence of application-level key exchange protocols or cryptographic key exchange implementation in README.md, Makefile, etc/atlas/config.yaml, or core code files.
- The application does not appear to implement its own key exchange; authentication is handled via OAuth2/OIDC (see security/oauth_proxy.py), which delegates key exchange to the underlying protocol and IdP.
- Requirement: NOT APPLICABLE — Application does not implement its own key exchange; handled by external OAuth2/OIDC infrastructure.

Remediation:
Use encryption for key exchange.

---

### 254. APSC-DV-003110 | SV-222642r961863

- Rule ID: SV-222642r961863
- Severity: high
- Rule Title: The application must not contain embedded authentication data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires no embedded authentication data (passwords, certificates, secrets) in code or configuration.
- etc/atlas/config.yaml: Only references to secrets are environment variable names (e.g., OPENAI_API_KEY, MIDAS_GITHUB_TOKEN, INTROSPECTION_CLIENT_SECRET), not actual secret values.
- pyproject.toml: No embedded secrets or authentication data.
- README.md: No embedded credentials; instructs users to set environment variables for tokens.
- No evidence of embedded authentication data in the provided files, but full static review of all code/config files is required to confirm absence.
- Requirement: PARTIALLY SATISFIED — No embedded secrets found in reviewed files, but full repository scan required for complete assurance.

Remediation:
Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.

---

### 255. APSC-DV-003120 | SV-222643r1136915

- Rule ID: SV-222643r1136915
- Severity: high
- Rule Title: The application must have the capability to mark sensitive/classified output when required.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the application to mark sensitive/classified output when required.
- No documentation, configuration, or code references output marking, classification guides, or marking procedures in README.md, Makefile, or etc/atlas/config.yaml.
- No evidence of output marking logic or user procedures for manual marking is present.
- Requirement: NOT SATISFIED — No evidence of sensitive/classified output marking capability.

Remediation:
Enable the application to adequately mark sensitive/classified output.

---

### 256. APSC-DV-003130 | SV-222644r961863

- Rule ID: SV-222644r961863
- Severity: low
- Rule Title: Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires test plans, procedures, and results to be created and executed prior to each release or patch update.
- README.md: Testing section describes baseline and property testing frameworks, test organization, and test execution commands (e.g., make test, make test-core), but does not reference formal test plans or procedures for each release.
- Makefile: Provides test execution targets but does not reference test plan documentation or release-specific procedures.
- No evidence of formal test plans or release-specific test procedures is present in static artifacts.
- Requirement: PARTIALLY SATISFIED — Automated tests are present, but no formal test plans or procedures for each release are documented.

Remediation:
Execute tests plans prior to release or patch update.

---

### 257. APSC-DV-003140 | SV-222645r961863

- Rule ID: SV-222645r961863
- Severity: medium
- Rule Title: Application files must be cryptographically hashed prior to deploying to DoD operational networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires cryptographic hashing of application files prior to deployment.
- README.md: No reference to cryptographic hash validation or process documentation for file integrity verification prior to deployment.
- Makefile: No target or command for generating or validating cryptographic hashes of application files.
- No documentation or configuration describes a hash validation process for deployment.
- Requirement: NOT SATISFIED — No evidence of cryptographic hash validation prior to deployment.

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
- Static repository review completed on 2026-04-30.
- Control requires at least one tester to be designated for security testing.
- README.md: Testing section describes test types and organization, but does not designate personnel or roles for security testing.
- No documentation or configuration references designated security testers or an organization chart.
- Requirement: NOT SATISFIED — No evidence of designated security tester(s).

Remediation:
Designate personnel to conduct security testing on the applications.

---

### 259. APSC-DV-003160 | SV-222647r961863

- Rule ID: SV-222647r961863
- Severity: low
- Rule Title: Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires annual execution of test procedures to ensure secure system state on initialization, shutdown, and aborts.
- README.md: Testing section describes baseline and property tests, but does not reference annual test procedures or specific tests for initialization, shutdown, or abort scenarios.
- No documentation or configuration references annual test execution or test dates.
- Requirement: NOT SATISFIED — No evidence of annual security state test procedures.

Remediation:
Create test procedures to test the security state of the application and exercise test procedures annually.

---

### 260. APSC-DV-003170 | SV-222648r961863

- Rule ID: SV-222648r961863
- Severity: medium
- Rule Title: An application code review must be performed on the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires documented application code reviews for security flaws.
- README.md: Testing section describes baseline and property testing, but does not reference code review processes, tools, or reports.
- No documentation or configuration references code review procedures or results.
- Requirement: NOT SATISFIED — No evidence of code review process or results.

Remediation:
Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.

---

### 261. APSC-DV-003180 | SV-222649r961863

- Rule ID: SV-222649r961863
- Severity: low
- Rule Title: Code coverage statistics must be maintained for each release of the application.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Code coverage statistics must be maintained for each release of the application.
- File: README.md — Section 'Testing', 'Test Types', and 'Coverage configuration' describe the use of baseline snapshot testing and code coverage measurement.
- File: Makefile — Target 'test-coverage' runs tests with coverage and stores data in '.coverage/coverage'.
- File: pyproject.toml — '[tool.coverage.run]' and '[tool.coverage.report]' configure coverage data collection and reporting.
- File: README.md — 'make test-coverage' documents how to run tests with coverage and where results are stored.
- Requirement: SATISFIED — Code coverage statistics are generated and maintained as part of the test process, with explicit configuration and documentation.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Flaws found during a code review must be tracked in a defect tracking system.
- File: README.md — Section 'CI/CD' and 'Best Practices' reference the use of GitHub Issues for tracking defects and context entries, and the integration of GitHub Bookstore as a context storage backend.
- File: etc/atlas/config.yaml — 'plugins.github_bookstore.repository: "MetroStar/midas-midas-context"' and 'plugins.github_issue_fetcher.repositories' list repositories used for issue tracking.
- File: plugins/advice.py — The AdviceFacet integrates with GitHub Issues and Bookstore for knowledge and defect tracking.
- File: Makefile — References to GitHub submodules and issue fetchers for integration.
- Requirement: SATISFIED — Defect tracking is integrated via GitHub Issues and Bookstore, and referenced in both configuration and code.

Remediation:
Track software defects in a defect tracking system.

---

### 263. APSC-DV-003200 | SV-222651r961863

- Rule ID: SV-222651r961863
- Severity: medium
- Rule Title: The changes to the application must be assessed for IA and accreditation impact prior to implementation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The changes to the application must be assessed for IA and accreditation impact prior to implementation.
- File: README.md — No explicit mention of IA (Information Assurance) or accreditation impact assessment process.
- File: etc/atlas/config.yaml — No references to CCB (Change Control Board) or IA assessment process.
- No static documentation or code artifacts describing a formal IA impact analysis or CCB process.
- Requirement: PARTIALLY SATISFIED — While the repository is under active development with CI/CD and release processes, there is no static evidence of a formal IA impact assessment process for changes.

Remediation:
Review IA impact to the system prior to implementing changes.

---

### 264. APSC-DV-003210 | SV-222652r961863

- Rule ID: SV-222652r961863
- Severity: medium
- Rule Title: Security flaws must be fixed or addressed in the project plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Security flaws must be fixed or addressed in the project plan.
- File: README.md — No explicit reference to a project plan or process for integrating security flaws into planning.
- File: etc/atlas/config.yaml — No project plan or security flaw tracking process described.
- File: plugins/advice.py — Security-related knowledge can be contributed and queried, but no evidence of integration into a project plan.
- Requirement: PARTIALLY SATISFIED — Security flaws can be tracked via GitHub Issues, but there is no explicit project plan artifact or process for integrating security flaws into planning.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application development team must follow a set of coding standards.
- File: README.md — Section 'Best Practices' and 'Development' explicitly state: 'Follow the facet pattern for new capabilities', 'Use Clio for all logging', 'Write baseline tests for new functionality', 'Keep tests deterministic with Echo sanitizations', and 'Document MCP tool descriptions clearly for AI assistants'.
- File: pyproject.toml — '[tool.ruff]' and '[tool.pyright]' configure strict linting and type checking, enforcing coding standards for Python code.
- File: Makefile — 'test-athena' and 'test-core' targets run linting and code quality checks as part of the test process.
- Requirement: SATISFIED — Coding standards are documented, enforced via linting/type checking, and referenced in developer documentation.

Remediation:
Create and maintain a coding standard process and documentation for developers to follow. 

Include programming best practices based on the languages being used for application development. Include items that should be standardized across the team that deals with how developers write their application code.

---

### 266. APSC-DV-003220 | SV-222654r961863

- Rule ID: SV-222654r961863
- Severity: low
- Rule Title: The designer must create and update the Design Document for each release of the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The designer must create and update the Design Document for each release of the application.
- File: README.md — No explicit design document is referenced or included.
- File: etc/atlas/config.yaml — No design document or threat model documentation included.
- No static artifact matching a design document with required details (interfaces, protections, roles, restoration priorities, etc.).
- Requirement: NOT SATISFIED — No design document artifact found in the repository.

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
- Static repository review completed on 2026-04-30.
- Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.
- File: README.md — No explicit threat model document referenced or included.
- File: etc/atlas/config.yaml — No threat model documentation included.
- No static artifact matching a threat model with required sections (identified threats, vulnerabilities, mitigations, etc.).
- Requirement: NOT SATISFIED — No threat model documentation found in the repository.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application must not be subject to error handling vulnerabilities.
- File: README.md — Section 'Testing' describes baseline snapshot testing, including error path testing and exception handling.
- File: tests/core/advice_basic.py — Test context includes 'Test error paths' and 'Always test exception handling and edge cases'.
- File: pyproject.toml — '[tool.ruff.lint.select]' includes 'BLE' (blind except), 'S' (security), and 'RET' (return statements) to catch error handling issues.
- Requirement: SATISFIED — Error handling is tested and statically analyzed for vulnerabilities.

Remediation:
Ensure proper return code and exception handling is implemented throughout the application.

---

### 269. APSC-DV-003236 | SV-222657r961863

- Rule ID: SV-222657r961863
- Severity: medium
- Rule Title: The application development team must provide an application incident response plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application development team must provide an application incident response plan.
- File: README.md — No explicit incident response plan or process is referenced.
- File: etc/atlas/config.yaml — No incident response plan or process described.
- No static artifact matching an incident response plan with required processes (tracking, confirmation, remediation, notification).
- Requirement: NOT SATISFIED — No incident response plan documentation found in the repository.

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

Evidence:
- Static repository review completed on 2026-04-30.
- All products must be supported by the vendor or the development team.
- File: README.md — Section 'CI/CD' and 'Reproducible Builds' reference dependency management and reproducibility, but do not explicitly document support status for all components.
- File: pyproject.toml — Dependencies are listed and pinned, but no explicit support status or vendor documentation is included.
- No static artifact providing proof of support for all components.
- Requirement: PARTIALLY SATISFIED — Dependency versions are pinned and managed, but explicit support documentation is missing.

Remediation:
Remove or decommission all unsupported software products in the application.

---

### 271. APSC-DV-003250 | SV-222659r961863

- Rule ID: SV-222659r961863
- Severity: high
- Rule Title: The application must be decommissioned when maintenance or support is no longer available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application must be decommissioned when maintenance or support is no longer available.
- File: README.md — No explicit decommissioning process or maintenance contract documentation is referenced.
- File: etc/atlas/config.yaml — No decommissioning or maintenance process described.
- No static artifact documenting maintenance contracts or decommissioning procedures.
- Requirement: NOT SATISFIED — No evidence of decommissioning or maintenance contract process.

Remediation:
Ensure there is maintenance for the application.

---

### 272. APSC-DV-003260 | SV-222660r961863

- Rule ID: SV-222660r961863
- Severity: low
- Rule Title: Procedures must be in place to notify users when an application is decommissioned.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Procedures must be in place to notify users when an application is decommissioned.
- File: README.md — No explicit notification procedure for decommissioning is referenced.
- File: etc/atlas/config.yaml — No notification procedure described.
- No static artifact documenting user notification procedures for decommissioning.
- Requirement: NOT SATISFIED — No evidence of user notification procedures for decommissioning.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Unnecessary built-in application accounts must be disabled.
- Architectural reason: The application is a developer tool and framework, not a user-facing application with built-in accounts. Authentication is handled via OIDC/OAuth2 integration (see etc/atlas/config.yaml: 'issuer_url', 'introspection_client_id', etc.), and there is no evidence of built-in application accounts in the provided code or configuration.

Remediation:
Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Default passwords must be changed.
- Architectural reason: The application does not use default passwords. Authentication is handled via OIDC/OAuth2 (see etc/atlas/config.yaml: 'issuer_url', 'introspection_client_id', etc.), and there are no static credentials or default passwords in the provided code or configuration.

Remediation:
Configure the application to use strong authenticators instead of passwords when possible. Otherwise, change default passwords to a DoD-approved strength password and follow all guidance for passwords.

---

### 275. APSC-DV-003285 | SV-222663r961863

- Rule ID: SV-222663r961863
- Severity: medium
- Rule Title: An Application Configuration Guide must be created and included with the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- An Application Configuration Guide must be created and included with the application.
- File: README.md — Provides extensive configuration and usage documentation, but does not constitute a formal Application Configuration Guide covering all required topics (encryption, PKI, password, auditing, backup, network, deployment, security assumptions, etc.).
- File: etc/atlas/config.yaml — Contains detailed configuration for plugins, personas, and pipelines, but is not a comprehensive configuration guide as described in the control.
- Requirement: PARTIALLY SATISFIED — Configuration is documented, but a formal Application Configuration Guide is not present.

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
- Static repository review completed on 2026-04-30.
- If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.
- Architectural reason: There is no evidence that the application processes or stores classified information. No references to classified data, classification guides, or related controls are present in the provided files.

Remediation:
Create and maintain a security classification guide.

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The designer must ensure uncategorized or emerging mobile code is not used in applications.
- File: pyproject.toml — All dependencies are standard, well-known Python packages; no mobile code or browser-executed code is present.
- File: README.md — No mention of mobile code, JavaScript, or browser plugins except for Swagger UI (documentation only).
- Requirement: SATISFIED — No uncategorized or emerging mobile code is present in the application.

Remediation:
Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Production database exports must have database administration credentials and sensitive data removed before releasing the export.
- Architectural reason: The application is a code analysis and developer tool, not a production application with a user database. No evidence of database exports or sensitive data handling is present in the provided code or configuration.

Remediation:
Remove sensitive data from production database exports.

---

### 279. APSC-DV-003320 | SV-222667r961863

- Rule ID: SV-222667r961863
- Severity: medium
- Rule Title: Protections against DoS attacks must be implemented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Protections against DoS attacks must be implemented.
- File: README.md — No explicit mention of DoS protections or threat model documentation.
- File: etc/atlas/config.yaml — No configuration for DoS mitigation or rate limiting.
- No static artifact describing DoS threat identification or mitigation.
- Requirement: NOT SATISFIED — No evidence of DoS threat identification or mitigation.

Remediation:
Implement mitigations from the threat model for DOS attacks.

---

### 280. APSC-DV-003330 | SV-222668r961863

- Rule ID: SV-222668r961863
- Severity: medium
- Rule Title: The system must alert an administrator when low resource conditions are encountered.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The system must alert an administrator when low resource conditions are encountered.
- File: README.md — No mention of resource monitoring or alerting.
- File: etc/atlas/config.yaml — No configuration for resource monitoring or alerting.
- No static artifact describing automated monitoring or alerting for low resource conditions.
- Requirement: NOT SATISFIED — No evidence of low resource alerting mechanisms.

Remediation:
Implement mechanisms to alert system administrators about a low resource condition.

---

### 281. APSC-DV-003340 | SV-222669r961863

- Rule ID: SV-222669r961863
- Severity: low
- Rule Title: At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires static evidence that at least one application administrator is registered to receive update/security notifications for all application components (custom, libraries, third-party tools).
- File: README.md — No explicit section or configuration for administrator registration or notification recipients for updates/alerts. No mention of admin email lists, notification hooks, or alert registration.
- File: etc/atlas/config.yaml — No configuration key for admin contacts, notification recipients, or alert registration. No 'admin', 'notification', or 'alert' recipient fields present under any plugin or global config.
- File: pyproject.toml — No maintainer or admin email/contact fields in [project] or elsewhere; only 'authors' field with 'MIDAS Development Team' (not a notification registration mechanism).
- No static artifact (YAML, code, or documentation) demonstrates that deployment personnel are registered to receive update/security notifications for any component.
- Requirement: PARTIALLY SATISFIED — Application documentation lists authors but does not statically register administrators for update/security notifications. Evidence of registration mechanism or recipient list is missing.

Remediation:
Register administrators to receive update notifications so they can patch and update applications and application components.

---

### 282. APSC-DV-003345 | SV-222670r961863

- Rule ID: SV-222670r961863
- Severity: low
- Rule Title: The application must provide notifications or alerts when product update and security related patches are available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the application to provide notifications or alerts when product updates or security patches are available, including a description, risk summary, mitigation, and how to obtain the update.
- File: README.md — No section describing an automated or manual notification process for product updates or security patches. No mention of alerting, notification hooks, or update distribution mechanisms.
- File: etc/atlas/config.yaml — No configuration for update notification, alerting, or patch availability. No keys for 'notification', 'alert', 'update', or 'patch' under any plugin or global config.
- File: pyproject.toml — No scripts, dependencies, or metadata related to update/patch notification or alerting.
- No static artifact (YAML, code, or documentation) describes a process or mechanism for notifying administrators or users of available updates or security patches, nor any process for communicating risk or mitigation.
- Requirement: NOT SATISFIED — No evidence of an update/patch notification process or mechanism in static configuration or documentation.

Remediation:
Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.

---

### 283. APSC-DV-003350 | SV-222671r961863

- Rule ID: SV-222671r961863
- Severity: medium
- Rule Title: Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires confirmation that connections between the DoD enclave and the Internet are routed through a DMZ if the application is publicly accessible.
- This is a deployment/network architecture control. No static source code, configuration, or documentation in the provided files specifies network topology, DMZ enforcement, or public accessibility status.
- No evidence in etc/atlas/config.yaml, README.md, or pyproject.toml regarding DMZ configuration or network boundaries.
- Requirement: NOT REVIEWED — Cannot be assessed via static source code or configuration; requires deployment/network interview and live environment review.

Remediation:
Setup a DMZ between DoD and public networks.

---

### 284. APSC-DV-003360 | SV-222672r961833

- Rule ID: SV-222672r961833
- Severity: low
- Rule Title: The application must generate audit records when concurrent logons from different workstations occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the application to generate audit records when concurrent logons from different workstations occur, including logging the source workstation IP address.
- File: etc/atlas/config.yaml — No configuration for audit logging, session tracking, or concurrent logon detection. No keys for 'audit', 'logon', 'session', or 'ip_address' under any plugin or global config.
- File: core/project_resource.py — No code for authentication, session management, or audit logging of logons or IP addresses. ProjectResource and ProjectRegistry focus on resource/project tracking, not user sessions.
- File: security/__init__.py — Implements OIDC/OAuth2 token validation and issuer config, but no evidence of audit logging for concurrent logons or IP address tracking. No references to logging user logons, session IDs, or source IP addresses.
- File: README.md — No mention of audit log configuration, logon tracking, or concurrent session detection.
- No static artifact demonstrates audit record generation for concurrent logons from different workstations or IP address logging.
- Requirement: NOT SATISFIED — No evidence of audit log records for concurrent logons or IP address tracking in static code or configuration.

Remediation:
Configure the application to log concurrent logons from different workstations.

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires evidence that all program managers, designers, developers, and testers receive annual security training pertaining to their job function.
- File: README.md — No section or reference to security training requirements, training records, or evidence of annual security training for any role.
- File: etc/atlas/config.yaml — No configuration or documentation of security training, training completion, or class rosters.
- File: pyproject.toml — No mention of security training, training dependencies, or documentation.
- No static artifact (YAML, code, or documentation) provides evidence of annual security training for any personnel.
- Requirement: NOT SATISFIED — No evidence of security training or training records present in static artifacts.

Remediation:
Provide application development/operational related security specific annual training for managers, designers, developers, and testers.

---

### 286. APSC-DV-002010 | SV-265634r1117183

- Rule ID: SV-265634r1117183
- Severity: medium
- Rule Title: The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires NSA-approved cryptography for protection of classified information if the application processes classified data.
- File: etc/atlas/config.yaml — No indication that the application processes classified data. No configuration for classified data handling, NSA-approved cryptography, or FIPS 140-2 modules.
- File: README.md — No mention of classified data processing, classified information, or cryptographic requirements for classified data.
- File: pyproject.toml — No dependencies or configuration for NSA Type-1 encryption or FIPS 140-2 modules. Only standard cryptography libraries for JWT validation (PyJWT[crypto], cryptography) are present, which are not sufficient for classified data.
- Control check_content: "If the application does not process classified data, this requirement is not applicable."
- Requirement: NOT APPLICABLE — No evidence that the application processes classified information; cryptographic requirements for classified data do not apply.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
