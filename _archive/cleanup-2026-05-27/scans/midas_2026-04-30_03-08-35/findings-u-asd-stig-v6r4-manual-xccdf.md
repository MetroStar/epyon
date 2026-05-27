# midas STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 201 |
| Not a Finding | 9 |
| Not Applicable | 73 |
| Not Reviewed | 3 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a mechanism to limit the number of logon sessions per user.
- Searched all provided files for configuration keys or logic such as 'max_sessions', 'session_limit', or similar in etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/middleware.py, security/token_authority.py, security/oauth_proxy.py, and README.md.
- No configuration setting or code artifact found that enforces a per-user session limit or tracks concurrent sessions per user.
- Session management is present (see BearerMiddleware in security/middleware.py), but no logic for limiting concurrent sessions.
- Requirement: NOT SATISFIED — no evidence of session-per-user limitation in configuration or code.

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
- Control requires clearing temporary storage and cookies when the session is terminated, and prohibits storing authentication information in cookies or local storage.
- Searched for cookie/session management logic in security/middleware.py, security/oauth_proxy.py, and README.md.
- The application uses Bearer JWT tokens for authentication (see security/middleware.py::BearerMiddleware), and does not reference cookies or browser storage for session state.
- No explicit code found that sets, clears, or manages cookies or browser storage on session termination.
- No evidence of authentication information being stored in cookies or local storage, but also no explicit clearing logic.
- Requirement: PARTIALLY SATISFIED — authentication is token-based and not stored in cookies, but no explicit evidence of clearing temporary storage/cookies on logout.

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
- Searched for session timeout, idle timeout, or similar settings in etc/atlas/config.yaml, security/middleware.py, security/token_authority.py, and README.md.
- No configuration key or code artifact found for session idle timeout or automatic session termination based on inactivity.
- BearerMiddleware (security/middleware.py) validates tokens on each request but does not enforce idle timeouts; token expiry is based on JWT 'exp' claim, which is not statically set in this codebase.
- Requirement: NOT SATISFIED — no evidence of session idle timeout enforcement for non-privileged users.

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
- Searched for admin session timeout, idle timeout, or privilege-based session management in etc/atlas/config.yaml, security/middleware.py, security/token_authority.py, and README.md.
- No configuration key or code artifact found for privilege-based session idle timeout or automatic session termination for admin users.
- BearerMiddleware (security/middleware.py) does not differentiate session timeout by user privilege.
- Requirement: NOT SATISFIED — no evidence of admin session idle timeout enforcement.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a user-initiated logoff capability in the interactive user interface.
- README.md and codebase describe MIDAS as an API server for AI assistants and IDE integration, not an interactive web application with user sessions.
- Authentication is via Bearer JWT tokens; no UI or web interface for user-initiated logoff is present.
- Requirement: NOT APPLICABLE — application does not provide an interactive user interface for user-initiated logoff.

Remediation:
Design and configure the application to provide all users with the capability to manually terminate their application session.

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires displaying an explicit logoff message to users in an interactive UI.
- README.md and codebase indicate MIDAS is an API server for AI assistants and IDEs, not an interactive web application.
- No UI or mechanism for displaying logoff messages to users is present.
- Requirement: NOT APPLICABLE — application does not provide an interactive user interface.

Remediation:
Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires marking data with organization-defined security attributes in storage if the application processes classified, CUI, or other marked data.
- No evidence in README.md, etc/atlas/config.yaml, or core/project_resource.py of handling classified, CUI, or marked data.
- No data marking or security attribute fields present in storage models.
- Requirement: NOT APPLICABLE — application does not process data requiring security markings.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires retaining security attribute markings with data in process if the application processes classified, CUI, or marked data.
- No evidence in README.md, etc/atlas/config.yaml, or core/project_resource.py of handling classified, CUI, or marked data.
- No data marking or security attribute logic present in processing code.
- Requirement: NOT APPLICABLE — application does not process data requiring security markings.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires retaining security attribute markings with data in transmission if the application processes classified, CUI, or marked data.
- No evidence in README.md, etc/atlas/config.yaml, or core/project_resource.py of handling classified, CUI, or marked data.
- No data marking or security attribute logic present in transmission code.
- Requirement: NOT APPLICABLE — application does not process data requiring security markings.

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
- Searched etc/atlas/config.yaml for HTTPS/TLS configuration; server_host is set to '0.0.0.0', server_port to 8000, but no evidence of TLS/SSL configuration (no 'ssl_certfile', 'ssl_keyfile', or similar).
- README.md documents server running on 'http://localhost:8000' (not HTTPS).
- No code artifacts in security/middleware.py or security/oauth_proxy.py indicating TLS enforcement at the application layer.
- Requirement: NOT SATISFIED — no evidence of TLS/SSL configuration for remote access sessions.

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
- Searched etc/atlas/config.yaml for HTTPS/TLS configuration; server_host is set to '0.0.0.0', server_port to 8000, but no evidence of TLS/SSL configuration (no 'ssl_certfile', 'ssl_keyfile', or similar).
- README.md documents server running on 'http://localhost:8000' (not HTTPS).
- No code artifacts in security/middleware.py or security/oauth_proxy.py indicating TLS enforcement at the application layer.
- Requirement: NOT SATISFIED — no evidence of TLS/SSL configuration for remote access sessions.

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
- Control applies only if the application uses SOAP messages requiring integrity.
- Searched README.md, etc/atlas/config.yaml, and codebase for SOAP, WS-Security, or SAML usage.
- No evidence of SOAP message handling, WS-Security, or SAML assertion logic in any provided file.
- Requirement: NOT APPLICABLE — application does not use SOAP messages.

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
- Control applies only if the application uses WS-Security tokens.
- Searched README.md, etc/atlas/config.yaml, and codebase for WS-Security, SOAP, or SAML usage.
- No evidence of WS-Security token handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use WS-Security tokens.

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
- Searched README.md, etc/atlas/config.yaml, and codebase for WS-Security or SAML assertion usage.
- No evidence of WS-Security or SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use WS-Security or SAML assertions.

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
- Searched README.md, etc/atlas/config.yaml, and codebase for SAML assertion usage.
- No evidence of SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use SAML assertions.

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
- Control applies only if the application uses WS-Security tokens.
- Searched README.md, etc/atlas/config.yaml, and codebase for WS-Security token usage.
- No evidence of WS-Security token handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use WS-Security tokens.

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
- Control applies only if the application uses SAML assertions with SubjectConfirmation elements.
- Searched README.md, etc/atlas/config.yaml, and codebase for SAML assertion usage.
- No evidence of SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use SAML assertions.

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
- Control applies only if the application uses SAML assertions with Conditions elements.
- Searched README.md, etc/atlas/config.yaml, and codebase for SAML assertion usage.
- No evidence of SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use SAML assertions.

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
- Control applies only if the application uses SAML assertions with OneTimeUse elements.
- Searched README.md, etc/atlas/config.yaml, and codebase for SAML assertion usage.
- No evidence of SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use SAML assertions.

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
- Control applies only if the application uses SAML assertions with SessionIndex tied to privacy data.
- Searched README.md, etc/atlas/config.yaml, and codebase for SAML assertion usage.
- No evidence of SAML assertion handling in any provided file.
- Requirement: NOT APPLICABLE — application does not use SAML assertions.

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
- Control requires automated mechanisms for supporting account management functions (e.g., automated disabling/removal of inactive/terminated accounts, notifications, etc.).
- File: etc/atlas/config.yaml — No explicit configuration for automated account management actions (e.g., disabling/removal of inactive accounts, automated notifications, or account lifecycle management) is present in the configuration.
- File: core/project_resource.py — Implements project/resource registration, metadata, and state tracking, but does not implement user account management or automated account lifecycle actions.
- File: plugins/advice.py — No account management logic; provides knowledge interaction tools only.
- File: README.md — Describes authentication via OIDC/OAuth2 and integration with external IdPs (e.g., Keycloak), but does not document automated account management mechanisms within the application itself.
- Requirement: PARTIALLY SATISFIED — Application supports external IdP integration (OIDC/OAuth2), but there is no static evidence of automated account management actions (e.g., disabling/removal of inactive/terminated accounts) within the application. Further evidence from authentication/authorization plugins or runtime configuration is required.

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
- File: etc/atlas/config.yaml — No mention of shared or group accounts in configuration or documentation.
- File: README.md — No reference to shared/group accounts; authentication is described as individual via OIDC/OAuth2.
- File: core/project_resource.py — Resource/project management is not related to user/group account management.
- There is no evidence that the application supports or requires shared/group accounts.
- Requirement: NOT APPLICABLE — Application does not implement or require shared/group accounts; all authentication is individual and delegated to external IdP.

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
- File: etc/atlas/config.yaml — No configuration for temporary user accounts or expiration/removal settings.
- File: README.md — No mention of temporary user accounts; all authentication is via external IdP.
- File: core/project_resource.py — No user account management logic.
- There is no evidence that the application supports temporary user accounts.
- Requirement: NOT APPLICABLE — Application does not implement temporary user accounts; authentication is delegated to external IdP.

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
- Control requires a process or feature to prevent removal/disabling of emergency accounts during a crisis.
- File: etc/atlas/config.yaml — No mention of emergency accounts or related configuration.
- File: README.md — No reference to emergency accounts; authentication is via external IdP.
- File: core/project_resource.py — No user account management logic.
- There is no evidence that the application supports or requires emergency accounts.
- Requirement: NOT APPLICABLE — Application does not implement emergency accounts; authentication is delegated to external IdP.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic disabling of accounts after 35 days of inactivity unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account inactivity tracking or disabling logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); inactivity disabling is the responsibility of the IdP.

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
- File: etc/atlas/config.yaml — No configuration for application user accounts; authentication is via external IdP.
- File: README.md — No process described for enumerating or validating application user accounts; user management is external.
- File: core/project_resource.py — Manages project/resource registration, not user accounts.
- There is no static evidence of a mechanism to enumerate, validate, or remove unnecessary application user accounts within the application itself.
- Requirement: PARTIALLY SATISFIED — Application does not appear to create local user accounts, but there is no explicit evidence of a process to enumerate or validate user accounts. Confirmation from authentication/authorization plugins or runtime configuration is required.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing of account creation unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account creation or auditing logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account creation auditing is the responsibility of the IdP.

Remediation:
Configure the application to write a log entry when a new user account is created.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 28. APSC-DV-000350 | SV-222414r960780

- Rule ID: SV-222414r960780
- Severity: medium
- Rule Title: The application must automatically audit account modification.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing of account modification unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account modification or auditing logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account modification auditing is the responsibility of the IdP.

Remediation:
Configure the application to write a log entry when a user account is modified.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 29. APSC-DV-000360 | SV-222415r960783

- Rule ID: SV-222415r960783
- Severity: medium
- Rule Title: The application must automatically audit account disabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing of account disabling actions unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account disabling or auditing logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account disabling auditing is the responsibility of the IdP.

Remediation:
Configure the application to write a log entry when a user account is disabled.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 30. APSC-DV-000370 | SV-222416r960786

- Rule ID: SV-222416r960786
- Severity: medium
- Rule Title: The application must automatically audit account removal actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing of account removal actions unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account removal or auditing logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account removal auditing is the responsibility of the IdP.

Remediation:
Configure the application to write a log entry when a user account is removed.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 31. APSC-DV-000380 | SV-222417r1015684

- Rule ID: SV-222417r1015684
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are created.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are created unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account creation or notification logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account creation notification is the responsibility of the IdP.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are created.

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are modified unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account modification or notification logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account modification notification is the responsibility of the IdP.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are modified.

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are disabled unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account disabling or notification logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account disabling notification is the responsibility of the IdP.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are disabled.

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are removed unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account removal or notification logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account removal notification is the responsibility of the IdP.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires automatic auditing of account enabling actions unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account enabling or auditing logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account enabling auditing is the responsibility of the IdP.

Remediation:
Configure the application to write a log entry when a user account is enabled. 

At a minimum, ensure account name, date and time of the event are recorded.

---

### 36. APSC-DV-000430 | SV-222422r1015688

- Rule ID: SV-222422r1015688
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account enabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires notification to SAs/ISSOs when accounts are enabled unless using a centralized user management system.
- File: etc/atlas/config.yaml — Authentication is configured via OIDC/OAuth2 (see 'issuer_url', 'introspection_client_id', etc.), indicating use of external IdP.
- File: README.md — Documents use of external IdP (Keycloak, Cognito, Okta, etc.) for authentication and user management.
- File: core/project_resource.py — No user account enabling or notification logic.
- Requirement: NOT APPLICABLE — Application delegates user management to external IdP (OIDC/OAuth2); account enabling notification is the responsibility of the IdP.

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
- Control requires identification and documentation of application data protection requirements.
- File: etc/atlas/config.yaml — Contains configuration for various plugins and data stores (e.g., vectorstore, cortex, sylva, embedder), but does not document data protection requirements (e.g., classification, encryption, retention, access control) for application data elements.
- File: README.md — No section or documentation describing data protection requirements for application data elements.
- No evidence of a dedicated data protection requirements document or section in the provided files.
- Requirement: NOT SATISFIED — Application data protection requirements are not identified or documented in the provided static artifacts.

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
- Control requires implementation of organization-defined data mining detection techniques (e.g., query limits, automated alarming, record limits, etc.) if required.
- File: etc/atlas/config.yaml — No configuration for data mining detection, query rate limiting, or automated alarming on query events.
- File: README.md — No mention of data mining protections or detection techniques.
- File: core/project_resource.py, plugins/advice.py — No logic for query rate limiting, record count limiting, or data mining detection.
- Requirement: PARTIALLY SATISFIED — No evidence of data mining detection techniques implemented in the application. If not required by the organization, this control may be Not Applicable, but no such statement is present in the documentation.

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
- Control requires enforcement of approved authorizations for logical access to information and system resources (e.g., RBAC, access control policies).
- File: etc/atlas/config.yaml — Security section configures OIDC/OAuth2 integration (issuer_url, audience, client IDs), but does not define application-level access control policies or RBAC.
- File: core/project_resource.py — Implements resource/project registration and access verification for resources, but not for user access to application data or resources.
- File: plugins/advice.py — No access control enforcement logic; MCP tool access is not restricted by role or policy in the provided code.
- File: README.md — No documentation of application-level access control policies or RBAC enforcement.
- Requirement: PARTIALLY SATISFIED — Application supports authentication via external IdP, but there is no static evidence of application-level access control enforcement (e.g., RBAC, per-resource authorization) in the provided files.

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
- File: etc/atlas/config.yaml — No configuration for DAC or user-controlled permissions on data/objects.
- File: core/project_resource.py — Resource/project management is performed by administrators, not by end users; no DAC logic present.
- File: README.md — No mention of user-controlled permissions or DAC.
- There is no evidence that the application implements discretionary access controls.
- Requirement: NOT APPLICABLE — Application does not implement DAC; all resource/project management is administrative, not user-discretionary.

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
- Control requires enforcement of information flow control policies (rulesets, data labels, policies) within the system.
- File: README.md — No mention of data labeling, information flow control, or policy enforcement for data movement within the application. The architecture and plugin/facet system is described, but no explicit mechanism for data flow control is documented.
- File: etc/atlas/config.yaml — No configuration keys for data labeling, flow control rules, or policy enforcement. Plugin configs focus on AI personas, context, ingestion, and storage, not on information flow control.
- File: core/facet.py — Defines plugin/facet base class, but no evidence of data flow control logic or enforcement hooks.
- File: core/project_resource.py — Defines project/resource abstraction, but no data labeling or flow control enforcement.
- File: plugins/github_bookstore.py — Manages context storage via GitHub Issues, but does not implement or reference information flow control.
- Requirement: PARTIALLY SATISFIED — Application is extensible and supports plugins, but there is no evidence of data flow control enforcement, rulesets, or data labeling in the provided static artifacts. No explicit mechanism for controlling or restricting information flow based on policy.

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
- File: README.md — Describes integration with external systems (e.g., GitHub, OIDC IdP, vectorstores), but no mention of data labeling or flow control enforcement between systems.
- File: etc/atlas/config.yaml — Configures external integrations (GitHub, vectorstores, OIDC), but no keys for data flow control, labeling, or policy enforcement between systems.
- File: core/facet.py, core/project_resource.py — No evidence of cross-system data flow control or enforcement logic.
- File: plugins/github_bookstore.py — Interacts with GitHub Issues, but does not implement or reference information flow control between systems.
- Requirement: PARTIALLY SATISFIED — Application connects to multiple systems, but there is no evidence of data flow control enforcement or policy-based restrictions between interconnected systems in the provided static artifacts.

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
- Control requires that non-privileged users cannot execute privileged functions or alter security safeguards.
- File: README.md — No mention of OS-level user/group permissions, privilege separation, or restrictions on application user accounts.
- File: Makefile — No commands for setting file permissions or restricting execution to non-privileged users. No mention of user/group management.
- File: etc/atlas/config.yaml — No configuration for OS user/group, privilege separation, or file/directory ownership.
- File: core/facet.py, core/project_resource.py — No code for privilege checks, OS-level permission enforcement, or user/group validation.
- File: pyproject.toml — No scripts or install hooks for setting file/directory permissions.
- Requirement: PARTIALLY SATISFIED — No evidence of excessive permissions, but also no explicit enforcement or documentation of least privilege for application accounts or files. Cannot confirm prevention of non-privileged users executing privileged functions from static analysis alone.

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
- Control requires the application to execute without excessive account permissions (no admin/root/DBA privileges).
- File: README.md — No documentation of required OS/database user accounts, privilege levels, or group memberships for running the application.
- File: Makefile — No commands for setting or checking user/group permissions for execution.
- File: etc/atlas/config.yaml — No configuration for OS/database user accounts or privilege levels.
- File: core/facet.py, core/project_resource.py — No code for privilege checks or enforcement of least privilege at the OS or database level.
- Requirement: PARTIALLY SATISFIED — No evidence of excessive permissions, but also no explicit enforcement or documentation of least privilege for application or database accounts. Cannot confirm compliance from static artifacts alone.

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
- Control requires auditing the execution of privileged functions (logging admin actions, including action, date, and time).
- File: README.md — No mention of privileged function auditing or admin action logging.
- File: etc/atlas/config.yaml — No configuration for audit log location, privileged action logging, or audit policy.
- File: core/facet.py — Defines plugin/facet system, but no evidence of privileged action logging.
- File: security/oauth_proxy.py — Uses 'security.audit_log.emit' for token proxy events, but not for privileged application functions.
- Example: 'from security.audit_log import emit as _audit' and calls to '_audit' for token proxy events only.
- File: plugins/github_bookstore.py — No privileged function auditing.
- Requirement: PARTIALLY SATISFIED — Some audit logging exists for OAuth2 token proxy events, but there is no evidence of auditing privileged application functions (e.g., user management, configuration changes).

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
- Control requires enforcement of account lockout after 3 consecutive invalid logon attempts within 15 minutes.
- File: README.md — No mention of account lockout, failed login tracking, or lockout policy.
- File: etc/atlas/config.yaml — No configuration for lockout thresholds, failed login counters, or lockout duration.
- File: core/facet.py, core/project_resource.py — No code for login attempt tracking, lockout enforcement, or user authentication logic.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not implement account lockout logic; rate limiting applies to /token endpoint, not user logins.
- Requirement: NOT SATISFIED — No evidence of account lockout after failed logon attempts in any static artifact.

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
- File: README.md — No mention of account unlock process or administrator procedures.
- File: etc/atlas/config.yaml — No configuration for account unlock workflow or process documentation.
- File: core/facet.py, core/project_resource.py — No code for unlocking user accounts or admin unlock workflows.
- File: security/oauth_proxy.py — No account unlock logic; only handles OAuth2 proxying.
- Requirement: NOT SATISFIED — No evidence of an account unlock process or supporting code/documentation.

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
- Control requires display of the DoD Notice and Consent Banner before granting access to the application (interactive UI).
- File: README.md — Application is described as a backend MCP server with AI assistant integration (VS Code, Copilot, etc.), not an interactive user interface.
- File: etc/atlas/config.yaml — No configuration for login banners or UI banners.
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- Requirement: NOT APPLICABLE — Application does not provide an interactive user interface; banner requirement does not apply.

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
- File: README.md — Application is a backend MCP server with no interactive user interface.
- File: etc/atlas/config.yaml — No configuration for banners or UI prompts.
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- Requirement: NOT APPLICABLE — Application does not provide an interactive user interface; banner retention requirement does not apply.

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
- Control applies only to publicly accessible applications with interactive UI (DoD banner display).
- File: README.md — Application is a backend MCP server, not a public web application with interactive UI.
- File: etc/atlas/config.yaml — No configuration for public access banners.
- File: core/facet.py, core/project_resource.py — No UI code or banner display logic.
- Requirement: NOT APPLICABLE — Application is not a publicly accessible interactive application; banner requirement does not apply.

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
- Control requires display of last successful logon date/time in the user interface.
- File: README.md — Application is a backend MCP server with no interactive user interface for users.
- File: etc/atlas/config.yaml — No configuration for displaying last logon information.
- File: core/facet.py, core/project_resource.py — No UI code or user-facing display logic.
- Requirement: NOT APPLICABLE — Application does not provide a user interface; last logon display requirement does not apply.

Remediation:
Design and configure the application to display the date and time when the user was last successfully granted access to the application.

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires non-repudiation (digital signatures or equivalent) for organization-defined actions.
- File: README.md — No mention of digital signatures, non-repudiation, or cryptographic proof of actions.
- File: etc/atlas/config.yaml — No configuration for digital signature, non-repudiation, or audit trail with cryptographic binding.
- File: core/facet.py, core/project_resource.py — No code for digital signature generation, verification, or non-repudiation services.
- File: plugins/github_bookstore.py — No non-repudiation or signature logic.
- Requirement: NOT SATISFIED — No evidence of non-repudiation functionality in any static artifact.

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
- File: README.md — No mention of audit log aggregation or system-wide audit trail correlation.
- File: etc/atlas/config.yaml — No configuration for audit log aggregation or time correlation.
- File: core/facet.py, core/project_resource.py — No code for audit log aggregation or time correlation.
- Requirement: NOT APPLICABLE — Application does not provide audit record aggregation; control does not apply.

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
- File: README.md — No mention of session management or session ID creation logging.
- File: etc/atlas/config.yaml — No configuration for session ID creation auditing or logging.
- File: core/facet.py, core/project_resource.py — No code for session management or session creation event logging.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not log session ID creation events; audit logging is limited to token proxy events.
- Requirement: NOT SATISFIED — No evidence of session ID creation event auditing in any static artifact.

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
- File: README.md — No mention of session management or session ID destruction logging.
- File: etc/atlas/config.yaml — No configuration for session ID destruction auditing or logging.
- File: core/facet.py, core/project_resource.py — No code for session management or session destruction event logging.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not log session ID destruction events.
- Requirement: NOT SATISFIED — No evidence of session ID destruction event auditing in any static artifact.

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
- File: README.md — No mention of session renewal or privilege escalation logging.
- File: etc/atlas/config.yaml — No configuration for session ID renewal auditing or logging.
- File: core/facet.py, core/project_resource.py — No code for session renewal or privilege escalation event logging.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not log session ID renewal events.
- Requirement: NOT SATISFIED — No evidence of session ID renewal event auditing in any static artifact.

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
- File: etc/atlas/config.yaml — No configuration for log redaction, sensitive data filtering, or log format.
- File: core/facet.py, core/project_resource.py — No code for log sanitization or sensitive data filtering.
- File: security/oauth_proxy.py — Audit logging for token proxy events does not include sensitive data (logs client_id, grant_type, status, but not tokens or secrets):
- Example: '_audit("token_proxy", outcome="success", client_id=client_id, grant_type=grant_type, upstream_status=resp.status_code, client_ip=client_ip)'
- Requirement: PARTIALLY SATISFIED — No evidence of sensitive data being logged in the provided code, but also no explicit log sanitization or filtering. Cannot confirm for all log sources without reviewing all logging code.

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
- File: README.md — No mention of session timeout or timeout event logging.
- File: etc/atlas/config.yaml — No configuration for session timeout auditing or logging.
- File: core/facet.py, core/project_resource.py — No code for session timeout detection or event logging.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not log session timeout events.
- Requirement: NOT SATISFIED — No evidence of session timeout event auditing in any static artifact.

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
- Control requires that all audit events include a time stamp indicating when the event occurred.
- File: security/oauth_proxy.py — Audit log entries for token proxy events include a timestamp field:
- Example: 'self.log_queue.put({"type": msg_type, "message": message, "timestamp": datetime.now().isoformat(), **extra})' in core/facet.py:AsyncJob.log()
- However, this is only for async job logs and token proxy events, not for all audit events.
- File: README.md, etc/atlas/config.yaml, core/facet.py, core/project_resource.py — No evidence of comprehensive audit logging with timestamps for all events.
- Requirement: PARTIALLY SATISFIED — Some logs include timestamps, but cannot confirm all required audit events are logged with time stamps.

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
- File: README.md — No mention of HTTP header logging or audit.
- File: etc/atlas/config.yaml — No configuration for HTTP header logging or audit.
- File: core/facet.py, core/project_resource.py — No code for HTTP header logging.
- File: security/oauth_proxy.py — Handles OAuth2 proxying, but does not log HTTP headers (User-Agent, Referer, etc.) in audit logs or elsewhere.
- Requirement: NOT SATISFIED — No evidence of HTTP header audit logging in any static artifact.

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
- Control requires audit logs to include connecting system IP addresses.
- File: security/middleware.py — BearerMiddleware logs client IP on every auth event:
- `_audit("auth_grant", ..., client_ip=client_ip, ...)` and `_audit("auth_deny", ..., client_ip=client_ip, ...)`
- `client_ip` is extracted from ASGI scope: `client_ip: str = (scope.get("client") or ("unknown", 0))[0]`
- File: security/audit_log.py (not included) — referenced for `_audit` function, but actual log storage location and format not visible in provided files.
- README.md: No explicit documentation of audit log file location or retention for IP addresses.
- Requirement: PARTIALLY SATISFIED — IP addresses are included in structured audit log events for authentication, but static evidence of log file storage, log format, and coverage for all connection types is incomplete from provided files.

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
- Control requires audit logs to include the username or user ID associated with each event.
- File: security/middleware.py — BearerMiddleware logs `sub` (subject/user ID) on all auth events:
- `_audit("auth_grant", sub=verified.sub, ...)` and `_audit("auth_deny", sub=_unverified_sub, ...)`
- `sub` is extracted from the JWT claims: `verified.sub` or `_unverified_sub`
- File: security/audit_log.py (not included) — referenced for `_audit` function, but actual log storage location and format not visible in provided files.
- README.md: No explicit documentation of audit log file location or user ID logging for all event types.
- Requirement: PARTIALLY SATISFIED — User ID is included in structured audit log events for authentication, but static evidence of log file storage, log format, and coverage for all event types is incomplete from provided files.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of privilege grant operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not privilege grants.
- etc/atlas/config.yaml: No configuration for privilege management or audit logging of privilege grants.
- Requirement: NOT SATISFIED — No static evidence of privilege grant operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of security object access operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not access to security objects.
- etc/atlas/config.yaml: No configuration for security object access or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of security object access operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of security level access operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not access to security levels.
- etc/atlas/config.yaml: No configuration for security level access or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of security level access operations or audit logging for such events.

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
- Control requires audit records for access to categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and etc/atlas/config.yaml: No evidence of data compartmentalization, classification levels, or protected categories of information.
- No code or configuration for data classification or category-based access control.
- Requirement: NOT APPLICABLE — Application does not implement or require compartmentalized data or classification levels.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of privilege modification operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not privilege modifications.
- etc/atlas/config.yaml: No configuration for privilege modification or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of privilege modification operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of security object modification operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not security object modifications.
- etc/atlas/config.yaml: No configuration for security object modification or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of security object modification operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of security level modification operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not security level modifications.
- etc/atlas/config.yaml: No configuration for security level modification or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of security level modification operations or audit logging for such events.

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
- Control requires audit records for modification of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and etc/atlas/config.yaml: No evidence of data compartmentalization, classification levels, or protected categories of information.
- No code or configuration for data classification or category-based access control.
- Requirement: NOT APPLICABLE — Application does not implement or require compartmentalized data or classification levels.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of privilege deletion operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not privilege deletions.
- etc/atlas/config.yaml: No configuration for privilege deletion or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of privilege deletion operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of security level deletion operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not security level deletions.
- etc/atlas/config.yaml: No configuration for security level deletion or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of security level deletion operations or audit logging for such events.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of database security object deletion operations or corresponding audit log entries for such events.
- security/middleware.py: Only authentication and scope checks are audited, not database security object deletions.
- etc/atlas/config.yaml: No configuration for database security object deletion or audit logging of such events.
- Requirement: NOT SATISFIED — No static evidence of database security object deletion operations or audit logging for such events.

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
- Control requires audit records for deletion of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and etc/atlas/config.yaml: No evidence of data compartmentalization, classification levels, or protected categories of information.
- No code or configuration for data classification or category-based access control.
- Requirement: NOT APPLICABLE — Application does not implement or require compartmentalized data or classification levels.

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
- File: security/middleware.py — BearerMiddleware logs all authentication attempts:
- `_audit("auth_grant", ...)` on successful authentication
- `_audit("auth_deny", ...)` on failed authentication (invalid/missing/expired token)
- Log events include `sub` (user ID), `client_ip`, `method`, `path`, and status.
- File: security/audit_log.py (not included) — referenced for `_audit` function, but actual log file location and format not visible in provided files.
- Requirement: PARTIALLY SATISFIED — Authentication events are audited, but static evidence of log file storage, log format, and coverage for all logon mechanisms is incomplete from provided files.

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
- File: security/middleware.py — Only authentication and scope checks are audited; no evidence of privileged activity (e.g., admin actions, system-level changes) audit logging.
- core/facet.py: MCPSpec supports `required_scope` for tool-level scope enforcement, but no evidence of audit logging for privileged tool invocations.
- README.md: No documentation of privileged activity audit logging.
- Requirement: NOT SATISFIED — No static evidence of privileged activity or system-level access audit logging.

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
- File: security/middleware.py — BearerMiddleware logs authentication events, but no evidence of explicit session start/end audit records.
- core/facet.py: Chronicle class tracks `connection_time` and `last_activity`, but no evidence these are logged to audit records.
- README.md: No documentation of session start/end audit logging.
- Requirement: NOT SATISFIED — No static evidence of session start/end time audit logging.

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
- No static evidence found in README.md, core/facet.py, core/project_resource.py, or security/middleware.py of audit logging for application object access.
- security/middleware.py: Only authentication and scope checks are audited.
- etc/atlas/config.yaml: No configuration for object access audit logging.
- Requirement: NOT SATISFIED — No static evidence of application object access audit logging.

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
- Control requires audit records for all direct access to the information system (e.g., OS commands, file system navigation), but only if the application implements such features.
- README.md and codebase: No evidence of features allowing direct OS access, command execution, or file system manipulation by users.
- Application is a code analysis and MCP tool server, not a shell or OS access gateway.
- Requirement: NOT APPLICABLE — Application does not provide direct access to the underlying OS or system resources.

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
- README.md: User authentication is via OIDC/OAuth2; no evidence of local user account management.
- etc/atlas/config.yaml: Security configuration references OIDC issuer and audience, but no local user management or audit logging for account lifecycle events.
- security/middleware.py: Only authentication events are audited, not account management events.
- Requirement: NOT SATISFIED — No static evidence of user account creation, modification, disabling, or termination audit logging.

Remediation:
Configure the application to log user account creation, modification, disabling, and termination events.

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Application must initiate session auditing (logging) upon startup.
- File: README.md — Logging is referenced as 'Clio' is the centralized logging library (see 'Supporting Libraries: Clio (lib/clio.py) - Centralized logging with deterministic test output').
- File: core/facet.py — Facet base class and plugins use a logger (Clio) for logging, e.g., 'self.logger.info("FacetMyTool initialized")' and 'self.logger.info("AdviceFacet initialized")'.
- File: plugins/advice.py — AdviceFacet logs initialization: 'self.logger.info("AdviceFacet initialized")' in _initialize().
- File: core/kb.py — KnowledgeBase logs initialization: 'self.logger.info("KnowledgeBase initialized")'.
- File: core/project_resource.py — ProjectRegistry logs initialization: 'self.logger.info("ProjectRegistry initialized")'.
- However, there is no explicit evidence of a log entry specifically indicating 'application startup' or a dedicated startup event being logged at the very beginning of application execution (e.g., in midas.py or a main entrypoint).
- Requirement: PARTIALLY SATISFIED — Logging infrastructure is present and components log their own initialization, but there is no static evidence that a top-level application startup event is logged as soon as the application starts. Evidence of a log entry like 'Application started' or similar at process start is missing.

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
- Control requires: Application must log shutdown events.
- File: core/facet.py — Facet base class provides a shutdown() method, which sets self._initialized = False. Subclasses may override this for cleanup.
- File: plugins/advice.py — AdviceFacet overrides shutdown(): 'self.logger.info("AdviceFacet shutting down")'.
- File: core/project_resource.py — No explicit shutdown logging found.
- File: core/kb.py — No explicit shutdown logging found.
- File: README.md — No mention of shutdown logging.
- There is no evidence of a global application shutdown event being logged (e.g., in midas.py or a main entrypoint). Only some plugin facets log their own shutdown, but not the application as a whole.
- Requirement: PARTIALLY SATISFIED — Some facets log their own shutdown, but there is no static evidence that the application logs a shutdown event at the system or process level.

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
- Control requires: Application must log destination IP addresses for outbound connections.
- File: README.md — No mention of logging destination IP addresses.
- File: core/project_resource.py — ProjectResource and ProjectRegistry manage resources, including remote Git repositories, but do not log destination IP addresses.
- File: security/middleware.py — Middleware logs authentication events, but not outbound connections or destination IPs.
- File: etc/atlas/config.yaml — No configuration for logging destination IPs.
- No static evidence found of any logging statement or configuration that records the destination IP address of remote systems the application connects to (e.g., for Git, GitHub, or other services).
- Requirement: NOT SATISFIED — No evidence that destination IP addresses are logged for outbound connections.

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
- Control requires: Application must log user actions involving access to data.
- File: README.md — No mention of audit logging for data access.
- File: core/project_resource.py — ProjectResource provides get_state(), get_history(), and get_contributions(), but there is no evidence of logging user access events.
- File: plugins/advice.py — AdviceFacet logs tool invocations (e.g., 'self.logger.info(f"Advice request from client {chronicle.client_id} ...")'), but this is for knowledge queries, not general data access.
- File: security/middleware.py — Middleware logs authentication events, not data access.
- No evidence found of audit records being generated for user access to protected data elements.
- Requirement: NOT SATISFIED — No static evidence that user data access events are logged.

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
- Control requires: Application must log user actions involving changes to data.
- File: core/project_resource.py — ProjectResource and ProjectRegistry track resource state and history (e.g., commits, issue updates), but there is no evidence of logging user actions that change data.
- File: plugins/advice.py — AdviceFacet logs knowledge contributions ('self.logger.info(f"Knowledge contribution from client {chronicle.client_id}")'), but this is limited to the advice facet and not general data changes.
- File: security/middleware.py — No logging of data modification events.
- No evidence found of audit records being generated for user-initiated data changes (e.g., CRUD operations).
- Requirement: NOT SATISFIED — No static evidence that user data modification events are logged.

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Audit records must contain date and time of events.
- File: plugins/advice.py — Logging statements use 'self.logger.info(...)', but the format of log output is determined by the Clio logger (lib/clio.py, not present in context). No evidence in this context that timestamps are included in log output.
- File: core/project_resource.py — No explicit timestamp in logging statements.
- File: security/middleware.py — Audit logs (e.g., '_audit("auth_grant", ...)') and JSONResponse logs, but the timestamp format is not shown in this context.
- File: README.md — No explicit mention of log format or timestamp inclusion.
- Requirement: PARTIALLY SATISFIED — Logging is present, but there is no static evidence that log entries include date and time. The log format of Clio is not shown in the provided files.

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Audit records must indicate which component, feature, or function triggered the event.
- File: plugins/advice.py — Logging statements include the facet name (e.g., 'AdviceFacet'), and log messages often include the tool name or action (e.g., 'Advice request from client ... for query ...').
- File: core/project_resource.py — Logging statements include the class name (e.g., 'ProjectRegistry initialized', 'Registered resource: ... (type: ...)').
- File: security/middleware.py — Audit logs include event type (e.g., 'auth_grant', 'auth_deny'), method, path, and client_ip.
- However, there is no evidence of a consistent log field or structure that always records the triggering component, feature, or function for all audit events.
- Requirement: PARTIALLY SATISFIED — Some log entries include component or feature names, but there is no static evidence that all audit records consistently include this information.

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
- Control requires: When using centralized logging, application must include a unique identifier to distinguish itself from other application logs.
- File: README.md — Clio is described as 'Centralized logging with deterministic test output', but there is no mention of a unique application identifier in log output.
- File: core/facet.py — Logger is instantiated with the facet name (e.g., 'facet_{self.name}'), which may appear in logs, but this is not a global application identifier.
- File: etc/atlas/config.yaml — No configuration for centralized logging or unique application identifier in logs.
- No evidence found of a unique application identifier (e.g., application name, host, or client name) being included in log records for centralized logging.
- Requirement: NOT SATISFIED — No static evidence that logs include a unique identifier for the application in a centralized logging context.

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
- Control requires: Audit records must contain information to establish the outcome of events (e.g., SUCCESS, ERROR).
- File: plugins/advice.py — Logging statements indicate actions (e.g., 'Successfully created context record ...'), but these are not structured audit records and do not consistently record the outcome of all operations.
- File: core/project_resource.py — Logging statements indicate actions (e.g., 'Registered resource: ...'), but do not explicitly record operation outcomes (success/failure) in a structured way.
- File: security/middleware.py — Audit logs include 'auth_grant' and 'auth_deny' events, which indicate outcome for authentication events.
- No evidence found of a consistent, structured outcome field in audit records for all application events.
- Requirement: PARTIALLY SATISFIED — Some events (authentication) log outcomes, but there is no static evidence that all audit records include event outcomes.

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Audit records must contain the identity of any individual or process associated with the event.
- File: plugins/advice.py — Logging statements include 'client_id' from the Chronicle object (e.g., 'Advice request from client {chronicle.client_id} ...').
- File: core/project_resource.py — No evidence of user or process identity being logged in resource actions.
- File: security/middleware.py — Audit logs include 'sub' (subject) from the verified token for authentication events.
- File: core/facet.py — Chronicle holds 'client_id', but it is not clear if this is always logged for all events.
- Requirement: PARTIALLY SATISFIED — Some events (advice facet, authentication) include user/process identity, but there is no static evidence that all audit records include this information for all relevant events.

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
- Control requires: Audit records must contain the full-text recording of privileged commands or the individual identities of group account users.
- File: README.md — No mention of privileged command logging or group account user identification.
- File: plugins/advice.py — No evidence of privileged command logging.
- File: core/project_resource.py — No evidence of privileged command logging or group account user identification.
- File: security/middleware.py — No evidence of privileged command logging.
- Requirement: NOT SATISFIED — No static evidence that privileged commands or group account user identities are logged.

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
- Control requires: Application must implement transaction recovery logs when transaction based.
- File: README.md — No evidence that the application is transaction-based (e.g., no database transaction management or ACID transaction system).
- File: core/project_resource.py — ProjectResource tracks project state and history, but not transactional operations.
- File: etc/atlas/config.yaml — No configuration for transaction logging.
- The application is not architected as a transactional system (no evidence of database transaction management or transaction recovery logs).
- Requirement: NOT APPLICABLE — This application is not transaction-based; transaction recovery logs do not apply.

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
- Control requires: Application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.
- File: etc/atlas/config.yaml — Centralized configuration for facets and plugins, but no evidence of centralized log management or configuration of audit record content.
- File: README.md — No mention of centralized log management or configuration interface for audit records.
- File: core/facet.py, core/kb.py — No evidence of centralized log management.
- Requirement: NOT SATISFIED — No static evidence that the application provides centralized management/configuration of audit record content.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Application must off-load audit records onto a different system or media than the system being audited (unless using centralized logging).
- File: README.md — No mention of log offloading or centralized logging solution.
- File: etc/atlas/config.yaml — No configuration for log offloading or centralized logging.
- File: core/facet.py, core/kb.py — No evidence of log offloading.
- Requirement: NOT SATISFIED — No static evidence that audit records are off-loaded to a different system or media.

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
- Control requires: Application must be configured to write application logs to a centralized log repository.
- File: README.md — Clio is described as 'Centralized logging with deterministic test output', but there is no evidence of configuration for a centralized log repository.
- File: etc/atlas/config.yaml — No configuration for centralized log repository.
- File: core/facet.py, core/kb.py — No evidence of centralized log repository configuration.
- Requirement: NOT SATISFIED — No static evidence that logs are written to a centralized log repository.

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Application must provide an immediate warning to the SA and ISSO when audit record storage volume reaches 75% of capacity (unless using centralized logging with alarming).
- File: README.md — No mention of log storage capacity monitoring or alarming.
- File: etc/atlas/config.yaml — No configuration for log storage capacity monitoring or alarming.
- File: core/facet.py, core/kb.py — No evidence of log storage capacity monitoring or alarming.
- Requirement: NOT SATISFIED — No static evidence that the application monitors log storage capacity or sends alarms at 75% utilization.

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Application must provide an immediate real-time alert to the SA and ISSO for all audit failure events (unless using centralized logging with alarming).
- File: README.md — No mention of audit failure alarming.
- File: etc/atlas/config.yaml — No configuration for audit failure alarming.
- File: core/facet.py, core/kb.py — No evidence of audit failure alarming.
- Requirement: NOT SATISFIED — No static evidence that the application provides real-time alerts for audit failure events.

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
- Static repository review completed on 2026-04-30.
- Control requires: Application must alert the ISSO and SA in the event of an audit processing failure (unless using centralized logging with alarming).
- File: README.md — No mention of audit processing failure alarming.
- File: etc/atlas/config.yaml — No configuration for audit processing failure alarming.
- File: core/facet.py, core/kb.py — No evidence of audit processing failure alarming.
- Requirement: NOT SATISFIED — No static evidence that the application alerts on audit processing failure.

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
- Control requires: Application must shut down by default upon audit failure (unless availability is an overriding concern, or compensating controls are in place).
- File: README.md — No mention of application shutdown on audit failure or compensating controls.
- File: etc/atlas/config.yaml — No configuration for shutdown on audit failure.
- File: core/facet.py, core/kb.py — No evidence of shutdown logic tied to audit failure.
- Requirement: NOT SATISFIED — No static evidence that the application shuts down or compensates for audit failure.

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
- Control requires: Application must provide the capability to centrally review and analyze audit records from multiple components within the system (unless using centralized logging).
- File: README.md — No mention of centralized audit review or analysis capability.
- File: etc/atlas/config.yaml — No configuration for centralized audit review.
- File: core/facet.py, core/kb.py — No evidence of centralized audit review capability.
- Requirement: NOT SATISFIED — No static evidence that the application provides centralized review/analysis of audit records from multiple components.

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
- Control requires the application to provide filtering of audit records based on criteria such as user, event type, date/time, system resource, IP, object, event level, and keywords.
- File: core/project_resource.py — ProjectRegistry class provides methods for resource and project management, but no explicit audit log filtering capability is implemented in this file.
- File: README.md — No mention of audit log filtering or user-facing audit log search/filtering features.
- File: etc/atlas/config.yaml — No configuration for audit log filtering or audit log management utilities.
- No evidence of a log management utility or MCP tool for filtering audit records by the required criteria.
- Requirement: PARTIALLY SATISFIED — Project/resource management is present, but there is no static evidence of audit log filtering capability as required by the control.

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
- Control requires audit reduction (filtering) and on-demand reporting based on filtered audit events.
- File: core/project_resource.py — No MCP tool or method for generating on-demand audit reports based on filtered audit event data.
- File: README.md — No documentation of audit reduction or reporting features for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit log reporting or reduction.
- No static evidence of a reporting feature for audit logs or audit reduction capability.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or on-demand reporting for audit logs.

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
- Control requires audit reduction capability for on-demand audit review and analysis.
- File: core/project_resource.py — No methods or MCP tools for audit reduction or on-demand audit review/analysis.
- File: README.md — No mention of audit reduction or audit review features for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit reduction or audit review.
- No static evidence of audit reduction or on-demand audit review/analysis for audit logs.
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
- Control requires audit reduction (event filtering) to support after-the-fact investigations.
- File: core/project_resource.py — No audit reduction or filtering methods for audit logs.
- File: README.md — No documentation of audit reduction or filtering for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit reduction or filtering for audit logs.
- No static evidence of audit reduction or filtering for after-the-fact investigations of audit logs.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or filtering for audit logs.

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
- Control requires report generation capability for on-demand audit review and analysis.
- File: core/project_resource.py — No MCP tool or method for generating audit reports.
- File: README.md — No documentation of audit report generation for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit report generation for audit logs.
- No static evidence of audit report generation for audit logs.
- Requirement: NOT SATISFIED — No static evidence of audit report generation for audit logs.

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
- Control requires customizable, immediate, ad-hoc audit log reporting.
- File: core/project_resource.py — No MCP tool or method for customizable, immediate, ad-hoc audit log reporting.
- File: README.md — No documentation of customizable audit log reporting.
- File: etc/atlas/config.yaml — No configuration for audit log reporting.
- No static evidence of customizable, immediate, ad-hoc audit log reporting.
- Requirement: NOT SATISFIED — No static evidence of customizable, immediate, ad-hoc audit log reporting.

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
- Control requires report generation capability for after-the-fact investigations of security incidents.
- File: core/project_resource.py — No MCP tool or method for generating audit reports for after-the-fact investigations.
- File: README.md — No documentation of audit report generation for after-the-fact investigations.
- File: etc/atlas/config.yaml — No configuration for audit report generation for after-the-fact investigations.
- No static evidence of audit report generation for after-the-fact investigations of audit logs.
- Requirement: NOT SATISFIED — No static evidence of audit report generation for after-the-fact investigations.

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
- Control requires audit reduction (event filtering) that does not alter original content or time ordering of audit records.
- File: core/project_resource.py — No audit reduction or filtering methods for audit logs; no evidence of filtering implementation.
- File: README.md — No documentation of audit reduction or filtering for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit reduction or filtering for audit logs.
- No static evidence of audit reduction or filtering for audit logs, so cannot confirm or deny alteration of original content/time ordering.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or filtering for audit logs.

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
- Control requires report generation capability that does not alter original content or time ordering of audit records.
- File: core/project_resource.py — No audit report generation methods for audit logs; no evidence of filtering implementation.
- File: README.md — No documentation of audit report generation for audit logs.
- File: etc/atlas/config.yaml — No configuration for audit report generation for audit logs.
- No static evidence of audit report generation for audit logs, so cannot confirm or deny alteration of original content/time ordering.
- Requirement: NOT SATISFIED — No static evidence of audit report generation for audit logs.

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
- Control requires audit records to use internal system clocks for timestamps.
- File: core/project_resource.py — Timestamps for project/resource events (e.g., created_at, checked_at) are generated using datetime.now(UTC).isoformat(), e.g.:
- 'created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())'
- 'checked_at: str  # ISO timestamp of when check was performed'
- File: lib/ingestion/state.py — IngestionRecord and StalenessResult use datetime.now().isoformat() for completed_at and last_ingested_at.
- These usages indicate that system time is used for resource/project events, but there is no explicit evidence that audit log events (if any) use system time for their timestamps.
- No audit log implementation is present in the provided files.
- Requirement: PARTIALLY SATISFIED — System time is used for resource/project events, but no evidence for audit log events.

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
- Control requires audit record timestamps to be mappable to UTC/GMT.
- File: core/project_resource.py — Timestamps are generated using datetime.now(UTC).isoformat(), which produces ISO 8601 UTC timestamps (e.g., '2024-06-10T12:34:56.789012+00:00').
- File: lib/ingestion/state.py — IngestionRecord uses datetime.now().isoformat(), which is local time unless explicitly set to UTC.
- Some timestamps are UTC, others may be local time depending on usage of datetime.now() vs datetime.now(UTC).
- No audit log implementation is present in the provided files.
- Requirement: PARTIALLY SATISFIED — UTC timestamps are used for some resource/project events, but no evidence for audit log events.

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
- Control requires audit record timestamps to have at least 1-second granularity.
- File: core/project_resource.py — Timestamps are generated using datetime.now(UTC).isoformat(), which includes seconds and microseconds.
- File: lib/ingestion/state.py — IngestionRecord uses datetime.now().isoformat(), which includes seconds and microseconds.
- No audit log implementation is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Timestamps for resource/project events have sufficient granularity, but no evidence for audit log events.

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
- Control requires audit information to be protected from unauthorized read access.
- File: core/project_resource.py — No audit log implementation or access control for audit data.
- File: etc/atlas/config.yaml — No configuration for audit log storage or access control.
- File: README.md — No documentation of audit log access control.
- No static evidence of audit log storage or access control for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log storage or access control.

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
- Control requires audit information to be protected from unauthorized modification.
- File: core/project_resource.py — No audit log implementation or access control for audit data.
- File: etc/atlas/config.yaml — No configuration for audit log storage or access control.
- File: README.md — No documentation of audit log access control.
- No static evidence of audit log storage or access control for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log storage or access control.

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
- Control requires audit information to be protected from unauthorized deletion.
- File: core/project_resource.py — No audit log implementation or access control for audit data.
- File: etc/atlas/config.yaml — No configuration for audit log storage or access control.
- File: README.md — No documentation of audit log access control.
- No static evidence of audit log storage or access control for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log storage or access control.

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
- Control applies only if the application provides a distinct audit tool oriented functionality (separate tool for viewing/manipulating log data).
- File: README.md — No mention of a distinct audit tool or audit tool submodule.
- File: core/project_resource.py — No audit tool implementation or audit tool access control.
- File: etc/atlas/config.yaml — No configuration for audit tool functionality.
- The application does not provide a distinct audit tool as described in the control.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality present.

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
- Control applies only if the application provides a distinct audit tool oriented functionality (separate tool for viewing/manipulating log data).
- File: README.md — No mention of a distinct audit tool or audit tool submodule.
- File: core/project_resource.py — No audit tool implementation or audit tool access control.
- File: etc/atlas/config.yaml — No configuration for audit tool functionality.
- The application does not provide a distinct audit tool as described in the control.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality present.

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
- Control applies only if the application provides a distinct audit tool oriented functionality (separate tool for viewing/manipulating log data).
- File: README.md — No mention of a distinct audit tool or audit tool submodule.
- File: core/project_resource.py — No audit tool implementation or audit tool access control.
- File: etc/atlas/config.yaml — No configuration for audit tool functionality.
- The application does not provide a distinct audit tool as described in the control.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality present.

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
- Control applies only if the application includes a built-in backup capability for its own audit records.
- File: README.md — No mention of audit log backup or backup scheduling.
- File: core/project_resource.py — No audit log backup implementation.
- File: etc/atlas/config.yaml — No configuration for audit log backup or backup scheduling.
- The application does not include a built-in backup capability for audit records.
- Requirement: NOT APPLICABLE — No built-in audit log backup capability present.

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
- Control requires cryptographic mechanisms (e.g., hash, message digest) to protect the integrity of audit information.
- File: core/project_resource.py — No audit log implementation or cryptographic integrity protection for audit data.
- File: etc/atlas/config.yaml — No configuration for cryptographic integrity protection of audit logs.
- File: README.md — No documentation of cryptographic integrity protection for audit logs.
- No static evidence of cryptographic integrity protection for audit logs.
- Requirement: NOT SATISFIED — No static evidence of cryptographic integrity protection for audit logs.

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
- Control requires the application to provide separate audit tools (executables or libraries) for viewing/manipulating logs, and that these tools are cryptographically hashed for integrity validation.
- File: README.md — No mention of separate audit tool executables or libraries for log viewing/manipulation; audit logging is referenced only as a code module (e.g., `security/audit_log.py`).
- File: pyproject.toml — No entry for a standalone audit tool or CLI for log manipulation.
- File: Makefile — No target for an audit tool; no mention of log viewing/manipulation utilities.
- File: core/facet.py — No implementation of a log viewer or manipulation tool; audit logging is internal only.
- File: etc/atlas/config.yaml — No configuration for a separate audit tool; audit logging is not exposed as a user-facing tool.
- The application does not provide a separate file-oriented audit tool for viewing or manipulating logs; all audit functionality is internal to the application codebase.
- Requirement: NOT APPLICABLE — No separate audit tool is provided by the application; control does not apply.

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
- Control requires periodic validation of cryptographic hashes for separate audit tool files (executables/libraries for log viewing/manipulation).
- File: README.md — No mention of a separate audit tool for logs; audit logging is internal.
- File: Makefile — No target for audit tool hash validation or integrity checking.
- File: pyproject.toml — No dependency or script for audit tool hash validation.
- File: etc/atlas/config.yaml — No configuration for audit tool hash validation.
- No evidence of a process or mechanism for periodic hash validation of audit tool files, as no such tools exist in the application.
- Requirement: NOT APPLICABLE — No separate audit tool is provided; periodic hash validation of audit tools does not apply.

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
- File: README.md — No mention of user-facing plugin/module installation capability; all extension points (facets/plugins) are developer-side only.
- File: pyproject.toml — No mechanism for runtime user installation of plugins/extensions; all dependencies are managed via package installation and developer configuration.
- File: Makefile — No target or command for user-initiated installation of plugins/extensions.
- File: core/facet.py — Plugins (facets) are registered via code, not user interface; no user-facing installation mechanism.
- File: etc/atlas/config.yaml — Plugin configuration is static and loaded at startup; no user-facing installation or extension mechanism.
- The application does not provide any UI or API for users to install software components, plugins, or extensions at runtime.
- Requirement: NOT APPLICABLE — Application does not provide user-facing software installation capability.

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
- File: etc/atlas/config.yaml — Main configuration file; no explicit file permission settings or access control mechanisms are defined in this YAML.
- File: README.md — Configuration is loaded from YAML files and environment variables; no mention of access control enforcement for configuration changes.
- File: Makefile — No target for managing configuration permissions.
- File: core/facet.py — No code for enforcing access restrictions on configuration changes; configuration is loaded at startup.
- No static evidence of OS-level file permissions or application-level access control for configuration files.
- Requirement: PARTIALLY SATISFIED — Configuration is file-based and not exposed via a user interface, but static analysis cannot confirm that file permissions restrict access to authorized users only. Evidence of access restriction is missing.

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
- Control requires audit logging of user accounts making configuration changes.
- File: etc/atlas/config.yaml — Configuration is file-based; no evidence of audit logging for configuration changes.
- File: README.md — No mention of audit logs for configuration changes; audit logging is referenced only for application events.
- File: security/audit_log.py (not included) — File name suggests audit logging exists, but content not available for review.
- No static evidence that configuration changes (file edits) are logged with user attribution.
- Requirement: PARTIALLY SATISFIED — Application uses file-based configuration, but no evidence that changes are logged with user attribution. Audit logging for configuration changes is not confirmed.

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
- Control requires the application to prevent installation of patches/components unless digitally signed or hash-verified.
- File: README.md — Installation and updates are performed via `pip install` and `make`; no mention of digital signature or hash verification for patches or components.
- File: Makefile — No target for verifying digital signatures or hashes of installed packages/components.
- File: pyproject.toml — No configuration for signature or hash verification of dependencies; dependencies are installed from PyPI or GitHub.
- No evidence of a mechanism to prevent installation of unsigned or unverified patches/components.
- Requirement: NOT SATISFIED — No static evidence of digital signature or hash verification for installed components.

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
- Control requires restriction of privileges to change software libraries.
- File: pyproject.toml — Libraries are installed via package management; no evidence of runtime privilege enforcement.
- File: Makefile — No target for managing library file permissions.
- File: README.md — No mention of runtime library update capability; all library changes are developer-side.
- File: etc/atlas/config.yaml — No configuration for restricting library update privileges.
- No static evidence of OS-level file permissions or application-level controls restricting write access to library files.
- Requirement: PARTIALLY SATISFIED — Libraries are managed via package installation, but static analysis cannot confirm file permission enforcement or privilege restriction for library updates.

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
- File: README.md — References static analysis (pyright, ruff, pip-audit) and CI/CD pipeline, but no explicit mention of vulnerability scanning or retention of scan results.
- File: .github/workflows/ci.yml — CI pipeline runs tests and static analysis, but no explicit step for vulnerability scanning or scan result retention.
- File: pyproject.toml — Includes `pip-audit` as a dev dependency (via athena), but no evidence of scan scheduling or result retention.
- No static evidence of a documented vulnerability scanning process or storage of scan results.
- Requirement: PARTIALLY SATISFIED — Static analysis tools are present, but full vulnerability assessment process and scan result retention are not confirmed.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of organization-defined policies restricting program execution.
- File: README.md — No mention of application-level execution restriction policies; application is a developer tool, not an end-user application subject to execution restriction.
- File: Makefile, pyproject.toml — No enforcement of execution policies; no integration with AppLocker, RBAC, or similar mechanisms.
- Application is a developer tool/library, not a managed end-user application; execution restriction policies are not applicable.
- Requirement: NOT APPLICABLE — Application type is not subject to execution restriction policies.

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
- Control requires a deny-all, permit-by-exception (whitelist) policy for execution of authorized software programs, applicable to configuration management or similar applications.
- File: README.md — Application is not a configuration management system; no mention of application whitelisting or execution control.
- File: pyproject.toml, Makefile — No mechanism for execution whitelisting.
- Application is not designed to manage system processes or restrict execution of other applications.
- Requirement: NOT APPLICABLE — Application is not a configuration management or execution control system.

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
- Control requires disabling non-essential application capabilities.
- File: etc/atlas/config.yaml — Features are enabled/disabled via configuration, e.g., `metrics_mode: false`, but no explicit list of non-essential capabilities or mechanism to disable them at runtime.
- File: README.md — Describes available facets and plugins, but no mention of a process for disabling unused features.
- File: Makefile — No target for disabling features.
- No static evidence of a mechanism to enumerate and disable non-essential capabilities beyond manual configuration edits.
- Requirement: PARTIALLY SATISFIED — Some features can be disabled via config, but no comprehensive mechanism for disabling all non-essential capabilities is documented.

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
- Control requires the application to use only PPSM CAL-approved ports, protocols, and functions.
- File: etc/atlas/config.yaml — Server port is set via `server_port: 8000` under `plugins.security`; OIDC IdP runs on `issuer_url: "http://localhost:8082/realms/midas-mcp"`.
- File: README.md — Default server listens on `http://localhost:8000`; dev IdP on `http://localhost:8080` or `8082`.
- File: Makefile — References `DEV_IDP_PORT`, `DEV_PORT`, but no enforcement of PPSM CAL compliance.
- No static evidence of validation against PPSM CAL or restriction to only approved ports/protocols.
- Requirement: PARTIALLY SATISFIED — Ports are statically configured, but compliance with PPSM CAL is not enforced or documented.

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
- Control requires reauthentication when user roles are changed or privileges escalated.
- File: etc/atlas/config.yaml — No configuration for reauthentication triggers on role change or privilege escalation.
- File: README.md — Authentication is via OIDC/OAuth2; no mention of reauthentication on role change.
- File: security/oauth_proxy.py — Implements OAuth2 proxy endpoints, but no evidence of reauthentication enforcement on role/privilege change.
- No static evidence of reauthentication enforcement for role changes or privilege escalation.
- Requirement: NOT SATISFIED — No evidence of reauthentication requirement on role/privilege change.

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
- Control requires devices (e.g., gateways, firewalls) to periodically reauthenticate.
- File: etc/atlas/config.yaml — No configuration for device reauthentication intervals.
- File: README.md — No mention of device authentication or reauthentication.
- File: security/oauth_proxy.py — Handles OAuth2 token issuance, but no evidence of device-specific reauthentication intervals.
- No static evidence of device reauthentication enforcement or interval configuration.
- Requirement: NOT SATISFIED — No evidence of device reauthentication enforcement.

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
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present (`issuer_url`, `mcp_audience`, etc.), but no explicit enforcement of unique user identification in application logic.
- File: README.md — Authentication is via OIDC/OAuth2; no mention of unique user account enforcement.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but does not show user uniqueness enforcement.
- No static evidence of unique user account enforcement or mapping of tokens to unique users.
- Requirement: PARTIALLY SATISFIED — OIDC/OAuth2 is used, which typically provides unique user identification, but static analysis cannot confirm enforcement in application logic.

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
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present; no mention of Alt. Token or multifactor authentication enforcement for privileged accounts.
- File: README.md — No mention of Alt. Token or multifactor authentication for privileged access.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but no evidence of Alt. Token or multifactor enforcement for privileged accounts.
- No static evidence of multifactor authentication enforcement for privileged accounts.
- Requirement: NOT SATISFIED — No evidence of Alt. Token or multifactor authentication enforcement for privileged accounts.

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
- Control requires acceptance of Personal Identity Verification (PIV) credentials (CAC).
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present; no mention of CAC/PIV credential acceptance.
- File: README.md — No mention of CAC/PIV authentication.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but no evidence of CAC/PIV credential handling.
- No static evidence of CAC/PIV credential acceptance or enforcement.
- Requirement: NOT SATISFIED — No evidence of CAC/PIV credential acceptance.

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
- Control requires electronic verification of PIV (CAC) credentials.
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present; no mention of CAC/PIV credential verification.
- File: README.md — No mention of CAC/PIV authentication or PIN verification.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but no evidence of CAC/PIV credential verification or PIN prompt.
- No static evidence of CAC/PIV credential verification.
- Requirement: NOT SATISFIED — No evidence of electronic verification of PIV credentials.

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
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present; no mention of CAC/Alt. Token or multifactor authentication enforcement for non-privileged accounts.
- File: README.md — No mention of CAC/Alt. Token or multifactor authentication for non-privileged access.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but no evidence of CAC/Alt. Token or multifactor enforcement for non-privileged accounts.
- No static evidence of multifactor authentication enforcement for non-privileged accounts.
- Requirement: NOT SATISFIED — No evidence of CAC/Alt. Token or multifactor authentication enforcement for non-privileged accounts.

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
- File: etc/atlas/config.yaml — OIDC/OAuth2 configuration present; no mention of Alt. Token or multifactor authentication enforcement for local privileged access.
- File: README.md — No mention of Alt. Token or multifactor authentication for local privileged access.
- File: security/oauth_proxy.py — Implements OAuth2 endpoints, but no evidence of Alt. Token or multifactor enforcement for local privileged accounts.
- No static evidence of multifactor authentication enforcement for local privileged accounts.
- Requirement: NOT SATISFIED — No evidence of Alt. Token or multifactor authentication enforcement for local privileged accounts.

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
- File: etc/keycloak/dev-realm.json — users are defined with password credentials only:
- "credentials": [{"type": "password", "value": "dev-password", "temporary": false}]
- No evidence of CAC, client certificate, or multifactor authentication configuration in Keycloak realm or application config.
- File: etc/atlas/config.yaml — security.issuer_url is set to a local Keycloak instance, but no MFA or PKI/CAC enforcement is present in the configuration.
- Requirement: NOT SATISFIED — Only password authentication is configured; no evidence of multifactor (CAC/Alt. Token) authentication.

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
- Control requires individual authentication before group authenticator use. Applies only if group/shared accounts are used.
- File: etc/keycloak/dev-realm.json — users are individually defined ("dev-user", "dev-admin"); no group/shared accounts present.
- File: etc/atlas/config.yaml — no configuration for group/shared accounts or group authenticators.
- Requirement: NOT APPLICABLE — Application does not use group or shared accounts.

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
- File: etc/keycloak/dev-realm.json — authentication uses password credentials; no evidence of Kerberos, IPSEC, SSH, or cryptographic signing of packets.
- File: etc/atlas/config.yaml — security.issuer_url uses HTTP ("http://localhost:8082/realms/midas-mcp"); no explicit TLS/SSL configuration or enforcement of TLS 1.2+.
- File: pyproject.toml — dependencies include PyJWT[crypto], but this is for JWT validation, not transport security.
- Requirement: PARTIALLY SATISFIED — JWT-based authentication is present, but no evidence of TLS 1.2+ or other replay-resistant transport mechanisms. Passwords are used for privileged accounts, and HTTP is used for issuer URL.

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
- File: etc/keycloak/dev-realm.json — nonprivileged users authenticate with passwords; no evidence of Kerberos, IPSEC, SSH, or cryptographic signing of packets.
- File: etc/atlas/config.yaml — security.issuer_url uses HTTP ("http://localhost:8082/realms/midas-mcp"); no explicit TLS/SSL configuration or enforcement of TLS 1.2+.
- Requirement: PARTIALLY SATISFIED — JWT-based authentication is present, but no evidence of TLS 1.2+ or other replay-resistant transport mechanisms. Passwords are used for nonprivileged accounts, and HTTP is used for issuer URL.

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
- Control requires mutual authentication (e.g., two-way SSL/TLS with client certificates) when mandated by policy or data owner.
- File: etc/atlas/config.yaml — no configuration for mutual authentication or client certificate enforcement.
- File: etc/keycloak/dev-realm.json — no evidence of client certificate requirements or mutual authentication settings.
- Requirement: PARTIALLY SATISFIED — OIDC authentication is present, but no evidence of mutual authentication (client certificates) in application or IdP configuration.

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
- Control requires authentication of all network-connected endpoint devices before establishing any connection; Basic Authentication is not allowed.
- File: etc/atlas/config.yaml — no explicit device authentication mechanism is configured; authentication is user-based via OIDC/Keycloak.
- File: etc/keycloak/dev-realm.json — only user credentials (passwords) are defined; no device authentication or client certificate configuration.
- Requirement: PARTIALLY SATISFIED — User authentication is enforced, but no evidence of device authentication or prohibition of Basic Authentication for devices.

Remediation:
Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only to Service-Oriented Applications handling non-releasable data and requires mutual SSL/TLS authentication for endpoint devices.
- File: README.md — application is described as a developer tool for code analysis and migration, not a service-oriented application handling non-releasable data.
- File: etc/atlas/config.yaml — no indication of non-releasable data or SOA endpoints requiring mutual SSL/TLS.
- Requirement: NOT APPLICABLE — Application is not a service-oriented application handling non-releasable data.

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
- Control applies only if the application authenticates devices (e.g., mobile phones, gateways, smart devices) or does not use DOD PKI certificates.
- File: etc/keycloak/dev-realm.json — only user accounts are defined; no device accounts or device authentication present.
- File: etc/atlas/config.yaml — no configuration for device authentication or device IDs.
- Requirement: NOT APPLICABLE — Application does not authenticate devices.

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
- File: etc/keycloak/dev-realm.json — user credentials are defined with plaintext passwords (e.g., "dev-password"), but no password policy is specified.
- File: etc/atlas/config.yaml — no password policy or minimum length enforcement is configured for Keycloak or the application.
- Requirement: NOT SATISFIED — No evidence of password length enforcement.

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
- File: etc/keycloak/dev-realm.json — user credentials are defined with plaintext passwords; no password policy or complexity enforcement is specified.
- File: etc/atlas/config.yaml — no password complexity policy is configured.
- Requirement: NOT SATISFIED — No evidence of password complexity enforcement (uppercase character).

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
- File: etc/keycloak/dev-realm.json — user credentials are defined with plaintext passwords; no password policy or complexity enforcement is specified.
- File: etc/atlas/config.yaml — no password complexity policy is configured.
- Requirement: NOT SATISFIED — No evidence of password complexity enforcement (lowercase character).

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
- File: etc/keycloak/dev-realm.json — user credentials are defined with plaintext passwords; no password policy or complexity enforcement is specified.
- File: etc/atlas/config.yaml — no password complexity policy is configured.
- Requirement: NOT SATISFIED — No evidence of password complexity enforcement (numeric character).

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
- File: etc/keycloak/dev-realm.json — user credentials are defined with plaintext passwords; no password policy or complexity enforcement is specified.
- File: etc/atlas/config.yaml — no password complexity policy is configured.
- Requirement: NOT SATISFIED — No evidence of password complexity enforcement (special character).

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
- Control requires that at least eight characters change when passwords are changed.
- File: etc/keycloak/dev-realm.json — no password change policy or enforcement of changed character count is present.
- File: etc/atlas/config.yaml — no password change policy is configured.
- Requirement: NOT SATISFIED — No evidence of password change character difference enforcement.

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
- Control requires that only cryptographic representations of passwords are stored (no plaintext, no MD5).
- File: etc/keycloak/dev-realm.json — user credentials are stored as plaintext values ("value": "dev-password").
- File: etc/atlas/config.yaml — no evidence of cryptographic password storage or hash algorithm configuration.
- Requirement: NOT SATISFIED — Passwords are stored in plaintext in the Keycloak realm file.

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
- Control requires that passwords are transmitted only over cryptographically protected channels (e.g., TLS/SSL).
- File: etc/keycloak/dev-realm.json — authentication is via password, but no evidence of enforced TLS/SSL for transmission.
- File: etc/atlas/config.yaml — security.issuer_url uses HTTP ("http://localhost:8082/realms/midas-mcp"); no explicit TLS/SSL configuration.
- Requirement: NOT SATISFIED — No evidence that password transmission is protected by TLS/SSL.

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
- File: etc/keycloak/dev-realm.json — no password lifetime policy is specified.
- File: etc/atlas/config.yaml — no password lifetime enforcement is configured.
- Requirement: NOT SATISFIED — No evidence of minimum password lifetime enforcement.

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
- File: etc/keycloak/dev-realm.json — no password expiration policy is specified.
- File: etc/atlas/config.yaml — no password expiration enforcement is configured.
- Requirement: NOT SATISFIED — No evidence of maximum password lifetime enforcement.

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
- File: etc/keycloak/dev-realm.json — no password history or reuse policy is specified.
- File: etc/atlas/config.yaml — no password reuse policy is configured.
- Requirement: NOT SATISFIED — No evidence of password reuse prohibition.

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
- Control requires support for temporary passwords with forced change on first logon.
- File: etc/keycloak/dev-realm.json — user credentials have "temporary": false; no evidence of temporary password support or forced change on first use.
- File: etc/atlas/config.yaml — no configuration for temporary passwords or forced password change on first use.
- Requirement: NOT SATISFIED — No evidence of temporary password support or forced change on first logon.

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
- The application does not implement any user password management or password reset/change functionality in the provided codebase or configuration.
- File: README.md — No mention of user password change/reset features; authentication is handled via OIDC/OAuth2 (see 'Run the server with dev authentication' and 'For production or when using an external IdP...').
- File: etc/atlas/config.yaml — Security configuration is for OAuth2/OIDC (issuer_url, mcp_audience, introspection_client_id), not for local password management.
- File: pyproject.toml — No dependencies for password management or user account modules.
- File: security/oauth_proxy.py — Implements OAuth2 proxy endpoints, no password change/reset endpoints.
- No code or configuration for user password storage or change processes found in any provided file.
- Requirement: NOT APPLICABLE — Application does not utilize passwords; authentication is delegated to external IdP via OAuth2/OIDC.

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
- The application provides project resource and user/session management for code/project resources, but there is no evidence of user account deletion or session termination logic tied to user deletion.
- File: core/project_resource.py — ProjectResource and ProjectRegistry manage project and resource registration, but not user accounts or sessions.
- File: README.md — No mention of user account deletion or session termination upon account deletion; authentication is handled via external IdP.
- File: etc/atlas/config.yaml — No configuration for user account deletion or session termination.
- File: security/oauth_proxy.py — Handles OAuth2 proxy endpoints, not user account management.
- No static artifact found that terminates sessions upon account deletion.
- Requirement: PARTIALLY SATISFIED — Application does not appear to manage user accounts directly, but session termination on account deletion cannot be confirmed from static artifacts.

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
- The application supports PKI-based authentication via OAuth2/OIDC, but there is no static evidence of certificate path validation to a trust anchor.
- File: etc/atlas/config.yaml — Security config uses issuer_url and mcp_audience for OIDC/OAuth2; no explicit certificate validation settings.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints but does not implement certificate path validation logic; relies on upstream IdP.
- File: README.md — Authentication is delegated to external IdP (OIDC/OAuth2), no mention of certificate validation implementation.
- No code found that constructs or validates certificate chains or revocation status.
- Requirement: PARTIALLY SATISFIED — PKI-based authentication is supported via OIDC/OAuth2, but certificate path validation to a trust anchor is not statically verifiable.

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
- The application may use private keys for OAuth2/OIDC (e.g., JWT signing), but there is no static evidence of private key storage or access control enforcement.
- File: etc/atlas/config.yaml — No private key paths or permissions specified for application cryptographic keys; GitHub App private_key_path is only for GitHub API access, not application authentication.
- File: security/oauth_proxy.py — No code for private key storage or access control; proxies OAuth2 endpoints.
- File: plugins/github_issue_fetcher.py — private_key_path is used for GitHub App authentication, not for application PKI.
- No file permissions or access control logic for private keys found in provided files.
- Requirement: PARTIALLY SATISFIED — Application may use private keys for external integrations, but enforcement of authorized access to private keys is not statically verifiable.

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
- The application delegates authentication to external IdPs via OAuth2/OIDC, but there is no static evidence of mapping authenticated PKI identities to individual users or groups within the application.
- File: etc/atlas/config.yaml — Security config references issuer_url and mcp_audience, but no mapping logic for PKI identities.
- File: security/oauth_proxy.py — Proxies OAuth2 endpoints, does not map certificate data to user accounts.
- File: README.md — Authentication is handled externally; no mention of user mapping from PKI credentials.
- No code found that maps certificate data to application user or group accounts.
- Requirement: PARTIALLY SATISFIED — Application relies on external IdP for authentication, but mapping of PKI identities to users/groups is not statically verifiable.

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
- No evidence found of a local cache of certificate revocation data (CRL) or fallback to CRL when OCSP is unavailable.
- File: etc/atlas/config.yaml — No configuration for CRL, OCSP, or revocation data caching.
- File: security/oauth_proxy.py — No code for certificate revocation checking or CRL import.
- File: README.md — No mention of certificate revocation or CRL/OCSP handling.
- Requirement: NOT SATISFIED — No static artifact for CRL caching or revocation checking found.

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
- The application does not implement any user interface for password or PIN entry; authentication is handled via OAuth2/OIDC with external IdP.
- File: README.md — Authentication is delegated to external IdP; no password entry UI or feedback implemented in application.
- File: etc/atlas/config.yaml — No password/PIN entry configuration.
- File: security/oauth_proxy.py — No password/PIN entry or display logic.
- Requirement: NOT APPLICABLE — Application does not display passwords or PINs; authentication is external.

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
- The application uses cryptographic modules for OAuth2/OIDC and possibly for JWT validation, but there is no static evidence that these modules are FIPS-approved.
- File: pyproject.toml — Dependencies include 'cryptography', 'PyJWT[crypto]', 'onnxruntime', but no explicit FIPS mode or module validation.
- File: etc/atlas/config.yaml — No configuration for FIPS mode or approved cryptographic modules.
- File: security/oauth_proxy.py — No code for enforcing FIPS-approved modules.
- Requirement: PARTIALLY SATISFIED — Cryptographic modules are used, but FIPS approval is not statically verifiable.

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
- The application supports authentication via OAuth2/OIDC, but there is no static evidence of unique identification and authentication of non-organizational users.
- File: etc/atlas/config.yaml — Security config for OAuth2/OIDC, but no user account management or unique user identification logic.
- File: README.md — Authentication is handled externally; no user account assignment or documentation in application.
- File: security/oauth_proxy.py — No user account management or unique identification logic.
- Requirement: PARTIALLY SATISFIED — Authentication is required, but unique identification of non-organizational users is not statically verifiable.

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
- No evidence found that the application accepts PIV credentials from other federal agencies.
- File: etc/atlas/config.yaml — Security config for OAuth2/OIDC, but no mention of PIV credential acceptance or configuration for Federal agency IdPs.
- File: README.md — No mention of PIV credential support.
- File: security/oauth_proxy.py — No code for PIV credential handling.
- Requirement: NOT SATISFIED — No static artifact for PIV credential acceptance found.

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
- No evidence found that the application electronically verifies PIV credentials from other federal agencies.
- File: etc/atlas/config.yaml — No configuration for PIV credential verification or Federal PKI trust anchors.
- File: README.md — No mention of PIV credential verification.
- File: security/oauth_proxy.py — No code for PIV credential verification.
- Requirement: NOT SATISFIED — No static artifact for PIV credential verification found.

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
- No evidence found that the application accepts FICAM-approved third-party credentials.
- File: etc/atlas/config.yaml — No configuration for FICAM-approved credential providers or trust anchors.
- File: README.md — No mention of FICAM credential support.
- File: security/oauth_proxy.py — No code for FICAM credential handling.
- Requirement: NOT SATISFIED — No static artifact for FICAM-approved credential acceptance found.

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
- No evidence found that the application conforms to FICAM-issued profiles (e.g., SAML, OpenID profiles).
- File: etc/atlas/config.yaml — Security config for OAuth2/OIDC, but no explicit FICAM profile conformance or configuration.
- File: README.md — No mention of FICAM profile conformance.
- File: security/oauth_proxy.py — No code for FICAM profile enforcement.
- Requirement: NOT SATISFIED — No static artifact for FICAM profile conformance found.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- The application does not provide non-local maintenance or diagnostic session capabilities.
- File: README.md — No mention of remote maintenance or diagnostic sessions; application is a code analysis and AI assistant backend.
- File: etc/atlas/config.yaml — No configuration for remote maintenance or diagnostic sessions.
- File: core/project_resource.py — Project/resource management is for code/project resources, not system maintenance.
- Requirement: NOT APPLICABLE — Application does not provide non-local maintenance sessions.

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
- No static evidence found of race condition analysis or mitigation in the application codebase.
- File: README.md — No mention of race condition testing or analysis tools.
- File: pyproject.toml — No dependencies for static/dynamic race condition analysis tools.
- File: Makefile — No test target for race condition analysis.
- File: core/facet.py, core/project_resource.py — No explicit locking or concurrency control mechanisms; some use of queue.Queue, but no race condition mitigation logic.
- Requirement: NOT SATISFIED — No static artifact for race condition analysis or mitigation found.

Remediation:
Be aware of potential timing issues related to application programming calls when designing and building the application.

Validate that variable values do not change while a switch event is occurring.

---

### 181. APSC-DV-002000 | SV-222568r961068

- Rule ID: SV-222568r961068
- Severity: medium
- Rule Title: The application must terminate all network connections associated with a communications session at the end of the session.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application is a stateless MCP tool server and AI code analysis platform, not a traditional web application with persistent user sessions or long-lived network connections per user session.
- File: README.md — 'MIDAS is a flexible and extensible product designed to help migrate and modernize legacy software projects...'
- File: README.md — 'MIDAS uses a three-layer architecture for intelligent tools', describing stateless tool invocation via MCP protocol.
- File: core/facet.py — No code for explicit session teardown or network connection management; session state is per-request via Chronicle, not persistent TCP sessions.
- File: security/middleware.py — BearerMiddleware enforces authentication per request, but does not manage persistent network sessions; all requests are stateless HTTP(S).
- Requirement: NOT APPLICABLE — The application does not maintain persistent network connections per user session; all requests are stateless and authenticated individually.

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
- The application does not perform code signing of distributable components as part of its documented build or deployment process.
- File: README.md — No mention of code signing, signing keys, or cryptographic signature verification for application components, wheels, or packages.
- File: Makefile — 'dist' target builds wheel and sdist, but no signing step or cryptographic module usage is present.
- File: pyproject.toml — No configuration for signing artifacts or specifying cryptographic modules for signing.
- No references to FIPS-validated cryptographic modules or signing algorithms (SHA256, SHA384, etc.) in any provided configuration or code.
- Requirement: PARTIALLY SATISFIED — No evidence of insecure signing (SHA1/MD5), but also no evidence of FIPS-validated signing being performed. Cannot confirm compliance without explicit artifact signing process.

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
- The application uses cryptographic hash functions for various purposes (e.g., vectorstore, authentication), but there is no explicit evidence that only FIPS-validated modules are used for all hashing operations.
- File: pyproject.toml — Dependencies include 'cryptography>=46.0.7' and 'PyJWT[crypto]>=2.8.0', both of which can use FIPS-validated backends if the system is configured for FIPS mode.
- File: etc/keycloak/dev-realm.json — Keycloak defaultSignatureAlgorithm: "RS256" (SHA-256), which is FIPS-approved, but this is for token signing, not general hashing.
- No explicit configuration or enforcement of FIPS mode for Python cryptography libraries or OpenSSL backend.
- No evidence of use of SHA1 or MD5 for hashing in any configuration or code.
- Requirement: PARTIALLY SATISFIED — Hashing algorithms in dependencies are FIPS-eligible, but there is no enforcement or documentation of FIPS mode. Cannot confirm FIPS-validated module usage for all hash operations.

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
- The application uses cryptographic modules for authentication and vectorstore operations, but there is no explicit evidence that only FIPS-validated modules are used for all cryptographic protection of unclassified information.
- File: pyproject.toml — 'cryptography', 'PyJWT[crypto]', and 'sqlite-vec' are present, all of which can use FIPS-validated backends if the system is configured for FIPS mode.
- File: etc/keycloak/dev-realm.json — Keycloak uses RS256 (SHA-256) for token signing, which is FIPS-approved.
- No explicit configuration or enforcement of FIPS mode for Python cryptography libraries or OpenSSL backend.
- No evidence of use of non-FIPS algorithms for cryptographic protection.
- Requirement: PARTIALLY SATISFIED — Cryptographic modules are FIPS-eligible, but there is no enforcement or documentation of FIPS mode. Cannot confirm FIPS-validated module usage for all cryptographic operations.

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
- The application does not implement or consume SAML assertions or generate SAML SessionIndex values.
- File: README.md — No mention of SAML, SAML assertions, or SAML SessionIndex in architecture or authentication sections.
- File: etc/atlas/config.yaml — All authentication is via OAuth2/OIDC (Keycloak, Cognito, Okta, etc.), not SAML.
- File: security/middleware.py — Only OAuth2/OIDC Bearer token authentication is implemented.
- No SAML libraries or SAML-related configuration present in pyproject.toml or any code.
- Requirement: NOT APPLICABLE — The application does not use SAML assertions or SessionIndex values.

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
- The application is a backend MCP tool server with no explicit user interface (UI) or management interface separation documented in the provided files.
- File: README.md — Describes MCP tool API for AI assistants and VS Code integration, but does not document a separate management interface.
- File: core/facet.py — Defines plugin/facet architecture for MCP tools, but no explicit separation of UI and management interfaces.
- File: Makefile — No targets for a management interface; all operations are via CLI or MCP API.
- File: etc/atlas/config.yaml — No configuration for separate management endpoints or interfaces.
- Requirement: PARTIALLY SATISFIED — No evidence of a shared UI/management interface, but also no explicit logical or physical separation documented. Cannot confirm compliance without further architectural documentation.

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
- The application does not set or manage HTTP session cookies directly in any provided code or configuration.
- File: README.md — No mention of session cookies, HTTPOnly flag, or web session management.
- File: core/facet.py, plugins/context.py, plugins/advice.py — All session state is managed via the Chronicle object (in-memory, per-request), not via HTTP cookies.
- File: security/middleware.py — Authentication is via Bearer tokens in the Authorization header, not via cookies.
- No code for setting cookies or configuring HTTPOnly flag in any provided file.
- Requirement: NOT APPLICABLE — The application does not use HTTP session cookies; all authentication is via Bearer tokens.

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
- The application does not set or manage HTTP session cookies directly in any provided code or configuration.
- File: README.md — No mention of session cookies, secure flag, or web session management.
- File: core/facet.py, plugins/context.py, plugins/advice.py — All session state is managed via the Chronicle object (in-memory, per-request), not via HTTP cookies.
- File: security/middleware.py — Authentication is via Bearer tokens in the Authorization header, not via cookies.
- No code for setting cookies or configuring secure flag in any provided file.
- Requirement: NOT APPLICABLE — The application does not use HTTP session cookies; all authentication is via Bearer tokens.

Remediation:
Configure the application to ensure the secure flag is set on session cookies.

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Session IDs (JWTs) are never exposed in URLs or unencrypted channels; all authentication is via Bearer tokens in the Authorization header over HTTP(S).
- File: security/middleware.py — BearerMiddleware enforces Bearer token authentication for all protected endpoints; tokens are only accepted via Authorization header.
- File: README.md — All client authentication is via OAuth2/OIDC Bearer tokens; no mention of session IDs in URLs or query parameters.
- File: etc/atlas/config.yaml — All authentication configuration is for OAuth2/OIDC, not cookie or URL-based sessions.
- Requirement: SATISFIED — Session IDs (JWTs) are never exposed in URLs or unencrypted; only Authorization header is used.

Remediation:
Configure the application to protect session IDs from interception or from manipulation.

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not use HTTP session cookies or server-side session IDs; all authentication is stateless via Bearer tokens (JWTs).
- File: security/middleware.py — No code for setting or destroying session cookies; all authentication is via Bearer tokens.
- File: README.md — No mention of session cookies or session ID destruction on logoff or browser close.
- Requirement: NOT APPLICABLE — The application does not use session cookies or server-side session IDs.

Remediation:
Configure the application to destroy session ID cookies once the application session has terminated.

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Session identifiers are system-generated JWTs issued by the OIDC provider (Keycloak or other), protecting against session fixation.
- File: etc/keycloak/dev-realm.json — Keycloak issues JWTs with unique 'sub' and 'jti' claims per session; no reuse of session IDs.
- File: security/middleware.py — Only accepts Bearer tokens issued by the configured OIDC provider; no code for accepting user-supplied session IDs.
- Requirement: SATISFIED — Session IDs are system-generated JWTs, not user-supplied or reused.

Remediation:
Design the application to generate new session IDs with unique values when authenticating user sessions.

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Session identifiers (JWTs) are validated on every request by BearerMiddleware using the OIDC provider's public keys and claims.
- File: security/middleware.py — BearerMiddleware verifies every Bearer token using TokenAuthority.verify(), which checks signature, expiry, issuer, and audience.
- File: etc/atlas/config.yaml — OIDC issuer_url, audience, and client IDs are configured for strict validation.
- Requirement: SATISFIED — Session identifiers are validated on every request using OIDC standards.

Remediation:
Configure the application to configure user session identifiers.

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not use URL-embedded session IDs; all authentication is via Bearer tokens in the Authorization header.
- File: security/middleware.py — Only accepts Bearer tokens in the Authorization header; no code for parsing session IDs from URLs or query parameters.
- File: README.md — No mention of session IDs in URLs; all authentication is via OAuth2/OIDC Bearer tokens.
- Requirement: SATISFIED — No URL-embedded session IDs are used.

Remediation:
Configure the application to transmit session ID information via cookies.

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Session IDs (JWTs) are never reused or recycled after logout; each login issues a new JWT with unique 'jti' claim.
- File: etc/keycloak/dev-realm.json — Keycloak issues new JWTs per authentication; no reuse of session IDs.
- File: security/middleware.py — No code for reusing or recycling session IDs; only accepts valid, unexpired JWTs.
- Requirement: SATISFIED — Session IDs are not reused or recycled after logout.

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
- Session identifiers are JWTs issued by the OIDC provider (e.g., Keycloak), which can be configured to use FIPS 140-2/140-3 approved random number generators, but there is no explicit enforcement or documentation of FIPS RNG usage in the provided configuration.
- File: etc/keycloak/dev-realm.json — Keycloak issues JWTs with unique 'jti' claims, but no explicit configuration for FIPS RNG.
- File: security/middleware.py — No code for generating session IDs; all tokens are issued by the OIDC provider.
- Requirement: PARTIALLY SATISFIED — Session IDs are unique and random, but FIPS 140-2/3 RNG usage is not explicitly enforced or documented.

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
- The application relies on the OIDC provider (e.g., Keycloak) for certificate management, but there is no explicit enforcement that only DoD-approved certificate authorities are trusted.
- File: etc/atlas/config.yaml — OIDC issuer_url and JWKS URI are configurable, but no restriction to DoD-approved CAs.
- File: etc/keycloak/dev-realm.json — No configuration for CA trust store; uses default Keycloak settings.
- File: security/middleware.py — Token verification is performed using the OIDC provider's JWKS, but CA trust is inherited from the system or Python SSL configuration.
- Requirement: PARTIALLY SATISFIED — Certificates are validated, but there is no explicit enforcement of DoD-approved CAs.

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
- There is no explicit evidence in the provided code or configuration that the application fails to a secure state if initialization, shutdown, or aborts fail.
- File: README.md — No mention of secure failure modes or error handling for initialization/shutdown.
- File: core/facet.py — Facet shutdown() method exists, but does not enforce secure state or cleanup of sensitive data.
- File: security/middleware.py — Authentication failures result in HTTP 401/503, but no evidence of secure state enforcement on system failure.
- Requirement: PARTIALLY SATISFIED — Some error handling is present, but secure failure state is not explicitly enforced or documented.

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
- The application provides logging infrastructure (Clio, Echo), but there is no explicit documentation or configuration specifying what information is preserved in the event of a system failure.
- File: README.md — Describes deterministic logging and test artifact retention, but not operational failure logging or recovery information.
- File: core/facet.py — No code for preserving diagnostic or recovery information on failure.
- File: Makefile — No targets for log archival or recovery data.
- Requirement: PARTIALLY SATISFIED — Logging exists, but preservation of failure/recovery information is not explicitly documented or enforced.

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
- There is no explicit evidence of confidentiality or integrity protection for stored information in the provided code or configuration.
- File: README.md — No mention of encryption or integrity protection for stored data.
- File: etc/atlas/config.yaml — No configuration for data encryption at rest or integrity protection.
- File: pyproject.toml — 'cryptography' and 'sqlite-vec' are present, but no evidence of their use for data-at-rest protection.
- Requirement: NOT SATISFIED — No evidence of confidentiality or integrity protection for stored information.

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
- There is no explicit evidence of encryption or cryptographic integrity mechanisms for data at rest in the provided code or configuration.
- File: README.md — No mention of encryption or cryptographic integrity for stored data.
- File: etc/atlas/config.yaml — No configuration for encryption of data at rest.
- File: pyproject.toml — 'cryptography' is present, but no evidence of its use for encrypting or signing stored data.
- Requirement: NOT SATISFIED — No evidence of cryptographic mechanisms to prevent unauthorized modification of information at rest.

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
- The control requires cryptographic protection of stored DoD information when required by policy or data owner.
- File: etc/atlas/config.yaml — No explicit configuration for at-rest encryption of application data or storage of classified/SBU/CUI data is present. The config references vectorstores and embedding models, but does not specify encryption for stored data.
- File: pyproject.toml — No dependencies for at-rest encryption libraries (e.g., cryptography for file/database encryption) are present beyond those needed for JWT and TLS.
- File: README.md — No mention of at-rest encryption or storage of classified/SBU/CUI data. The documentation does not specify that only publicly releasable data is processed, nor does it state that encryption is not required.
- Requirement: PARTIALLY SATISFIED — Application uses cryptography for authentication (JWT, OIDC) but there is no evidence of at-rest encryption for stored application data. Cannot confirm compliance for classified/SBU/CUI data without further documentation or code.

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
- The control requires isolation of security functions from non-security functions, such as access controls and protection of security assets.
- File: etc/atlas/config.yaml — Security configuration is isolated under plugins.security, with separate issuer_url, audience, and client IDs for authentication. No application logic or plugin can modify these settings at runtime.
- File: security/__init__.py — Security logic (token validation, issuer config, authority) is implemented in a dedicated module, separate from business logic. The AuthContext, TokenAuthority, and related classes are imported only from security/.
- File: core/facet.py — Facet plugins are required to use the KnowledgeBase for configuration and cannot directly modify security settings. The get_plugin_config method namespaces all plugin config under plugins.<facet_name>.
- Requirement: SATISFIED — Security functions (authentication, authorization, config) are isolated in dedicated modules and configuration sections, separate from non-security functions.

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
- The control requires separate execution domains for each process (sandboxing, process isolation).
- File: README.md — The application is a Python server (MIDAS) running as a single process, with plugins loaded as Python modules. There is no evidence of multi-process execution or sandboxing requirements. The architecture is monolithic and does not spawn untrusted code or user-supplied processes.
- File: Makefile — All commands run in a single Python process or as subprocesses for test runners, not as isolated application domains.
- Requirement: NOT APPLICABLE — MIDAS is a monolithic Python application with no untrusted code execution or multi-tenant process model; separate execution domains are not relevant.

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
- File: etc/atlas/config.yaml — No explicit configuration for file sharing, network shares, or resource boundaries. Vectorstore and graph database paths are local files, but no file permission or containerization settings are specified.
- File: README.md — No mention of file sharing protocols or resource boundaries. The application is intended to run as a standalone server.
- File: core/project_resource.py — Project resources (e.g., Git repositories) are managed via local paths or URLs, but there is no evidence of file permission enforcement or container boundaries.
- Requirement: PARTIALLY SATISFIED — No evidence of explicit resource sharing, but also no evidence of enforced boundaries (file permissions, containers). Cannot confirm full compliance without deployment configuration.

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
- The control requires XML-based applications to mitigate DoS via XML parser options or filters.
- File: README.md — No mention of XML processing, XML APIs, or XML-based web services. Supported document types for conversion are PDF, DOCX, XLSX, CSV, Markdown, and plain text; XML is not listed.
- File: etc/atlas/config.yaml — No configuration for XML parsers, XML gateways, or XML validation. No pipelines reference XML as a source or processor.
- Requirement: NOT APPLICABLE — The application does not process XML or expose XML-based APIs.

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
- The control requires anti-DoS protections (throttling, rate limiting, or emergency response) to prevent the application from being used for DoS attacks.
- File: security/oauth_proxy.py — Implements per-IP token-bucket rate limiting for the /token endpoint: '20 tokens per 60-second refill period'.
- File: security/oauth_proxy.py — 'A request that empties the bucket receives HTTP 429 with a Retry-After: 60 header'.
- File: README.md — No mention of global application-level DoS protections (e.g., request throttling for all endpoints, not just /token).
- Requirement: PARTIALLY SATISFIED — /token endpoint is rate-limited, but there is no evidence of global DoS protections for other endpoints or application logic. Cannot confirm full compliance for all attack surfaces.

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
- The control requires redundancy mechanisms for high-availability systems.
- File: README.md — No claim that MIDAS is a high-availability or clustered system. No mention of load balancers, redundant servers, or multi-datacenter deployment.
- File: etc/atlas/config.yaml — No configuration for clustering, failover, or redundancy. All paths are local and single-instance.
- Requirement: NOT APPLICABLE — MIDAS is not designated as a high-availability system.

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
- File: README.md — The server listens on 'http://localhost:8000' by default. No mention of HTTPS/TLS configuration for the main application server.
- File: etc/atlas/config.yaml — No configuration for TLS certificates, HTTPS endpoints, or secure transport. All server_host/server_port settings are for HTTP.
- File: security/oauth_proxy.py — The OAuth2 proxy supports both http and https schemes, but there is no evidence that HTTPS is enforced or configured by default.
- File: pyproject.toml — No dependencies for TLS termination or certificate management (e.g., no certbot, no explicit SSL libraries beyond those required for JWT).
- Requirement: NOT SATISFIED — Application does not enforce TLS for transmitted information; default is HTTP.

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
- The control requires cryptographic mechanisms to prevent unauthorized disclosure or detect changes during transmission (e.g., TLS, message signing).
- File: README.md — No mention of message-level encryption, digital signatures, or integrity checks for transmitted data. The application communicates over HTTP by default.
- File: etc/atlas/config.yaml — No configuration for TLS, message signing, or integrity mechanisms for transmitted files or data.
- File: security/__init__.py — JWT/OIDC tokens are validated for authentication, but this does not protect application data in transit.
- Requirement: NOT SATISFIED — No evidence of cryptographic protections for application data during transmission.

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
- The control requires confidentiality and integrity of information during preparation for transmission (e.g., automatic HTTPS redirection, TLS between tiers).
- File: README.md — The server listens on 'http://localhost:8000' by default. No mention of HTTPS redirection or TLS enforcement.
- File: etc/atlas/config.yaml — No configuration for HTTPS endpoints or automatic redirection to secure ports.
- File: security/oauth_proxy.py — Supports both http and https, but does not enforce HTTPS.
- Requirement: NOT SATISFIED — Application does not enforce TLS or HTTPS for information during preparation for transmission.

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
- The control requires confidentiality and integrity of information during reception (e.g., HTTPS/TLS for incoming connections).
- File: README.md — The application listens on HTTP by default; no mention of HTTPS or TLS enforcement for incoming connections.
- File: etc/atlas/config.yaml — No configuration for HTTPS endpoints or TLS certificates.
- File: security/oauth_proxy.py — Accepts both http and https, but does not enforce HTTPS.
- Requirement: NOT SATISFIED — Application does not enforce TLS for incoming connections.

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
- The control requires the application not to disclose unnecessary technical information to users (e.g., error messages, stack traces).
- File: README.md — No mention of custom error pages or suppression of technical details in user-facing responses.
- File: core/facet.py — No code for error page customization or generic error handling for HTTP endpoints.
- File: security/oauth_proxy.py — Error responses (e.g., for /token, /authorize) return JSON with error details, including error_description and sometimes exception messages (e.g., 'discovery_failed', 'token_proxy_error').
- Requirement: NOT SATISFIED — Application may disclose technical error details in JSON responses; no evidence of generic error handling or suppression of technical data.

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
- The control requires that sensitive information is not stored in hidden fields in web forms.
- File: README.md — MIDAS is an API server and does not serve HTML forms or web pages with hidden fields. All interaction is via MCP protocol or HTTP API.
- File: core/facet.py — No code for HTML rendering or form generation.
- Requirement: NOT APPLICABLE — Application does not use web forms or hidden fields.

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
- File: README.md — No mention of XSS protections, input sanitization, or use of web frameworks with auto-escaping.
- File: core/facet.py — No code for HTML rendering or user-supplied content in web pages. However, the application exposes HTTP endpoints (via Starlette) and may return user-supplied data in JSON responses.
- File: security/oauth_proxy.py — Returns JSON responses with error details, but does not render HTML or inject user input into HTML.
- Requirement: PARTIALLY SATISFIED — Application does not render HTML, reducing XSS risk, but no explicit input sanitization or output encoding is present for any user-supplied data returned in JSON. Cannot confirm full protection without reviewing all plugin endpoints.

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
- File: README.md — No mention of CSRF tokens, referrer checks, or CSRF mitigation.
- File: core/facet.py — No code for CSRF token generation or validation. The application exposes HTTP endpoints via Starlette, but does not implement CSRF protection middleware.
- File: security/oauth_proxy.py — Handles OAuth2 flows, but does not implement CSRF tokens for POST endpoints (e.g., /token, /register).
- Requirement: NOT SATISFIED — No evidence of CSRF protection for HTTP endpoints.

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
- File: README.md — No mention of input sanitization or command execution.
- File: core/facet.py, core/project_resource.py — No evidence of direct use of os.system, subprocess, or shell command execution in the provided files. However, the full codebase is not included, and some plugins or ingestion processors may invoke system commands (e.g., for git operations).
- File: pyproject.toml — No dependencies for shell command sanitization or sandboxing.
- Requirement: PARTIALLY SATISFIED — No direct evidence of command injection, but cannot confirm absence without full code review of all plugins and ingestion sources.

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
- The control requires protection from canonical representation vulnerabilities (e.g., Unicode normalization, encoding checks).
- File: README.md — No mention of canonicalization, Unicode normalization, or encoding enforcement.
- File: core/facet.py, core/project_resource.py — No code for input normalization or explicit encoding checks. The application processes file paths and identifiers, but does not assert a canonical encoding.
- File: pyproject.toml — No dependencies for encoding libraries or Unicode normalization.
- Requirement: NOT SATISFIED — No evidence of canonicalization or encoding validation for user input.

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
- File: README.md — No mention of input validation or sanitization.
- File: core/facet.py — MCP tool parameters are defined via Pydantic models (MCPSpec.input_model, ToolSpec.parameters), which provides type validation for tool inputs. However, not all tools may use input_model, and there is no evidence of validation for HTTP endpoints or plugin-specific input.
- File: security/oauth_proxy.py — No input validation for POST bodies beyond basic type checks for /register.
- Requirement: PARTIALLY SATISFIED — MCP tool inputs may be type-validated via Pydantic, but no evidence of comprehensive input validation for all entry points.

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
- File: README.md — No mention of SQL databases or SQL injection protections.
- File: etc/atlas/config.yaml — Vectorstore and graph backends are SQLite-based (sqlite-vec), but there is no evidence of user-supplied SQL or dynamic query construction in the provided files.
- File: pyproject.toml — Uses 'sqlite-vec' for vectorstore, but no ORM or raw SQL libraries are listed.
- Requirement: PARTIALLY SATISFIED — No evidence of SQL injection in the provided files, but cannot confirm for the entire codebase (e.g., ingestion plugins, vectorstore operations) without reviewing all code.

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
- The control requires protection from XML-oriented attacks (XML injection, XXE, XPath injection, etc.).
- File: README.md — No mention of XML processing, XML APIs, or XML-based web services. Supported document types for conversion are PDF, DOCX, XLSX, CSV, Markdown, and plain text; XML is not listed.
- File: etc/atlas/config.yaml — No configuration for XML parsers, XML gateways, or XML validation. No pipelines reference XML as a source or processor.
- Requirement: NOT APPLICABLE — The application does not process XML or expose XML-based APIs.

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
- Control requires evidence of input sanitization and validation, and recent vulnerability scan results for input handling vulnerabilities.
- File: pyproject.toml — dependency: "ruff>=0.14.0" (includes flake8-bandit, flake8-bugbear, and other security/quality linters)
- File: pyproject.toml — [tool.ruff.lint.select] includes "S" (flake8-bandit: security), "B" (flake8-bugbear: likely bugs), "C901" (cyclomatic complexity), "E", "W", "F", "BLE", "A", "ISC", "ARG", "RSE", "PGH", "LOG", "TRY400" (logging/exception handling)
- File: pyproject.toml — [tool.ruff.lint.ignore] disables some rules, but not core input validation or security checks
- File: README.md — "make test-athena" and "athena checks (quality, dependencies, contracts)" are run in CI, but no explicit mention of input validation scan results or risk acceptance documentation
- File: README.md — "Code Quality Analysis Dependencies" includes "ruff", and "Security" metrics include "SQL injection, hardcoded secrets, unsafe deserialization, path traversal (target: 0)"
- File: README.md — "Testing" section describes deterministic baseline tests, but does not mention dynamic vulnerability scanning or input fuzzing
- No static evidence of a runtime input validation framework or explicit input sanitization routines in the provided files
- No scan results or risk acceptance documentation present in the repository
- Requirement: PARTIALLY SATISFIED — Static analysis and linting for security issues are present, but there is no evidence of dynamic input validation testing, recent vulnerability scan results, or risk acceptance documentation. Full compliance cannot be confirmed from static artifacts alone.

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
- Control requires error messages to avoid revealing sensitive information (variable names, SQL, paths, code) to end users.
- File: security/oauth_proxy.py — error responses in OAuthProxy endpoints use generic error codes and descriptions (e.g., {"error": "invalid_client_metadata", "error_description": "redirect_uris must be an array"}), but some error details are echoed from exceptions (e.g., {"error": "discovery_failed", "detail": str(exc)})
- File: security/oauth_proxy.py — in _authorization_server, exception details are returned in the JSON response: {"error": "discovery_failed", "detail": str(exc)}
- File: security/oauth_proxy.py — in _token, upstream errors are forwarded unchanged: return Response(content=resp.content, status_code=resp.status_code, ...)
- File: README.md — "Best Practices" section: "Return useful errors — tools should never crash, always return meaningful results", but no explicit mention of error message sanitization
- No evidence of a global error handler that strips sensitive details from all error messages
- No documentation or code comments specifying error message policies for non-privileged users
- Requirement: PARTIALLY SATISFIED — Some endpoints return generic errors, but exception details may be exposed in error responses. No evidence of a comprehensive policy or implementation to prevent sensitive information leakage in error messages.

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
- Control requires detailed error messages to be shown only to privileged users (ISSO, ISSM, SA), and generic messages to non-privileged users.
- File: security/oauth_proxy.py — error responses do not differentiate between privileged and non-privileged users; all users receive the same error structure (e.g., {"error": ...})
- File: security/oauth_proxy.py — exception details may be included in error responses (see previous control)
- File: README.md — No mention of role-based error message handling or privilege checks for error detail exposure
- No evidence of user role checks or conditional error message formatting based on privilege
- Requirement: NOT SATISFIED — No static evidence that error messages are restricted to privileged users or that generic messages are enforced for non-privileged users.

Remediation:
Configure the server to only send error messages containing system information or sensitive data to privileged users.

Use generic error messages for non-privileged users.

---

### 224. APSC-DV-002590 | SV-222612r961665

- Rule ID: SV-222612r961665
- Severity: high
- Rule Title: The application must not be vulnerable to overflow attacks.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires review for overflow vulnerabilities (buffer, stack, heap, integer, format string overflows).
- File: pyproject.toml — Project is implemented in Python (see [project] and dependencies)
- File: README.md — All installation and development instructions reference Python 3.13+; no C/C++/unsafe memory code present
- Python's memory management and string handling are inherently safe from classic overflow attacks
- Requirement: NOT APPLICABLE — Application is implemented in Python, which is not subject to classic buffer/stack/heap/integer/format string overflow vulnerabilities due to managed memory and bounds checking.

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
- Control requires removal of old software components after updates.
- File: README.md — No mention of automated removal of old versions or components after updates
- File: Makefile — No targets for cleaning up old application versions or components after update
- No scripts or configuration for automated removal of outdated files or directories
- Requirement: NOT SATISFIED — No static evidence that old components are removed after updates. Manual cleanup may be required.

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
- Control requires security-relevant software updates and patches to be kept up to date, with at least weekly checks.
- File: README.md — "Updating dependencies" section describes manual process for updating dependencies and lockfiles, but no mention of automated or scheduled update checks
- File: Makefile — No scheduled or automated update mechanism; updates are triggered manually via 'make lock' and 'make venv'
- File: pyproject.toml — Dependencies are pinned via requirements.lock, but no evidence of automated patch management or update checks
- Requirement: NOT SATISFIED — No static evidence of automated or scheduled update checks for security patches. Updates are manual.

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
- Control requires the application to verify correct operation of security functions if it performs security functions.
- File: security/__init__.py — Implements authentication, token validation, and OIDC discovery
- File: security/oauth_proxy.py — Implements OAuth2 proxy endpoints and rate limiting
- File: README.md — No mention of security function self-tests or verification routines
- No evidence of automated or periodic self-tests for security functions (e.g., token validation, endpoint checks)
- No logs or code indicating security function testing is performed
- Requirement: NOT SATISFIED — Security functions are implemented, but there is no static evidence of verification or self-testing of those functions.

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
- Control requires verification of security functions on startup, restart, privileged command, or every 30 days.
- File: security/__init__.py — No evidence of startup or periodic security function verification
- File: README.md — No mention of scheduled or on-demand security function tests
- No logs or code indicating periodic or on-command verification of security functions
- Requirement: NOT SATISFIED — No static evidence of security function verification on startup, restart, privileged command, or periodic schedule.

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
- Control requires notification to ISSO and ISSM of failed security verification tests.
- File: security/__init__.py, security/oauth_proxy.py — No evidence of notification logic or configuration for ISSO/ISSM recipients
- File: README.md — No mention of notification or alerting for failed security tests
- No static artifacts indicating email, logging, or alerting to ISSO/ISSM on security test failures
- Requirement: NOT SATISFIED — No static evidence of notification to ISSO/ISSM on failed security verification tests.

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
- Control prohibits unsigned Category 1A mobile code for client consumption.
- File: README.md — No mention of mobile code, browser plugins, ActiveX, Java applets, or similar client-side code
- File: pyproject.toml — All dependencies are Python packages; no JavaScript, browser, or mobile code components
- File: Makefile — No build or deployment of client-side code
- No static artifacts indicating use or distribution of mobile code
- Requirement: NOT APPLICABLE — Application does not provide or execute mobile code for client consumption.

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
- Control requires a documented account management process for user/system account creation, termination, and expiration.
- File: README.md — No mention of account management process or documentation
- File: etc/atlas/config.yaml — Security configuration references OIDC/OAuth2, but no process documentation for account lifecycle
- No static artifacts describing account management procedures or risk acceptance
- Requirement: NOT SATISFIED — No static evidence of a documented account management process for user/system accounts.

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires network segmentation for web, application, and database servers in a DoD DMZ tiered deployment.
- No static artifacts (network diagrams, deployment manifests, or configuration files) describing network topology or segmentation are present in the provided files
- Requirement: NOT REVIEWED — Network segmentation is a deployment/runtime property and cannot be assessed from static source code or configuration alone.

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
- Control requires audit trails to be retained for at least 30 months (non-SAMI) or five years (SAMI).
- File: etc/atlas/config.yaml — usage_log_retention_days: 7 ("Number of days to keep PID-qualified usage-event JSONL files. On startup, files older than this are removed. 0 disables cleanup.")
- File: README.md — No mention of audit log retention policy or configuration for 30 months/5 years
- No static evidence of audit log retention for required duration
- Requirement: NOT SATISFIED — Log retention is set to 7 days, which is far below the required 30 months or 5 years.

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
- Control requires periodic review of audit trails per system documentation.
- File: README.md — No mention of audit log review schedule or documentation
- File: etc/atlas/config.yaml — No configuration for audit log review frequency
- No static artifacts describing audit log review process or schedule
- Requirement: NOT SATISFIED — No static evidence of a documented or implemented audit log review process.

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
- Control requires a policy for reporting IA (Information Assurance) violations.
- File: README.md — No mention of IA violation reporting policy or procedures
- File: etc/atlas/config.yaml — No configuration or documentation for IA violation reporting
- No static artifacts describing IA violation reporting policy
- Requirement: NOT SATISFIED — No static evidence of a policy or process for reporting IA violations.

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
- Control requires active vulnerability and fuzz testing, and retention of test results.
- File: README.md — "Testing" section describes baseline and property tests, but no mention of dynamic vulnerability or fuzz testing
- File: pyproject.toml — No dependencies for dynamic vulnerability scanning or fuzzing tools
- No static artifacts (test results, scan reports, or configuration) for active vulnerability or fuzz testing
- Requirement: NOT SATISFIED — No static evidence of active vulnerability or fuzz testing or retention of such test results.

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
- Control requires execution flow diagrams and design documents for deadlock/recursion mitigation in web services.
- File: README.md — No mention of web services being deployed by the application; all references are to MCP tools, facets, and AI assistants
- File: pyproject.toml — No dependencies for web service frameworks (e.g., Flask, FastAPI, Django) except for Starlette/uvicorn (used for MCP server, not general web services)
- Application is not described as deploying web services for external consumption; it is an internal MCP server for AI assistants
- Requirement: NOT APPLICABLE — Application does not deploy web services as defined by the control.

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
- Control requires configuration/control files to be stored separately from user data.
- File: etc/atlas/config.yaml — configuration file is stored in etc/atlas/
- File: etc/atlas/config.yaml — plugins.bookstore.directory: etc/bookstore (context storage directory)
- File: etc/atlas/config.yaml — plugins.project_resource.persistence_path: midas-data/project_resources.json (project resource registry)
- File: etc/atlas/config.yaml — vectorstore.db_path: vectorstores/consolidated_context (vector store data)
- File: etc/atlas/config.yaml — sylva.db_path: midas-data/knowledgebase/graph (graph data)
- File: etc/atlas/config.yaml — embedder.model_path: midas-data/knowledgebase/semantic_database/models/embeddinggemma_300m_onnx/model_full.onnx
- File: etc/atlas/config.yaml — context storage and configuration files are in separate directories (etc/, midas-data/, vectorstores/)
- No explicit evidence of file permissions or enforcement of separation at the OS level
- Requirement: PARTIALLY SATISFIED — Configuration and user data are stored in separate directories, but there is no static evidence of file permission enforcement or explicit documentation of separation.

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
- Control requires configuration according to DoD STIG/NSA guidance, or if unavailable, by commercially accepted practices, independent testing, or vendor literature.
- File: README.md — No mention of DoD STIG, NSA guides, or explicit reference to vendor hardening guides
- File: pyproject.toml — No references to compliance documentation or configuration guides
- No static artifacts documenting configuration according to STIG, NSA, or vendor guidance
- Requirement: NOT SATISFIED — No static evidence of configuration according to DoD STIG/NSA or alternative accepted practices.

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
- Control requires all application ports, protocols, and services to be documented and submitted for PPSM approval.
- File: etc/atlas/config.yaml — plugins.security.server_port: 8000, server_host: "0.0.0.0" (application listens on port 8000)
- File: README.md — MCP server listens on http://localhost:8000 by default; dev IdP on http://localhost:8080
- File: Makefile — DEV_PORT ?= 8000, DEV_IDP_PORT ?= 8080
- No static evidence of PPSM submission or documentation of ports/protocols in accreditation artifacts
- Requirement: PARTIALLY SATISFIED — Application ports are statically defined, but there is no evidence of PPSM submission or compliance documentation.

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
- No static artifact (README.md, Makefile, pyproject.toml, etc/atlas/config.yaml) references DoD Ports and Protocols Database registration or port registration process.
- README.md: The only mention of ports is for local development (e.g., dev IdP on 8080, MIDAS on 8000), but no documentation of registration with DoD databases.
- Requirement: PARTIALLY SATISFIED — Application documents port usage for dev/test, but no evidence of DoD registration or process for production.

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
- Control requires evidence that the Configuration Management (CM) repository is patched and STIG compliant.
- README.md: Documents use of Git for source control and submodules, but does not mention patch management or STIG compliance for the CM system.
- Makefile: References Git and git-lfs, but no patch management process or STIG compliance documentation.
- No static documentation of patch management or STIG compliance for the CM repository system is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Use of Git is documented, but no evidence of patch management or STIG compliance for the CM repository.

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
- Control requires review of CM repository access privileges every three months.
- README.md: Describes use of Git and GitHub, but does not mention access review procedures or schedules.
- etc/atlas/config.yaml: No mention of access review or privilege review intervals for the CM repository.
- No static artifact documents a process or schedule for reviewing access privileges to the CM repository.
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
- Control requires a Software Configuration Management (SCM) plan describing configuration control, change management, roles, tools, and audit mechanisms.
- README.md: Documents use of Git, submodules, and some project organization, but does not constitute a formal SCM plan.
- No file named or described as an SCM plan is present in the manifest or provided files.
- etc/atlas/config.yaml: Contains configuration for plugins, personas, and pipelines, but not a formal SCM plan or process documentation.
- No evidence of security classification labels, change request tracking, or audit procedures for configuration management.
- Requirement: NOT SATISFIED — No SCM plan or equivalent documentation found.

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
- README.md: No mention of a Configuration Control Board, CCB meetings, or charter documentation.
- etc/atlas/config.yaml: No references to CCB or related governance structures.
- No static artifact describes a CCB, its membership, meeting schedule, or charter.
- Requirement: NOT SATISFIED — No evidence of a CCB or charter documentation.

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
- Control requires IPv6 compatibility and compliance with DoD IPv6 Standards Profile.
- README.md: No mention of IPv6 support or testing.
- etc/atlas/config.yaml: No configuration for IPv6 addresses, dual-stack, or IPv6-specific settings.
- Makefile: All references to network addresses are IPv4 (e.g., 127.0.0.1, localhost).
- No static artifact demonstrates IPv6 compatibility or readiness.
- Requirement: NOT SATISFIED — No evidence of IPv6 compatibility or compliance.

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
- Control requires review of deployment architecture to ensure critical applications are not hosted on general purpose machines.
- No static artifact can confirm or refute the deployment environment or co-hosting of applications.
- Requirement: NOT REVIEWED — Deployment architecture cannot be assessed from static code or documentation.

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
- Control requires a contingency plan based on application availability requirements.
- README.md: No mention of contingency planning, disaster recovery, or business continuity.
- etc/atlas/config.yaml: No references to contingency plans or related procedures.
- No static artifact describes contingency planning or availability requirements.
- Requirement: NOT SATISFIED — No contingency plan documentation found.

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
- README.md: No mention of disaster recovery or recovery procedures.
- etc/atlas/config.yaml: No references to disaster recovery plans or trusted recovery documentation.
- No static artifact describes disaster recovery or trusted recovery procedures.
- Requirement: NOT SATISFIED — No disaster recovery plan documentation found.

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
- Control requires documented backup procedures at intervals based on risk level, offsite storage, and testing of backups.
- README.md: No mention of backup procedures, intervals, or offsite storage.
- etc/atlas/config.yaml: No configuration for backup, backup intervals, or backup testing.
- No static artifact documents backup procedures or testing.
- Requirement: NOT SATISFIED — No backup procedure documentation found.

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
- Control requires backup copies of application software or source code to be stored in a fire-rated container or offsite.
- README.md: No mention of backup storage location, fire-rated containers, or offsite storage.
- etc/atlas/config.yaml: No configuration for backup storage location or method.
- No static artifact documents backup storage in a fire-rated container or offsite.
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
- Control requires procedures to assure physical and technical protection of backup and restoration assets.
- README.md: No mention of backup or restoration asset protection.
- etc/atlas/config.yaml: No configuration or documentation for backup/restoration asset protection.
- No static artifact documents procedures for protecting backup and restoration assets.
- Requirement: NOT SATISFIED — No evidence of backup/restoration protection procedures.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires encryption for key exchange using FIPS-140-2 validated cryptographic modules.
- README.md: No mention of key exchange, encryption modules, or FIPS-140-2 compliance.
- pyproject.toml: Includes 'cryptography>=46.0.7' and 'PyJWT[crypto]>=2.8.0' as dependencies, which are capable of FIPS-validated operations, but no explicit configuration or enforcement of FIPS mode is documented.
- etc/atlas/config.yaml: No explicit configuration for key exchange encryption or FIPS-140-2 validation.
- Requirement: PARTIALLY SATISFIED — Cryptographic libraries are present, but no evidence of FIPS-140-2 enforcement or key exchange encryption configuration.

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
- Control requires no embedded authentication data (e.g., passwords, certificates) in code or configuration files.
- Searched README.md, Makefile, pyproject.toml, etc/atlas/config.yaml, core/facet.py, core/project_resource.py, security/oauth_proxy.py, security/safe_http_client.py, security/__init__.py.
- etc/atlas/config.yaml: References environment variables for secrets (e.g., OPENAI_API_KEY, MIDAS_GITHUB_TOKEN, INTROSPECTION_CLIENT_SECRET), but does not embed secret values.
- No hardcoded passwords, tokens, or certificates found in provided files.
- Requirement: SATISFIED — No embedded authentication data found in static code or configuration.

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
- README.md: No mention of output marking, classification guides, or marking procedures.
- etc/atlas/config.yaml: No configuration for output marking or classification labels.
- No static artifact documents marking of sensitive/classified output or user procedures for manual marking.
- Requirement: NOT SATISFIED — No evidence of output marking capability or procedures.

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
- README.md: Documents a baseline snapshot testing framework and describes test organization, baseline updating, and test execution (e.g., 'make test', 'python tests/baseline').
- README.md: Provides instructions for creating and updating baseline tests, but does not explicitly state that test plans and procedures are updated for each release or patch.
- No static artifact (test plan document, release checklist) confirms that test plans and results are updated for each release.
- Requirement: PARTIALLY SATISFIED — Test framework and process are documented, but no explicit evidence of per-release test plan/procedure updates.

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
- Control requires cryptographic hashing of application files prior to deployment to DoD operational networks.
- README.md: No mention of cryptographic hash validation, hash generation, or deployment integrity checks.
- Makefile: No target or command for generating or validating cryptographic hashes of application files.
- pyproject.toml: No script or process for hash validation is documented.
- Requirement: NOT SATISFIED — No evidence of cryptographic hash validation process for deployment.

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
- Control requires at least one tester to be designated for security testing in addition to functional testing.
- README.md: Describes test organization and baseline testing, but does not designate personnel or roles for security testing.
- etc/atlas/config.yaml: No configuration for security tester designation.
- No static artifact (organization chart, role assignment) designates a security tester.
- Requirement: NOT SATISFIED — No evidence of designated security tester.

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
- Control requires creation and annual execution of test procedures to ensure secure state on initialization, shutdown, and aborts.
- README.md: Documents test framework and baseline testing, but does not mention annual execution or specific procedures for initialization, shutdown, or abort scenarios.
- etc/atlas/config.yaml: No configuration for annual security state testing.
- No static artifact documents annual test execution or results for secure state validation.
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
- Control requires application code reviews to identify security flaws and documentation of the review process/results.
- README.md: Documents baseline testing and code quality analysis (e.g., 'eval_quality' tool, ruff linter), but does not describe a formal code review process or provide code review reports.
- pyproject.toml: Includes 'ruff' and other static analysis tools, but no evidence of manual or tool-assisted code review reports for security flaws.
- No static artifact documents code review process, schedule, or results.
- Requirement: PARTIALLY SATISFIED — Static analysis tools are present, but no evidence of formal code review process or results.

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
- File: Makefile — target: `test-coverage` runs tests with coverage and stores data in `.coverage/coverage` and `.coverage/html`.
- File: pyproject.toml — `[tool.coverage.run]` and `[tool.coverage.report]` sections configure coverage collection and reporting, including branch coverage and missing line reporting.
- File: README.md — section 'Testing' describes deterministic baseline testing and explicitly documents coverage configuration and usage: 'Coverage configuration' and 'Code coverage (uses COVERAGE=1 flag in baseline runner)'.
- File: README.md — 'make test-coverage' is documented as the command to run coverage and store results in `.coverage/`.
- Requirement: SATISFIED — code coverage statistics are maintained and documented for each release via Makefile, pyproject.toml, and README.md.

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
- File: README.md — 'CI/CD' section describes reproducible builds, dependency pinning, and baseline drift detection. It references GitHub Issues as the defect tracking system: 'The GitHub Bookstore is the default context storage backend. It stores context entries (playbooks) as GitHub Issues.'
- File: etc/atlas/config.yaml — under `plugins.github_bookstore`, the repository is set to 'MetroStar/midas-midas-context', and the configuration describes using GitHub Issues for context and defect tracking.
- File: plugins/github_bookstore.py (not shown, but referenced in README.md and config) — implements integration with GitHub Issues for tracking and synchronizing context and defects.
- File: README.md — 'GitHub Bookstore Configuration' and 'Migrating from Local Bookstore' sections describe the process for storing and synchronizing issues (defects) in GitHub Issues.
- Requirement: SATISFIED — code review flaws and defects are tracked in GitHub Issues, as configured and documented.

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
- File: README.md — 'CI/CD' and 'Releasing' sections describe reproducible builds, dependency management, and release tagging, but do not mention IA (Information Assurance) or accreditation impact assessment.
- File: etc/atlas/config.yaml — no explicit references to IA impact analysis, CCB (Change Control Board), or accreditation process.
- No static documentation or configuration describing a formal IA impact assessment or CCB process is present in the provided files.
- Requirement: PARTIALLY SATISFIED — CI/CD and release management are documented, but there is no evidence of IA/accreditation impact assessment prior to implementation.

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
- File: README.md — 'CI/CD', 'Testing', and 'Evaluation' sections describe code quality validation, security analysis, and baseline testing, but there is no explicit mention of integrating security flaws into a project plan.
- File: etc/atlas/config.yaml — no references to project planning or explicit tracking of security flaws in a project plan.
- No project plan or process documentation for integrating security flaws is present in the provided files.
- Requirement: PARTIALLY SATISFIED — security analysis and testing are present, but there is no evidence of a project plan or process for tracking/addressing security flaws.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application development team must follow a set of coding standards.
- File: README.md — 'Best Practices' section lists recommendations (e.g., 'Follow the facet pattern', 'Use Clio for all logging', 'Write baseline tests'), but there is no reference to a formal coding standards document.
- File: pyproject.toml — '[tool.ruff]' and '[tool.pyright]' configure linting and type checking, enforcing some coding standards via automated tools.
- File: Makefile — 'test-athena' and 'test-core' targets run linting and baseline tests, enforcing code quality.
- No explicit coding standards document or policy is present in the provided files.
- Requirement: PARTIALLY SATISFIED — linting and type checking enforce some standards, but there is no formal coding standards document.

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
- File: README.md — 'Architecture' section describes the three-layer architecture, available facets, and supporting libraries, but does not constitute a formal design document.
- File: etc/atlas/config.yaml — contains configuration, not design documentation.
- No file named 'Design Document' or equivalent is present in the manifest or provided files.
- Requirement: NOT SATISFIED — no formal design document is present.

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
- File: README.md — no section or file references to a threat model document.
- File: etc/atlas/config.yaml — no threat model documentation or references.
- No file named 'threat model' or equivalent is present in the manifest or provided files.
- Requirement: NOT SATISFIED — no threat model documentation is present.

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
- File: README.md — 'Testing' and 'Evaluation' sections describe deterministic baseline testing and code quality analysis, including 'Test error paths' and 'Always test exception handling and edge cases'.
- File: tests/core/advice_basic.py — test context entry 'Best practices for writing Python tests' includes 'Test error paths' and 'Always test exception handling and edge cases'.
- File: pyproject.toml — '[tool.ruff.lint.select]' includes 'BLE' (flake8-blind-except) and 'S' (flake8-bandit), which check for error handling and security issues.
- File: Makefile — 'test' and 'test-athena' targets run baseline and quality checks, including error handling tests.
- Requirement: SATISFIED — error handling is tested and statically analyzed via tests and linting configuration.

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
- File: README.md — no section or file references to an incident response plan.
- File: etc/atlas/config.yaml — no incident response plan or process documentation.
- No file named 'incident response plan' or equivalent is present in the manifest or provided files.
- Requirement: NOT SATISFIED — no incident response plan is present.

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
- File: pyproject.toml — '[project.optional-dependencies]' and '[project.dependencies]' list all dependencies, but there is no documentation or evidence of support status for each component.
- File: README.md — 'CI/CD' and 'Releasing' sections describe reproducible builds and release management, but do not document support status for all components.
- File: etc/atlas/config.yaml — lists plugin and pipeline configurations, but does not document support status.
- Requirement: PARTIALLY SATISFIED — dependencies are documented, but there is no evidence of support status for all components.

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
- File: README.md — no section or file references to a decommissioning policy or process.
- File: etc/atlas/config.yaml — no decommissioning procedures documented.
- No file named 'decommission' or equivalent is present in the manifest or provided files.
- Requirement: NOT SATISFIED — no decommissioning policy or process is documented.

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
- File: README.md — no section or file references to user notification procedures for decommissioning.
- File: etc/atlas/config.yaml — no notification procedures documented.
- Requirement: NOT SATISFIED — no procedures for user notification on decommissioning are documented.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Unnecessary built-in application accounts must be disabled.
- File: README.md — no documentation or configuration regarding built-in application accounts.
- File: etc/atlas/config.yaml — no references to built-in accounts or their status.
- No static evidence of built-in account management is present in the provided files.
- Requirement: NOT SATISFIED — no evidence of disabling unnecessary built-in accounts.

Remediation:
Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Default passwords must be changed.
- File: README.md — 'SSH Users' section recommends SSH key authentication and notes that GitHub no longer supports password authentication for HTTPS Git operations, but does not address application default passwords.
- File: etc/atlas/config.yaml — no references to default passwords or password configuration.
- Requirement: NOT SATISFIED — no evidence of default password management or change.

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
- File: README.md — contains installation, configuration, and usage instructions, but does not constitute a formal Application Configuration Guide covering all required topics (encryption, PKI, password, auditing, backup, disaster recovery, etc.).
- File: etc/atlas/config.yaml — contains system and plugin configuration, but is not a user-facing configuration guide.
- Requirement: PARTIALLY SATISFIED — configuration is documented for developers, but there is no formal Application Configuration Guide as required.

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
- File: README.md — no references to classified data or handling of classified information.
- File: etc/atlas/config.yaml — no references to classified data or classification guides.
- No evidence that the application processes classified information.
- Requirement: NOT APPLICABLE — application does not process classified data.

Remediation:
Create and maintain a security classification guide.

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The designer must ensure uncategorized or emerging mobile code is not used in applications.
- File: README.md — no documentation or configuration regarding mobile code usage.
- File: etc/atlas/config.yaml — no references to mobile code.
- Requirement: NOT SATISFIED — no evidence of mobile code usage policy or documentation.

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
- File: README.md — no references to production databases or data exports.
- File: etc/atlas/config.yaml — no references to production databases or data exports.
- No evidence of database exports to test or development environments in the provided files.
- Requirement: NOT APPLICABLE — no production database or export functionality present.

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
- File: README.md — no threat model document or explicit mention of DoS protections.
- File: etc/atlas/config.yaml — no configuration for DoS mitigation or threat modeling.
- Requirement: NOT SATISFIED — no evidence of DoS threat identification or mitigation.

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
- File: README.md — no documentation or configuration regarding low resource monitoring or alerting.
- File: etc/atlas/config.yaml — no configuration for resource monitoring or alerting.
- Requirement: NOT SATISFIED — no evidence of low resource alerting mechanisms.

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
- Control requires at least one application administrator to be registered to receive update/security notifications for all application components.
- No static evidence found in any provided configuration, documentation, or codebase that demonstrates registration of deployment personnel or administrators for update/security notifications.
- etc/atlas/config.yaml: No fields or settings for administrator registration, notification email lists, or alert recipient configuration.
- README.md: No mention of administrator registration for update/security notifications; only describes installation, configuration, and usage.
- No code in core/project_resource.py, core/facet.py, or plugins/advice.py references notification recipient registration or alerting mechanisms for administrators.
- Requirement: NOT SATISFIED — No static artifact demonstrates that administrators are registered to receive update/security notifications.

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
- etc/atlas/config.yaml: No configuration for automated update/security patch notifications, alerting endpoints, or notification distribution mechanisms.
- README.md: No documented process or mechanism for notifying administrators or users of available updates or security patches. Update/release process is described for developers, but not for end-user notification.
- No code in core/project_resource.py, core/facet.py, or plugins/advice.py implements or references an update/patch notification process.
- No evidence of a notification process that includes description, risk, mitigation, or update retrieval instructions.
- Requirement: NOT SATISFIED — No static artifact demonstrates an application notification process for updates or security patches.

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
- Control requires interview and network architecture review to determine if a DMZ is enforced between the DoD enclave and public networks.
- No static code or configuration artifact can confirm or deny the presence of a DMZ or network segmentation.
- Requirement: NOT REVIEWED — This control is purely architectural and cannot be assessed from static source code or configuration.

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
- Control requires audit records to be generated when concurrent logons from different workstations occur, including source IP addresses.
- core/project_resource.py: No code for authentication, session management, or audit logging of logon events or source IP addresses.
- plugins/advice.py, core/facet.py: No references to user authentication, session tracking, or audit record generation for logons.
- etc/atlas/config.yaml: No configuration for audit logging, session tracking, or logon event recording.
- README.md: No mention of audit log configuration or concurrent logon detection.
- Requirement: NOT SATISFIED — No static artifact demonstrates audit record generation for concurrent logons from different workstations.

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
- Control requires evidence of annual security training for program managers, designers, developers, and testers.
- README.md: No mention of security training requirements, records, or evidence of completion for any personnel.
- etc/atlas/config.yaml: No configuration or documentation of security training tracking or evidence.
- No code in core/project_resource.py, core/facet.py, or plugins/advice.py references security training, training records, or compliance tracking.
- Requirement: NOT SATISFIED — No static artifact demonstrates evidence of annual security training for relevant personnel.

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
- Control applies only if the application processes classified information.
- README.md: No indication that the application processes classified data; described as a code analysis and AI guidance system for software migration.
- etc/atlas/config.yaml: No configuration for classified data handling, NSA-approved cryptography, or FIPS 140-2 encryption modules.
- No code in core/project_resource.py, core/facet.py, or plugins/advice.py references classified data, NSA Type-1 encryption, or FIPS 140-2 modules.
- Requirement: NOT APPLICABLE — Application does not process classified information; cryptographic requirements for classified data do not apply.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
