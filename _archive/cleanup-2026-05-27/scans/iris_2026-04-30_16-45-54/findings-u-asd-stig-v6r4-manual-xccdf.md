# iris STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 222 |
| Not a Finding | 23 |
| Not Applicable | 39 |
| Not Reviewed | 2 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: The application must provide a capability to limit the number of logon sessions per user.
- File: deploy/keycloak/dev-realm.json — No evidence of session-per-user limit (e.g., 'maxSessions' or similar) in realm or client configuration.
- File: api/README.md — No mention of session-per-user restriction in Keycloak or API authentication documentation.
- File: README.md — Keycloak is used for authentication, but no configuration for limiting concurrent sessions per user is described.
- Requirement: NOT SATISFIED — No static configuration or code artifact found that enforces a maximum number of concurrent sessions per user.

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
- Control requires: The application must clear temporary storage and cookies when the session is terminated and must not store authentication information (username/password) in cookies or local storage.
- File: README.md — Keycloak is used for authentication; session management is via JWT tokens, but no explicit mention of cookie clearing or local storage handling on logout.
- File: api/README.md — API uses JWT tokens in Authorization header; no evidence of cookies or local storage usage by backend.
- File: ui/src/components/video-player/video-player.tsx — No code related to authentication cookies or local storage management.
- File: ui/vitest.setup.ts — Mocks authentication for tests, but does not address cookie/local storage handling.
- Requirement: PARTIALLY SATISFIED — No evidence of credentials being stored in cookies/local storage, but no explicit code or configuration found that clears all temporary storage/cookies on logout. UI logout/cleanup logic not visible in provided files.

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
- Control requires: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800 (8 hours), which exceeds the 15 minute (900 seconds) requirement.
- File: README.md — Keycloak session management described, but no evidence of a 15-minute idle timeout for non-privileged users.
- Requirement: NOT SATISFIED — Session idle timeout is set to 8 hours, not 15 minutes, for all users.

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
- Control requires: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800 (8 hours), applies to all users including admin; no evidence of a separate, shorter timeout for admin users.
- File: README.md — No mention of differentiated session timeout for admin users.
- Requirement: NOT SATISFIED — No static configuration found for a 10-minute idle timeout for admin users; current setting is 8 hours for all.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.
- File: README.md — Keycloak is used for authentication; UI and API both depend on Keycloak, which provides a logout endpoint and UI logout capability.
- File: ui/README.md (not shown, but referenced) — Frontend is React-based and integrates with Keycloak; standard Keycloak integration provides logout.
- File: api/README.md — API uses JWT tokens from Keycloak; Keycloak provides logout endpoint.
- File: deploy/keycloak/dev-realm.json — Keycloak realm is configured for standard OpenID Connect flows, which include logout.
- Requirement: SATISFIED — Keycloak integration provides user-initiated logoff capability via standard OIDC logout endpoint.

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
- Control requires: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.
- File: README.md — No mention of explicit logoff message in UI or API documentation.
- File: ui/src/components/video-player/video-player.tsx — No code for displaying a logoff message found.
- File: ui/vitest.setup.ts — No evidence of logoff message handling in test setup.
- Requirement: NOT SATISFIED — No static evidence of an explicit logoff message being displayed to users upon logout.

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
- Control requires: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage (e.g., data marking/classification).
- File: README.md — No mention of data marking, classification, or security attributes associated with stored information.
- File: api/README.md — No evidence of data marking or security attribute fields in storage schema documentation.
- File: pointcloud-project/colmap_ingest.py — Database schema for point cloud data does not include fields for security attributes or data markings.
- Requirement: NOT SATISFIED — No static evidence of security attribute association with stored information.

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
- Control requires: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process (e.g., data marking/classification during processing).
- File: README.md — No mention of data marking or security attribute propagation during processing.
- File: api/app/process/router.py — No evidence of security attribute handling in processing endpoints.
- File: pointcloud-project/colmap_ingest.py — No code for propagating security attributes during processing.
- Requirement: NOT SATISFIED — No static evidence of security attribute association with information in process.

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
- Control requires: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission (e.g., data marking/classification during transmission).
- File: README.md — No mention of data marking or security attribute propagation during transmission.
- File: api/README.md — No evidence of security attribute handling in API transmission or response schemas.
- Requirement: NOT SATISFIED — No static evidence of security attribute association with information in transmission.

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
- Control requires: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions (e.g., TLS enforced).
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is configured for HTTPS (port 443) and requires an ACM certificate (AcmCertificateArn), indicating TLS is used for external access.
- File: README.md — UI and API are accessed via HTTP in local development, but production deployment references HTTPS via ALB.
- File: deploy/terraform/kubernetes/ingress.yaml (not shown) — Not available for review; would typically enforce TLS at ingress.
- Requirement: PARTIALLY SATISFIED — ALB is configured for HTTPS/TLS in production, but static evidence for backend/internal service encryption (e.g., API/UI communication) is not shown. No evidence of TLS enforcement for all internal/external endpoints.

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
- Control requires: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions (e.g., TLS enforced).
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is configured for HTTPS (port 443) and requires an ACM certificate (AcmCertificateArn), indicating TLS is used for external access.
- File: README.md — UI and API are accessed via HTTP in local development, but production deployment references HTTPS via ALB.
- Requirement: PARTIALLY SATISFIED — ALB is configured for HTTPS/TLS in production, but static evidence for backend/internal service encryption (e.g., API/UI communication) is not shown. No evidence of TLS enforcement for all internal/external endpoints.

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
- Control requires: Applications with SOAP messages requiring integrity must include Message ID, Service Request, Timestamp, SAML Assertion, and all elements must be digitally signed.
- File: README.md — No mention of SOAP or WS-Security; all APIs are RESTful (FastAPI, OpenID Connect, JWT, etc.).
- File: api/README.md — API is RESTful, not SOAP-based.
- Requirement: NOT APPLICABLE — Application does not utilize SOAP messages.

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
- Control requires: Messages protected with WS_Security must use time stamps with creation and expiration times.
- File: README.md — No mention of WS-Security or SOAP; all APIs are RESTful (FastAPI, OpenID Connect, JWT, etc.).
- File: api/README.md — API is RESTful, not SOAP-based.
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
- Control requires: Validity periods must be verified on all application messages using WS-Security or SAML assertions.
- File: README.md — No mention of WS-Security or SAML assertions; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
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
- Control requires: The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.
- File: README.md — No mention of SAML assertions; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
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
- Control requires: The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.
- File: README.md — No mention of SAML assertions or WS-Security tokens; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions or WS-Security tokens.

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
- Control requires: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.
- File: README.md — No mention of SAML assertions; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
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
- Control requires: The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.
- File: README.md — No mention of SAML assertions; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
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
- Control requires: The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.
- File: README.md — No mention of SAML assertions; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
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
- Control requires: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.
- File: README.md — No mention of SAML assertions or SessionIndex; authentication is via OpenID Connect/JWT.
- File: api/README.md — API is RESTful, not SOAP-based; no SAML assertion handling.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions or SessionIndex.

Remediation:
Encrypt messages when the SessionIndex is tied to privacy data.

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses Keycloak for centralized account management and authentication, providing automated mechanisms for account management functions.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system: ... User Management: Organizational group hierarchy with automatic role assignment ... Session Management: Secure token-based sessions with configurable timeouts"
- File: api/README.md — "The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header. ... The API integrates with Keycloak for authentication and authorization. ... The authentication happens before the endpoint function executes: ... User claims and roles are decoded ... User object is injected into the endpoint function"
- File: deploy/keycloak/dev-realm.json — "registrationAllowed": true, "users": [ ... ], "groups": [ ... ], "roles": { ... }, "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: deploy/keycloak/dev-realm.json — "bruteForceProtected": true, "failureFactor": 3, "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800, "ssoSessionMaxLifespan": 32400
- Automated account management is enforced via Keycloak, including registration, group/role assignment, and session management. No evidence of local user accounts circumventing Keycloak.
- Requirement: SATISFIED — Centralized, automated account management is enforced via Keycloak realm configuration and API integration.

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
- The application does not use shared or group application accounts; all user accounts are individual and mapped to specific users with unique credentials.
- File: deploy/keycloak/dev-realm.json — All users listed under "users" have unique usernames and credentials. No shared/group accounts are defined.
- File: README.md — "Keycloak provides ... User Management: Organizational group hierarchy with automatic role assignment" (groups are for RBAC, not shared credentials).
- Requirement: NOT APPLICABLE — No shared/group accounts are present or required by the application architecture.

Remediation:
Create a procedure for deleting either member accounts or the entire group account when members leave the group.

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence found of a mechanism to create or manage temporary user accounts with automatic removal or disabling after 72 hours.
- File: deploy/keycloak/dev-realm.json — No user account has a temporary flag or expiration attribute. All users have "enabled": true and no expiration or temporary account metadata.
- File: README.md, api/README.md — No mention of temporary account lifecycle or expiration settings.
- Requirement: PARTIALLY SATISFIED — No evidence of temporary account support or automatic expiration after 72 hours. Missing: explicit temporary account creation and timed disabling/removal.

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
- No evidence of emergency accounts being used or supported in the application.
- File: deploy/keycloak/dev-realm.json — No user account is marked as emergency or has any special emergency-related attribute.
- File: README.md, api/README.md — No mention of emergency accounts or related procedures.
- Requirement: NOT APPLICABLE — Emergency accounts are not used in this application.

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
- No evidence found of automatic disabling of accounts after 35 days of inactivity.
- File: deploy/keycloak/dev-realm.json — No attribute or policy for account inactivity timeout or disabling after inactivity.
- File: README.md, api/README.md — No mention of inactivity-based disabling or expiration.
- Requirement: NOT SATISFIED — No static configuration or code artifact enforces account disabling after 35 days of inactivity.

Remediation:
Design and configure the application to expire user accounts after 35 days of inactivity.

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- All application user accounts are managed centrally via Keycloak, and only essential user accounts are present.
- File: deploy/keycloak/dev-realm.json — All users are individually listed with unique usernames and mapped to roles/groups. No evidence of unnecessary or default accounts beyond those required for development/testing.
- File: README.md — "Default Admin Credentials (development only): Username: admin ... Note: Change default credentials before deploying to production environments."
- File: api/README.md — "Development Users: Two test users are pre-configured in the development realm ..."
- Requirement: SATISFIED — All user accounts are explicitly defined and managed; unnecessary accounts are not present.

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
- No static evidence found of audit logging for account creation events.
- File: deploy/keycloak/dev-realm.json — No audit log configuration present.
- File: README.md, api/README.md — No mention of audit log location or logging of account creation events.
- Requirement: PARTIALLY SATISFIED — Keycloak may provide audit logging, but no static configuration or log destination is referenced in the provided files. Missing: explicit log configuration or log file path for account creation events.

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
- No static evidence found of audit logging for account modification events.
- File: deploy/keycloak/dev-realm.json — No audit log configuration present.
- File: README.md, api/README.md — No mention of audit log location or logging of account modification events.
- Requirement: PARTIALLY SATISFIED — Keycloak may provide audit logging, but no static configuration or log destination is referenced in the provided files. Missing: explicit log configuration or log file path for account modification events.

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
- No static evidence found of audit logging for account disabling actions.
- File: deploy/keycloak/dev-realm.json — No audit log configuration present.
- File: README.md, api/README.md — No mention of audit log location or logging of account disabling events.
- Requirement: PARTIALLY SATISFIED — Keycloak may provide audit logging, but no static configuration or log destination is referenced in the provided files. Missing: explicit log configuration or log file path for account disabling events.

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
- No static evidence found of audit logging for account removal actions.
- File: deploy/keycloak/dev-realm.json — No audit log configuration present.
- File: README.md, api/README.md — No mention of audit log location or logging of account removal events.
- Requirement: PARTIALLY SATISFIED — Keycloak may provide audit logging, but no static configuration or log destination is referenced in the provided files. Missing: explicit log configuration or log file path for account removal events.

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
- No evidence found of notification to system administrators (SAs) or ISSOs when accounts are created.
- File: deploy/keycloak/dev-realm.json — No configuration for notification recipients or notification mechanism for account creation.
- File: README.md, api/README.md — No mention of admin notification or alerting on account creation.
- Requirement: NOT SATISFIED — No static configuration or code artifact for SA/ISSO notification on account creation.

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
- No evidence found of notification to system administrators (SAs) or ISSOs when accounts are modified.
- File: deploy/keycloak/dev-realm.json — No configuration for notification recipients or notification mechanism for account modification.
- File: README.md, api/README.md — No mention of admin notification or alerting on account modification.
- Requirement: NOT SATISFIED — No static configuration or code artifact for SA/ISSO notification on account modification.

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
- No evidence found of notification to system administrators (SAs) or ISSOs when accounts are disabled.
- File: deploy/keycloak/dev-realm.json — No configuration for notification recipients or notification mechanism for account disabling.
- File: README.md, api/README.md — No mention of admin notification or alerting on account disabling.
- Requirement: NOT SATISFIED — No static configuration or code artifact for SA/ISSO notification on account disabling.

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
- No evidence found of notification to system administrators (SAs) or ISSOs when accounts are removed.
- File: deploy/keycloak/dev-realm.json — No configuration for notification recipients or notification mechanism for account removal.
- File: README.md, api/README.md — No mention of admin notification or alerting on account removal.
- Requirement: NOT SATISFIED — No static configuration or code artifact for SA/ISSO notification on account removal.

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
- No static evidence found of audit logging for account enabling actions.
- File: deploy/keycloak/dev-realm.json — No audit log configuration present.
- File: README.md, api/README.md — No mention of audit log location or logging of account enabling events.
- Requirement: PARTIALLY SATISFIED — Keycloak may provide audit logging, but no static configuration or log destination is referenced in the provided files. Missing: explicit log configuration or log file path for account enabling events.

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
- No evidence found of notification to system administrators (SAs) or ISSOs when accounts are enabled.
- File: deploy/keycloak/dev-realm.json — No configuration for notification recipients or notification mechanism for account enabling.
- File: README.md, api/README.md — No mention of admin notification or alerting on account enabling.
- Requirement: NOT SATISFIED — No static configuration or code artifact for SA/ISSO notification on account enabling.

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
- No documentation found in the provided files that explicitly identifies application data elements and their protection requirements.
- File: README.md — Describes system architecture and data flow, but does not enumerate data elements or document specific protection requirements.
- File: api/README.md, ui/README.md — No data protection requirements documentation found.
- Requirement: NOT SATISFIED — Missing explicit documentation of data elements and their protection requirements.

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
- No evidence found of organization-defined data mining detection techniques implemented in the application.
- File: README.md, api/README.md — No mention of query rate limiting, automated alarming on atypical query events, limiting records per query, or data dump prevention.
- File: api/app/process/router.py — No endpoints or logic for query throttling or data mining detection.
- Requirement: NOT SATISFIED — No static configuration or code artifact for data mining detection or prevention.

Remediation:
Utilize and implement data mining protections when requirements specify it.

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application enforces approved authorizations for logical access to information and system resources via Keycloak RBAC and API-level role checks.
- File: deploy/keycloak/dev-realm.json — Roles and groups are defined for RBAC: "roles": { ... }, "groups": [ ... ]
- File: api/README.md — "Role-Based Access Control: The API implements role-based access control (RBAC) for protected endpoints. ... Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin ... All endpoints except /health require authentication."
- File: api/app/process/router.py — API endpoints are protected via FastAPI dependency injection, requiring authenticated users with specific roles for access.
- Requirement: SATISFIED — Access control is enforced via Keycloak RBAC and API endpoint role checks.

Remediation:
Design or configure the application to enforce access to application resources.

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence found of discretionary access control (DAC) policies allowing users to set permissions on application data or objects they control.
- File: deploy/keycloak/dev-realm.json — RBAC is implemented, but no DAC features are present.
- File: README.md, api/README.md — No mention of user-controlled sharing or permission assignment on resources.
- Requirement: NOT SATISFIED — No static configuration or code artifact for discretionary access control (DAC) policies.

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
- Control requires enforcement of information flow within the system based on organization-defined policies (e.g., data labels, rulesets, policies).
- File: README.md — Describes multi-modal AI video analysis, 3D scene reconstruction, and technical document retrieval, but does not mention explicit data labeling or flow control enforcement mechanisms.
- File: api/README.md — Describes API endpoints and RBAC via Keycloak, but no evidence of data flow control based on data labels or policies.
- File: api/app/process/router.py — API endpoints for processing, but no evidence of data labeling or flow control enforcement.
- File: vlm-testing/fpv_analyzer_rag.py — Implements document chunking and metadata for vector search, but no evidence of data flow control enforcement.
- File: deploy/keycloak/dev-realm.json — RBAC roles and groups are defined, but these are for access control, not information flow control.
- No evidence of data labeling, rulesets, or policy-based flow control in any provided code or configuration.
- Requirement: PARTIALLY SATISFIED — RBAC is present, but no static evidence of information flow control based on data labels or policies.

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
- Control requires enforcement of information flow between interconnected systems based on organization-defined policies (e.g., data labels, rulesets, policies).
- File: README.md — Describes integration with external systems (e.g., AWS S3, Qdrant, Bedrock), but does not mention explicit data flow control between systems.
- File: api/README.md — Describes API integration with Keycloak, S3, Qdrant, but no evidence of policy-based flow control between systems.
- File: api/app/process/router.py — API endpoints for processing, but no evidence of data labeling or flow control enforcement between systems.
- File: vlm-testing/fpv_analyzer_rag.py — Integrates with Qdrant, but no evidence of flow control enforcement.
- File: deploy/keycloak/dev-realm.json — RBAC roles and groups are defined, but these are for access control, not information flow control between systems.
- No evidence of data labeling, rulesets, or policy-based flow control between interconnected systems in any provided code or configuration.
- Requirement: PARTIALLY SATISFIED — RBAC is present, but no static evidence of information flow control between interconnected systems based on data labels or policies.

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
- File: deploy/keycloak/dev-realm.json — Defines roles (admin, role_maintainer, role_engineer, etc.) and assigns them to users. RBAC is enforced via Keycloak.
- File: api/README.md — 'Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin.'
- File: api/app/process/router.py — No explicit role checks in endpoint definitions; relies on FastAPI dependency injection and Keycloak RBAC (see README.md for explanation).
- File: deploy/aws/iris-stack.yaml — EC2 and RDS security groups restrict access, but OS-level user/group membership and file permissions are not shown in code.
- No static evidence of OS user/group membership, file/directory permissions, or explicit prevention of privilege escalation in application code.
- Requirement: PARTIALLY SATISFIED — RBAC is present for API endpoints, but OS-level permissions and file/directory ownership are not statically verifiable from provided artifacts.

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
- Control requires that the application executes without excessive account permissions (OS and database).
- File: deploy/aws/iris-stack.yaml — EC2 instance profile and IAM role are defined, but the actual permissions granted to the application process are not shown in code. RDS security group restricts access to EC2 SG only.
- File: api/README.md — No evidence of application running as root or with excessive OS/database privileges. No explicit user/group configuration for the application process.
- File: deploy/db/init-multiple-dbs.sh — Creates additional databases, but does not assign excessive privileges.
- No static evidence of application process user/group membership or database user privileges beyond what is required for operation.
- Requirement: PARTIALLY SATISFIED — No evidence of excessive permissions, but also no explicit evidence of least-privilege configuration for application OS/database accounts.

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
- Control requires auditing the execution of privileged functions (e.g., admin actions, configuration changes).
- File: api/README.md — Describes RBAC and admin endpoints, but does not mention audit logging of privileged actions.
- File: api/app/process/router.py — No evidence of logging for privileged/admin actions in endpoint implementations.
- File: api/app/process/__init__.py — No audit logging present.
- File: api/app/process/services/scene_summarization.py — Logging is present for summarization operations, but not for privileged/admin actions.
- File: deploy/keycloak/dev-realm.json — No evidence of audit logging configuration for privileged actions.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for privileged function execution.

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of account lockout after 3 failed logon attempts within 15 minutes.
- File: deploy/keycloak/dev-realm.json —
- "bruteForceProtected": true
- "failureFactor": 3
- "maxFailureWaitSeconds": 900
- "permanentLockout": false
- These settings enforce account lockout after 3 failed attempts within a 15-minute window, satisfying the control.
- Requirement: SATISFIED — Keycloak realm configuration enforces account lockout after 3 failed logon attempts in 15 minutes.

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
- Control requires an approved process for unlocking locked user accounts, with ISSO/ISSM approval.
- File: deploy/keycloak/dev-realm.json — No evidence of an explicit unlock process or documentation of ISSO/ISSM approval for account unlocks.
- File: README.md, api/README.md — No mention of account unlock process or approval workflow.
- Requirement: NOT SATISFIED — No static evidence of an approved process for unlocking locked user accounts.

Remediation:
Create a standard approved process for unlocking locked application accounts which includes validating user identity prior to unlocking the account.

Use that process when unlocking application user accounts.

---

### 48. APSC-DV-000550 | SV-222434r960843

- Rule ID: SV-222434r960843
- Severity: low
- Rule Title: The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires display of the Standard Mandatory DoD Notice and Consent Banner before granting access to the application (if interactive UI exists).
- File: deploy/keycloak/themes/README.md — Custom Keycloak login theme is implemented, and Keycloak is the authentication gateway for both UI and API.
- File: deploy/keycloak/dev-realm.json — "loginTheme": "iris"
- File: ui/.env.example — Configures Keycloak as SSO authority for UI.
- File: README.md — All user authentication is routed through Keycloak, which can be configured to display the DoD banner as part of the login theme.
- Requirement: SATISFIED — Interactive UI exists and Keycloak login theme can be configured to display the DoD banner before access.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the DoD banner to remain on screen until users acknowledge usage conditions and take explicit action to log on.
- File: deploy/keycloak/themes/README.md — Describes custom Keycloak login theme, but no explicit evidence that the banner requires user acknowledgment before proceeding.
- File: deploy/keycloak/dev-realm.json — "loginTheme": "iris"
- No static evidence of a required acknowledgment action for the DoD banner in the provided theme documentation or configuration.
- Requirement: PARTIALLY SATISFIED — Banner is displayed via Keycloak theme, but no evidence of explicit acknowledgment requirement.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires display of the DoD banner before granting access to a publicly accessible application.
- File: README.md — Application is web-based and publicly accessible via ALB (see deploy/aws/iris-stack.yaml).
- File: deploy/keycloak/themes/README.md — Custom Keycloak login theme is implemented for all authentication.
- File: deploy/keycloak/dev-realm.json — "loginTheme": "iris"
- Requirement: SATISFIED — Publicly accessible application displays DoD banner via Keycloak login theme before access.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires display of the time and date of the user's last successful logon in the user interface.
- File: deploy/keycloak/dev-realm.json — No evidence of last logon time display in UI or Keycloak configuration.
- File: ui/.env.example, ui/src/components/video-player/video-player.tsx — No evidence of last logon time display in UI code.
- Requirement: NOT SATISFIED — No static evidence of last successful logon time being displayed to users.

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
- Control requires non-repudiation (e.g., digital signatures) for organization-defined actions.
- File: README.md, api/README.md — No mention of digital signatures or non-repudiation requirements for application users.
- File: deploy/keycloak/dev-realm.json — No evidence of digital signature or non-repudiation configuration.
- Requirement: NOT APPLICABLE — Application is not required to provide non-repudiation services for users per documentation.

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
- Control applies only if the application provides audit record aggregation from multiple system components.
- File: README.md, api/README.md — No evidence that the application aggregates audit records from multiple systems; logging is per component/service.
- Requirement: NOT APPLICABLE — Application does not provide audit record aggregation.

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
- Control requires audit record generation for creation of session IDs.
- File: api/README.md — Describes JWT-based authentication and session management via Keycloak, but does not mention audit logging for session creation.
- File: deploy/keycloak/dev-realm.json — No evidence of session creation audit logging.
- File: api/app/process/router.py — No evidence of session creation audit logging.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for session ID creation.

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
- Control requires audit record generation for destruction of session IDs.
- File: api/README.md — Describes JWT-based authentication and session management via Keycloak, but does not mention audit logging for session destruction.
- File: deploy/keycloak/dev-realm.json — No evidence of session destruction audit logging.
- File: api/app/process/router.py — No evidence of session destruction audit logging.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for session ID destruction.

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
- Control requires audit record generation for renewal of session IDs (e.g., privilege escalation).
- File: api/README.md — Describes JWT-based authentication and session management via Keycloak, but does not mention audit logging for session renewal or privilege escalation.
- File: deploy/keycloak/dev-realm.json — No evidence of session renewal audit logging.
- File: api/app/process/router.py — No evidence of session renewal audit logging.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for session ID renewal.

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
- Control requires that sensitive data (e.g., passwords, session IDs, SSNs) are not written to application logs.
- File: api/app/process/services/scene_summarization.py — Logging is present for summarization operations, but no evidence of sensitive data being logged. However, no explicit filtering or redaction of sensitive data is shown.
- File: api/README.md — No mention of log redaction or sensitive data handling in logs.
- File: api/app/process/router.py — No evidence of sensitive data logging, but also no explicit safeguards.
- Requirement: PARTIALLY SATISFIED — No evidence of sensitive data being logged, but also no explicit safeguards or filtering present in static code.

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
- Control requires audit record generation for session timeouts.
- File: api/README.md — Describes session management via Keycloak, but does not mention audit logging for session timeouts.
- File: deploy/keycloak/dev-realm.json — No evidence of session timeout audit logging.
- File: api/app/process/router.py — No evidence of session timeout audit logging.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for session timeouts.

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
- Control requires that a time stamp is recorded for each event in application logs.
- File: api/app/process/services/scene_summarization.py — Logging is present (e.g., logger.info), but log format and inclusion of timestamps are not shown in static code.
- File: api/app/logging_config.py (not included in context) — May define log format, but not visible.
- Requirement: PARTIALLY SATISFIED — Logging is present, but no static evidence that time stamps are included in all log events.

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
- Control requires audit record generation for HTTP headers (User-Agent, Referer, GET, POST).
- File: api/README.md, api/app/process/router.py — No evidence of HTTP header logging in API endpoints or documentation.
- File: README.md — No mention of HTTP header logging.
- Requirement: NOT SATISFIED — No static evidence of HTTP header logging in application logs.

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
- No explicit evidence of IP address logging is present in the provided FastAPI router code (api/app/process/router.py) or in the RAG services (api/app/rag/services.py).
- No logging configuration or middleware code is present in the reviewed files that would capture and log client IP addresses for API requests.
- The README.md and api/README.md reference logging and audit requirements, but do not specify IP address capture in logs.
- Requirement: PARTIALLY SATISFIED — Logging is referenced, but there is no static evidence that connecting IP addresses are recorded in audit logs. Logging configuration and middleware code are missing from the provided context.

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
- The API uses JWT-based authentication via Keycloak (api/README.md: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.').
- Role-based access control is enforced via dependency injection (api/README.md: 'All API endpoints (except /health) use FastAPI dependency injection for authentication').
- However, there is no evidence in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py) that log entries include the user ID or username for each event.
- No logging statements or audit log examples are present in the reviewed files.
- Requirement: PARTIALLY SATISFIED — Authentication is enforced and user identity is available in the request context, but there is no static evidence that user IDs are recorded in audit logs.

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
- No evidence of privilege granting operations or corresponding audit logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- The api/README.md describes RBAC and admin endpoints, but does not mention audit logging for privilege changes.
- No log statements or audit trail code for privilege grants are present in the reviewed files.
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
- No evidence of security object access logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- No log statements or audit trail code for access attempts to security objects are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for access to security objects.

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
- No evidence of security level access logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- No log statements or audit trail code for access attempts to security levels are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for access to security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to access categories of information (e.g., classification levels).
- No evidence of compartmentalized data or category-based access controls is present in the provided code or documentation.
- No log statements or audit trail code for access attempts to protected categories of information are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for access to categories of information.

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
- No evidence of privilege modification operations or corresponding audit logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- The api/README.md describes RBAC and admin endpoints, but does not mention audit logging for privilege modifications.
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
- No evidence of security object modification logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- No log statements or audit trail code for modification attempts to security objects are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for modification of security objects.

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
- No evidence of security level modification logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- No log statements or audit trail code for modification attempts to security levels are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for modification of security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to modify categories of information (e.g., classification levels).
- No evidence of compartmentalized data or category-based modification controls is present in the provided code or documentation.
- No log statements or audit trail code for modification attempts to protected categories of information are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for modification of categories of information.

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
- No evidence of privilege deletion operations or corresponding audit logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
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
- No evidence of security level deletion logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- Requirement: NOT SATISFIED — No static evidence of audit records for deletion of security levels.

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
- No evidence of database security object deletion logging is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py).
- Requirement: NOT SATISFIED — No static evidence of audit records for deletion of database security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for successful/unsuccessful attempts to delete categories of information (e.g., classification levels).
- No evidence of compartmentalized data or category-based deletion controls is present in the provided code or documentation.
- No log statements or audit trail code for deletion attempts to protected categories of information are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for deletion of categories of information.

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
- The api/README.md describes JWT-based authentication via Keycloak and mentions that authentication failures return 401 Unauthorized automatically.
- However, there is no evidence in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py) that logon attempts (successful or unsuccessful) are recorded in audit logs.
- No log statements or audit trail code for authentication events are present in the reviewed files.
- Requirement: PARTIALLY SATISFIED — Authentication is enforced, but there is no static evidence that logon events are recorded in audit logs.

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
- Control requires audit records for privileged activities or other system-level access.
- The api/README.md describes admin endpoints and RBAC, but there is no evidence in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py) that privileged actions are logged.
- No log statements or audit trail code for privileged activities are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for privileged activities.

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
- Control requires audit records showing starting and ending time for user access to the system.
- The api/README.md describes session management via Keycloak, but there is no evidence in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py) that session start and end times are recorded in audit logs.
- No log statements or audit trail code for session activity are present in the reviewed files.
- Requirement: NOT SATISFIED — No static evidence of audit records for session start/end times.

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
- Control requires audit records when successful/unsuccessful accesses to objects occur.
- The provided FastAPI router code (api/app/process/router.py) and RAG services (api/app/rag/services.py) do not include log statements or audit trail code for access to application objects (files, folders, processes, modules, etc.).
- Requirement: NOT SATISFIED — No static evidence of audit records for object access.

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
- Control requires audit records for all direct access to the information system (e.g., OS commands, file system navigation, system resource manipulation).
- The application is a web-based API and UI system (see README.md, api/README.md) and does not expose direct OS access or system-level command execution to end users.
- No endpoints or UI features provide direct access to the underlying operating system.
- Requirement: NOT APPLICABLE — This is a web application with no direct OS access features.

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
- The api/README.md states: 'The API integrates with Keycloak for authentication and authorization.'
- User management is handled by Keycloak, not by the application itself.
- No evidence is present in the provided FastAPI router code (api/app/process/router.py) or RAG services (api/app/rag/services.py) that user account events are logged by the application.
- Requirement: PARTIALLY SATISFIED — User management is delegated to Keycloak, but there is no evidence that the application logs account events. If Keycloak logs are STIG compliant, this requirement may be inherited, but static evidence is not present in the application code.

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
- File: api/app/process/router.py — No explicit logging of application startup events is present in the router or endpoint definitions.
- File: api/app/process/services/scene_summarization.py — Logging is performed for processing events (e.g., logger.info("Scene summarization plan")), but there is no evidence of logging at application startup.
- File: api/app/process/services/scene_classification.py — Logging is present for processing/classification events, but not for application startup.
- File: api/app/rag/services.py — Logging is present for service-level operations, but not for application startup.
- File: api/README.md — No mention of startup logging in documentation.
- File: README.md — No mention of startup logging in documentation.
- No evidence found in provided files of a log entry such as "Application started" or similar at the point of application/service startup (e.g., in main.py or logging_config.py, which are not included in this context).
- Requirement: PARTIALLY SATISFIED — Logging is implemented for processing events, but there is no static evidence that logging is initiated at application startup. Full compliance cannot be confirmed without reviewing application entrypoint (main.py) and logging configuration.

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
- File: api/app/process/router.py — No evidence of logging shutdown events in any endpoint or router logic.
- File: api/app/process/services/scene_summarization.py — Logging is present for processing, but not for shutdown events.
- File: api/app/process/services/scene_classification.py — Logging is present for processing, but not for shutdown events.
- File: api/app/rag/services.py — Logging is present for service operations, but not for shutdown events.
- File: api/README.md, README.md — No mention of shutdown logging.
- No static evidence found of a log entry such as "Application shutting down" or similar in any provided file.
- Requirement: NOT SATISFIED — No evidence of shutdown event logging in static code or documentation.

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
- File: api/app/process/services/scene_summarization.py — Outbound connections to AWS Bedrock and S3 are made via boto3, but there is no evidence that destination IP addresses are logged.
- File: api/app/rag/services.py — Outbound connections to S3 and Bedrock are made via boto3, but no logging of destination IP addresses is present.
- File: api/app/process/services/scene_classification.py — Outbound connections to Qdrant and S3, but no logging of destination IP addresses.
- No log statements found that record the destination IP address of remote systems for any outbound connection.
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
- File: api/app/process/router.py — Endpoints process video, documents, and status, but no explicit logging of user access events is present.
- File: api/app/rag/services.py — Search and chat functions process queries, but no evidence of logging user access to data.
- File: api/README.md — Describes authentication and RBAC, but does not mention logging of user data access events.
- No log statements found that record user identity and data access events (e.g., "User X accessed document Y").
- Requirement: NOT SATISFIED — No evidence of logging user actions involving access to data.

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
- File: api/app/process/router.py — Endpoints for processing do not show explicit logging of user-initiated data changes.
- File: api/app/rag/services.py — No evidence of logging user actions that change data.
- File: api/README.md — No mention of logging data modification events.
- No log statements found that record user identity and data modification events (e.g., "User X modified Y").
- Requirement: NOT SATISFIED — No evidence of logging user actions involving changes to data.

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
- Control requires: Audit records must contain date and time of events.
- File: api/app/process/services/scene_summarization.py — All summary and metadata records include 'generated_at': datetime.utcnow().isoformat() + 'Z'.
- File: api/app/process/services/scene_classification.py — All stored metadata includes 'processed_at': datetime.utcnow().isoformat() + 'Z'.
- File: api/app/rag/services.py — S3 object listings and metadata include 'last_modified': obj['LastModified'].isoformat().
- All S3-stored JSON and JSONL records for processing and classification include ISO8601 timestamps.
- Requirement: SATISFIED — All audit records and metadata include date and time fields.

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
- File: api/app/process/services/scene_summarization.py — Logging statements include context (e.g., 'Scene summarization plan', 'session_id'), but audit records stored in S3 do not explicitly record the triggering component or function.
- File: api/app/process/services/scene_classification.py — Metadata includes 'session_id', but not the originating component or function.
- File: api/app/rag/services.py — No evidence that audit records include the component/feature/function that triggered the event.
- No log or audit record found with a field such as 'component', 'feature', or 'function' identifying the source of the event.
- Requirement: NOT SATISFIED — Audit records do not contain enough information to establish which component, feature, or function triggered the event.

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
- Control requires: When using centralized logging, application logs must include a unique identifier for the application and host.
- File: api/app/process/services/scene_summarization.py — S3 object keys include session_id and bucket name, but no explicit application or host identifier is included in log records.
- File: api/app/process/services/scene_classification.py — S3 paths include session_id, but not application or host name.
- File: api/app/rag/services.py — No evidence of application or host identifier in logs.
- File: deploy/aws/iris-stack.yaml — S3 bucket names are unique per stack, but this is not included in log records themselves.
- Requirement: NOT SATISFIED — No evidence that logs include both application and host identifiers.

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
- Control requires: Audit records must contain information to establish the outcome of events.
- File: api/app/process/services/scene_summarization.py — Processing functions return status in API responses (e.g., 'status': 'success'), but audit records in S3 do not explicitly record outcome (success/failure) for each event.
- File: api/app/process/services/scene_classification.py — Metadata includes 'status': 'completed' or 'exists', but not for all events.
- File: api/app/rag/services.py — No evidence of outcome logging for search or chat events.
- No log or audit record found with explicit outcome/result field for all events.
- Requirement: PARTIALLY SATISFIED — Some processing metadata includes outcome, but not all audit records/events include this information.

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
- Control requires: Audit records must establish the identity of any individual or process associated with the event.
- File: api/app/process/services/scene_summarization.py — Metadata includes 'session_id', but not user or process identity.
- File: api/app/process/services/scene_classification.py — Metadata includes 'session_id', but not user or process identity.
- File: api/app/rag/services.py — No evidence of user or process identity in logs or audit records.
- File: api/README.md — Describes authentication and RBAC, but does not mention logging user/process identity in audit records.
- Requirement: NOT SATISFIED — No evidence that audit records include user or process identity.

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
- Control requires: Audit records must contain full-text recording of privileged commands or individual identities of group account users.
- File: api/app/process/router.py — No evidence of logging privileged commands or group user identities.
- File: api/app/rag/services.py — No evidence of logging privileged commands or group user identities.
- File: api/README.md — No mention of privileged command logging.
- No log or audit record found with full-text of privileged commands or mapping of group account actions to individual users.
- Requirement: NOT SATISFIED — No evidence of privileged command or group user identity logging.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Application must implement transaction recovery logs when transaction based.
- File: api/app/process/services/scene_summarization.py — No evidence of transaction recovery logs.
- File: api/app/process/services/scene_classification.py — No evidence of transaction recovery logs.
- File: api/app/rag/services.py — No evidence of transaction recovery logs.
- File: api/README.md — No mention of transaction recovery logging or configuration.
- Requirement: NOT SATISFIED — No evidence of transaction recovery logs in application code or documentation.

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
- Control requires: Application must provide centralized management and configuration of audit record content for all components.
- File: api/app/process/services/scene_summarization.py — Logging is implemented per service/module, no evidence of centralized log management/configuration.
- File: api/app/process/services/scene_classification.py — Logging is implemented per service/module, no evidence of centralized log management/configuration.
- File: api/app/rag/services.py — No evidence of centralized log management/configuration.
- File: api/README.md — No mention of centralized log management or configuration interface.
- Requirement: NOT SATISFIED — No evidence of centralized management/configuration of audit record content.

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
- Control requires: Application must off-load audit records onto a different system or media than the system being audited, unless using centralized logging (then Not Applicable).
- File: api/app/process/services/scene_summarization.py — Audit records (summaries, metadata) are stored in S3 via S3Manager.put_object().
- File: api/app/process/services/scene_classification.py — Classification results are stored in S3 via S3Manager.put_object().
- File: api/app/rag/services.py — No evidence of audit record offloading, but S3 is used for storage.
- S3 is an external system, so audit records are off-loaded from the application host.
- However, there is no evidence of a formal schedule or automation for offloading logs if not using S3.
- Requirement: PARTIALLY SATISFIED — Audit records are off-loaded to S3, but no evidence of schedule/automation for other logs or risk acceptance documentation.

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
- File: api/app/process/services/scene_summarization.py — Audit records are written to S3 via S3Manager.put_object().
- File: api/app/process/services/scene_classification.py — Classification results are written to S3 via S3Manager.put_object().
- File: api/app/rag/services.py — No evidence of application logs (as opposed to data artifacts) being written to a centralized log repository.
- No evidence of application logs (stdout, error, or audit logs) being shipped to a centralized log repository (e.g., CloudWatch, ELK, etc.).
- Requirement: PARTIALLY SATISFIED — Data artifacts are stored in S3, but application logs are not shown to be centralized.

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
- Control requires: Application must provide immediate warning to SA/ISSO when audit record storage reaches 75% of capacity, unless using centralized logging with alarming (then Not Applicable).
- File: api/app/process/services/scene_summarization.py — No evidence of storage capacity monitoring or alarming.
- File: api/app/process/services/scene_classification.py — No evidence of storage capacity monitoring or alarming.
- File: api/app/rag/services.py — No evidence of storage capacity monitoring or alarming.
- File: deploy/aws/iris-stack.yaml — S3 bucket is used for storage, but no evidence of alarming configuration for capacity thresholds.
- Requirement: NOT SATISFIED — No evidence of storage capacity alarming for audit logs.

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
- Control requires: Application must provide immediate real-time alert to SA/ISSO for all audit failure events, unless using centralized logging with alarming (then Not Applicable).
- File: api/app/process/services/scene_summarization.py — No evidence of audit failure detection or alerting.
- File: api/app/process/services/scene_classification.py — No evidence of audit failure detection or alerting.
- File: api/app/rag/services.py — No evidence of audit failure detection or alerting.
- Requirement: NOT SATISFIED — No evidence of real-time alerting for audit failure events.

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
- Control requires: Application must alert ISSO/SA in the event of an audit processing failure, unless using centralized logging with alarming (then Not Applicable).
- File: api/app/process/services/scene_summarization.py — No evidence of audit processing failure detection or alerting.
- File: api/app/process/services/scene_classification.py — No evidence of audit processing failure detection or alerting.
- File: api/app/rag/services.py — No evidence of audit processing failure detection or alerting.
- Requirement: NOT SATISFIED — No evidence of alerting on audit processing failure.

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
- Control requires: Application must shut down by default upon audit failure (unless availability is an overriding concern), or take compensating action.
- File: api/app/process/services/scene_summarization.py — No evidence of application shutdown or compensating action on audit/logging failure.
- File: api/app/process/services/scene_classification.py — No evidence of application shutdown or compensating action on audit/logging failure.
- File: api/app/rag/services.py — No evidence of application shutdown or compensating action on audit/logging failure.
- Requirement: NOT SATISFIED — No evidence of application shutdown or compensating action on audit failure.

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
- Control requires: Application must provide capability to centrally review and analyze audit records from multiple components, unless using centralized logging (then Not Applicable).
- File: api/app/process/services/scene_summarization.py — Audit records are stored in S3, but no evidence of a centralized review/analysis interface.
- File: api/app/process/services/scene_classification.py — Audit records are stored in S3, but no evidence of a centralized review/analysis interface.
- File: api/app/rag/services.py — No evidence of centralized review/analysis capability for audit records.
- Requirement: NOT SATISFIED — No evidence of centralized review/analysis capability for audit records from multiple components.

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
- The control requires the application to provide filtering of audit records based on user, event type, date/time, system resource, IP, object accessed, event level, and keywords.
- No evidence of an application-level audit log filtering utility or API endpoint for audit log filtering was found in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- The API documentation (api/README.md) describes logging and processing endpoints but does not mention audit log filtering capabilities.
- No log management or filtering UI or API is described in the UI code (ui/README.md, ui/src/components/video-player/video-player.tsx).
- Requirement: PARTIALLY SATISFIED — Logging is present, but no static evidence of audit log filtering capability for the required criteria.

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
- The control requires on-demand audit reduction/reporting based on filtered audit event data.
- No static evidence of a reporting feature or audit reduction utility is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- The API and UI documentation do not describe any audit log reporting or filtering features.
- No endpoints or UI components for generating audit reports based on filtered audit data are present.
- Requirement: NOT SATISFIED — No static evidence of on-demand audit reduction/reporting capability.

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
- The control requires audit reduction capability for on-demand audit review and analysis.
- No static evidence of audit reduction or review features is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No endpoints or UI features for audit review or reduction are documented.
- Requirement: NOT SATISFIED — No static evidence of audit reduction for on-demand review/analysis.

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
- The control requires audit reduction capability to support after-the-fact investigations.
- No static evidence of audit reduction or filtering features for investigations is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No endpoints or UI features for after-the-fact audit review are documented.
- Requirement: NOT SATISFIED — No static evidence of audit reduction for investigations.

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
- No static evidence of audit report generation features is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No endpoints or UI features for generating audit reports are documented.
- Requirement: NOT SATISFIED — No static evidence of audit report generation for on-demand review/analysis.

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
- The control requires report generation capability for on-demand reporting requirements.
- No static evidence of customizable, immediate, ad-hoc audit log reporting is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No endpoints or UI features for generating customizable audit reports are documented.
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
- The control requires report generation capability for after-the-fact investigations.
- No static evidence of after-the-fact audit report generation is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No endpoints or UI features for generating audit reports for investigations are documented.
- Requirement: NOT SATISFIED — No static evidence of after-the-fact audit report generation.

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
- The control requires audit reduction (event filtering) to not alter original content or time ordering of audit records.
- No static evidence of audit reduction or filtering features is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes audit reduction or guarantees about not altering log content/order.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or preservation of original log content/order.

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
- The control requires report generation to not alter original content or time ordering of audit records.
- No static evidence of audit report generation features is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes audit report generation or guarantees about not altering log content/order.
- Requirement: NOT SATISFIED — No static evidence of audit report generation or preservation of original log content/order.

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
- The control requires use of internal system clocks for audit record timestamps.
- No static evidence of audit log timestamping or use of system clock for audit records is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- While video and summary generation code (e.g., api/app/process/services/scene_summarization.py) uses datetime.utcnow() for generated_at fields, this is for video summaries, not audit logs.
- Requirement: PARTIALLY SATISFIED — UTC timestamps are used for video summaries, but no evidence for audit log timestamping.

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
- The control requires audit record timestamps to be mapped to UTC or GMT.
- No static evidence of audit log timestamping or UTC/GMT mapping for audit records is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- Video summary code uses datetime.utcnow().isoformat() + 'Z' for generated_at, which is UTC, but this is not for audit logs.
- Requirement: PARTIALLY SATISFIED — UTC timestamps are used for video summaries, but no evidence for audit log timestamping.

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
- The control requires audit record timestamps to have at least one second granularity.
- No static evidence of audit log timestamping or granularity is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- Video summary code uses datetime.utcnow().isoformat() + 'Z', which has sub-second precision, but this is not for audit logs.
- Requirement: PARTIALLY SATISFIED — Sub-second precision is used for video summaries, but no evidence for audit log timestamping.

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
- No static evidence of audit log storage location, file permissions, or access control for audit logs is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes audit log access control or role-based restrictions for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log access control.

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
- No static evidence of audit log storage location, file permissions, or access control for audit logs is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes audit log modification controls or role-based restrictions for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log modification control.

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
- No static evidence of audit log storage location, file permissions, or access control for audit logs is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes audit log deletion controls or role-based restrictions for audit data.
- Requirement: NOT SATISFIED — No static evidence of audit log deletion control.

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
- The control applies only if the application provides a distinct audit tool or module for viewing/manipulating log data.
- No static evidence of a distinct audit tool or audit tool functionality is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No audit tool executables, modules, or UI components are present in the manifest or documentation.
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
- The control applies only if the application provides a distinct audit tool or module for viewing/manipulating log data.
- No static evidence of a distinct audit tool or audit tool functionality is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No audit tool executables, modules, or UI components are present in the manifest or documentation.
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
- The control applies only if the application provides a distinct audit tool or module for viewing/manipulating log data.
- No static evidence of a distinct audit tool or audit tool functionality is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No audit tool executables, modules, or UI components are present in the manifest or documentation.
- Requirement: NOT APPLICABLE — No distinct audit tool functionality is present in the application.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit records to be backed up at least every seven days onto a different system/component.
- No static evidence of a built-in backup capability for audit records is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No backup settings or scheduled backup logic for audit logs is present in the code or documentation.
- Requirement: NOT SATISFIED — No static evidence of audit log backup capability.

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
- The control requires cryptographic mechanisms to protect the integrity of audit information.
- No static evidence of cryptographic integrity protection (e.g., hash, HMAC, digital signature) for audit logs is present in: api/app/process/router.py, api/app/process/services/summarization.py, api/app/process/services/scene_summarization.py, or any README.md files.
- No code or documentation describes integrity checks or cryptographic protection for audit logs.
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
- Control requires the application to provide a separate audit tool (file or library) for viewing/manipulating logs, and that cryptographic hashes are generated for those tools.
- No evidence in any provided file (README.md, api/README.md, process/router.py, process/services/scene_summarization.py, rag/services.py, etc.) of a separate audit tool (executable, script, or library) for log viewing/manipulation.
- Logging is referenced (e.g., app/logging_config.py, logger usage), but no standalone audit tool is present in the manifest or code.
- No documentation or code for generating or storing cryptographic hashes of audit tools.
- Requirement: NOT APPLICABLE — Application does not provide a separate audit tool as defined by the control.

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
- No evidence in any provided file (README.md, api/README.md, process/router.py, process/services/scene_summarization.py, rag/services.py, etc.) of a separate audit tool (executable, script, or library) for log viewing/manipulation.
- No process or code for periodic hash checking of audit tools.
- Requirement: NOT APPLICABLE — Application does not provide a separate audit tool as defined by the control.

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
- Control requires the application to restrict user installation of software/components/extensions.
- No evidence in any provided file (README.md, api/README.md, process/router.py, etc.) of any UI or API endpoint that allows users to install plugins, extensions, or software modules.
- The application is a backend API and frontend UI with no extension/plugin system exposed to users.
- No documentation or code for user-driven installation of software.
- Requirement: NOT APPLICABLE — Application does not provide user-accessible software installation capabilities.

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
- File: api/app/config.py — All configuration is loaded from environment variables or .env files via Pydantic Settings.
- File: api/README.md — Documents that configuration is via .env files and environment variables, with no mention of a user-facing configuration interface.
- File: deploy/aws/iris-stack.yaml — EC2 UserData and bootstrap scripts copy .env.example to .env and set permissions (chmod 600), but enforcement of OS-level file permissions is handled outside the application.
- No evidence in application code of runtime configuration change endpoints or RBAC enforcement for configuration changes.
- No explicit code for restricting access to configuration files beyond initial chmod in deployment scripts.
- Requirement: PARTIALLY SATISFIED — Application does not expose configuration changes via UI/API, but static file permissions are only set at deployment; ongoing OS-level enforcement is not visible in static code.

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
- File: api/app/config.py — Configuration is loaded from .env/environment variables; no code for logging changes to configuration.
- File: deploy/aws/iris-stack.yaml — .env file is created and permissions set, but no audit logging of changes to configuration files is implemented in code.
- No evidence of audit log entries for configuration changes in any application code or documentation.
- Requirement: NOT SATISFIED — No static evidence of audit logging for configuration changes or user attribution.

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
- Control requires the application to prevent installation of unsigned patches/components or provide a cryptographic hash for manual verification.
- No evidence in any provided file (README.md, api/README.md, process/router.py, etc.) of a mechanism to verify digital signatures or hashes of patches/components before installation.
- Application is deployed via Docker images and infrastructure-as-code (CloudFormation, Terraform), but no code or documentation for signature/hash verification of application updates.
- Requirement: NOT SATISFIED — No static evidence of digital signature/hash verification for patches or components.

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
- Control requires limiting privileges to change software libraries.
- File: api/README.md — Application libraries are installed via pip/conda and Docker images; no user-facing library update mechanism.
- File: deploy/aws/iris-stack.yaml — No explicit OS-level file permission enforcement for application library directories beyond Docker/container isolation.
- No evidence in application code of runtime library update endpoints or RBAC enforcement for library changes.
- Requirement: PARTIALLY SATISFIED — Application does not expose library update functionality, but static OS-level file permission enforcement is not visible in code.

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
- Control requires regular vulnerability assessments and retention of scan results.
- File: README.md — Section 'End-to-End Testing' describes Playwright-based E2E tests, but no mention of vulnerability scanning.
- File: .github/workflows/api-code-quality.yml, .github/workflows/ui-code-quality.yml (not shown) — May contain linting/static analysis, but no evidence of security vulnerability scanning in provided files.
- No documentation or code for automated vulnerability scanning or retention of scan results.
- Requirement: NOT SATISFIED — No static evidence of vulnerability assessment process or scan result retention.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires restricting program execution per policy/terms/conditions.
- File: README.md — No mention of application execution restrictions or enforcement of terms/conditions.
- No evidence in code or documentation of RBAC, AppLocker, or other execution restriction mechanisms beyond authentication/authorization for API endpoints.
- Requirement: NOT SATISFIED — No static evidence of program execution restriction in accordance with policy.

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
- Control applies only to configuration management or similar applications that manage system processes/configurations.
- Application is an AI-powered video analysis and knowledge management system, not a configuration management tool.
- No evidence in code or documentation of application whitelisting or deny-all, permit-by-exception execution policy for system processes.
- Requirement: NOT APPLICABLE — Application is not a configuration management or system process management tool.

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
- File: README.md — Describes modular architecture and Docker Compose overlays for dev/lambda/prod, but no explicit list of disabled features or configuration for disabling non-essential modules.
- File: api/README.md — No mention of disabling features/capabilities not required for mission.
- No evidence in code or configuration of feature flags or explicit disabling of unused modules/services.
- Requirement: NOT SATISFIED — No static evidence of non-essential capability disabling.

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
- Control requires use of only PPSM CAL-approved ports/protocols.
- File: README.md — Documents service ports: PostgreSQL (5432), Keycloak (8080), API (5000), UI (3000), Qdrant (6333/6334).
- File: deploy/aws/iris-stack.yaml — Security groups and ALB expose ports 443, 3000, 8080, 5432.
- No evidence of explicit mapping to PPSM CAL or documentation of approval for these ports.
- Requirement: PARTIALLY SATISFIED — Ports are statically defined, but no evidence of PPSM CAL mapping or approval.

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
- File: api/README.md — Describes Keycloak-based authentication and RBAC, but no mention of forced reauthentication on role change or privilege escalation.
- No evidence in code of session invalidation or reauthentication triggers on role/privilege change.
- Requirement: NOT SATISFIED — No static evidence of reauthentication enforcement on privilege escalation or role change.

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
- No evidence in code or documentation of device authentication or periodic device reauthentication settings.
- Application is user-authenticated via Keycloak; device authentication is not addressed.
- Requirement: NOT SATISFIED — No static evidence of device reauthentication configuration.

Remediation:
Configure the application to require reauthentication periodically.

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires unique identification and authentication of organizational users.
- File: api/README.md — 'Authentication' section: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'
- File: api/README.md — 'Keycloak Configuration' and 'Role-Based Access Control' sections: Keycloak realm, client ID, and roles are configured; JWT tokens are verified for all endpoints except /health.
- File: api/app/config.py — KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID settings.
- File: api/app/main.py (not shown, but referenced) — All endpoints except /health require authentication via dependency injection.
- Requirement: SATISFIED — Application enforces unique user authentication via Keycloak and JWT for all protected endpoints.

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
- File: api/README.md — 'Authentication' section: Keycloak is used for authentication, but no mention of CAC, Alt. Token, or multifactor authentication for privileged accounts.
- File: deploy/keycloak/dev-realm.json (not shown) — Not reviewed for MFA configuration.
- No evidence in code or documentation of Alt. Token or CAC enforcement for privileged accounts.
- Requirement: NOT SATISFIED — No static evidence of multifactor authentication for privileged accounts.

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
- Control requires acceptance of PIV (CAC) credentials.
- File: api/README.md — 'Authentication' section: Keycloak is used for authentication, but no mention of CAC/PIV or certificate-based authentication.
- File: deploy/keycloak/dev-realm.json (not shown) — Not reviewed for PKI configuration.
- No evidence in code or documentation of CAC/PIV credential acceptance.
- Requirement: NOT SATISFIED — No static evidence of CAC/PIV authentication support.

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
- File: api/README.md — 'Authentication' section: Keycloak is used for authentication, but no mention of CAC/PIV or certificate-based authentication.
- File: deploy/keycloak/dev-realm.json (not shown) — Not reviewed for PKI configuration.
- No evidence in code or documentation of electronic verification of CAC/PIV credentials.
- Requirement: NOT SATISFIED — No static evidence of electronic verification of CAC/PIV credentials.

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
- File: api/README.md — 'Authentication' section: Keycloak is used for authentication, but no mention of CAC/Alt. Token or multifactor authentication for non-privileged accounts.
- File: deploy/keycloak/dev-realm.json (not shown) — Not reviewed for MFA configuration.
- No evidence in code or documentation of multifactor authentication for non-privileged accounts.
- Requirement: NOT SATISFIED — No static evidence of multifactor authentication for non-privileged accounts.

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
- File: api/README.md — 'Authentication' section: Keycloak is used for authentication, but no mention of Alt. Token or multifactor authentication for local privileged access.
- File: deploy/keycloak/dev-realm.json (not shown) — Not reviewed for MFA configuration.
- No evidence in code or documentation of Alt. Token enforcement for local privileged access.
- Requirement: NOT SATISFIED — No static evidence of multifactor authentication for local privileged accounts.

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
- File: deploy/keycloak/dev-realm.json — authentication is via Keycloak with password policy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of CAC, PIV, or certificate-based authentication (e.g., CLIENT-CERT, X.509, or smart card integration) in Keycloak realm config or application documentation.
- File: api/README.md — authentication is via Keycloak using username/password and JWT tokens; no mention of multifactor or certificate-based authentication.
- Requirement: NOT SATISFIED — only single-factor (password) authentication is enforced; no static evidence of CAC or Alt. Token support.

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
- Control requires individual authentication before group authenticator use; applies only if group/shared accounts are used.
- File: deploy/keycloak/dev-realm.json — all users are provisioned as individual accounts (e.g., "maintainer1", "engineer1", "admin"). No group/shared accounts present; group membership is managed via Keycloak groups, not shared credentials.
- File: api/README.md — authentication is via individual JWT tokens; no mention of group/shared account logins.
- Requirement: NOT APPLICABLE — application does not use group or shared accounts; all access is via individual user credentials.

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
- Control requires replay-resistant authentication for privileged accounts (e.g., TLS 1.2+, Kerberos, IPSEC, SSH, cryptographic signing).
- File: deploy/keycloak/dev-realm.json — authentication is via Keycloak using JWT tokens; password policy includes hashIterations(27500) (PBKDF2), but no evidence of mutual TLS or cryptographic signing of authentication traffic.
- File: api/README.md — API uses JWT-based authentication via Keycloak; tokens are signed with RS256 and verified using JWKS. No explicit evidence of TLS enforcement for API endpoints or Keycloak.
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak's sslRequired is set to "none" in dev-realm.json, and no enforcement of TLS 1.2+ is statically confirmed for all authentication endpoints.
- Requirement: PARTIALLY SATISFIED — JWT tokens are cryptographically signed (RS256), and ALB supports HTTPS, but static evidence of TLS enforcement for all authentication traffic and replay-resistance for privileged accounts is incomplete.

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
- Control requires replay-resistant authentication for nonprivileged accounts (e.g., TLS 1.2+, Kerberos, IPSEC, SSH, cryptographic signing).
- File: deploy/keycloak/dev-realm.json — authentication is via Keycloak using JWT tokens; password policy includes hashIterations(27500), but no evidence of mutual TLS or cryptographic signing of authentication traffic.
- File: api/README.md — API uses JWT-based authentication via Keycloak; tokens are signed with RS256 and verified using JWKS. No explicit evidence of TLS enforcement for API endpoints or Keycloak.
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak's sslRequired is set to "none" in dev-realm.json, and no enforcement of TLS 1.2+ is statically confirmed for all authentication endpoints.
- Requirement: PARTIALLY SATISFIED — JWT tokens are cryptographically signed (RS256), and ALB supports HTTPS, but static evidence of TLS enforcement for all authentication traffic and replay-resistance for nonprivileged accounts is incomplete.

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
- Control requires mutual authentication (e.g., mutual TLS/client certificates) when endpoint device non-repudiation is required.
- File: deploy/keycloak/dev-realm.json — no evidence of mutual TLS or client certificate authentication (sslRequired: "none").
- File: api/README.md — authentication is via Keycloak using JWT tokens; no mention of mutual authentication or client certificate requirements.
- File: deploy/aws/iris-stack.yaml — ALB supports HTTPS with ACM certificate, but no evidence of server requesting client certificates or mutual TLS configuration.
- Requirement: NOT SATISFIED — no static evidence of mutual authentication or client certificate enforcement.

Remediation:
Configure the application to utilize mutual authentication when specified by data protection requirements.

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires authentication of all network-connected endpoint devices (e.g., SOA/web services consumers).
- File: README.md, api/README.md — application is an interactive end-user system (UI + API) with no evidence of web services or SOA endpoints for remote device consumption.
- No device-to-device or machine-to-machine authentication flows are described or configured.
- Requirement: NOT APPLICABLE — application is designed for end-user interactive access only; does not expose web services for remote device consumption.

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
- Control requires mutual SSL/TLS authentication for SOA applications handling non-releasable data.
- File: README.md, api/README.md — application is not a service-oriented architecture (SOA) system; it is an interactive end-user application.
- No evidence of SOA endpoints or mutual TLS configuration for system-to-system communication.
- Requirement: NOT APPLICABLE — application is not SOA and does not handle non-releasable data via SOA endpoints.

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
- Control requires disabling device identifiers after 35 days of inactivity unless cryptographic certificates are used.
- File: README.md, api/README.md, deploy/keycloak/dev-realm.json — no evidence of device authentication or device accounts; authentication is user-based via Keycloak.
- No device IDs or device-specific accounts are present in user management or authentication flows.
- Requirement: NOT APPLICABLE — application does not authenticate devices; only user accounts are present.

Remediation:
Configure the application to disable device accounts after 35 days of inactivity or to utilize DOD PKI certificates that provide an expiration date.

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a minimum 15-character password length.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: security-documents/keycloak.json — identical passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- Password length is enforced at 15 characters minimum by Keycloak realm policy.
- Requirement: SATISFIED — password length policy meets or exceeds 15-character minimum.

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
- Control requires at least one uppercase character in passwords.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'upperCase' or equivalent complexity rule in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no uppercase requirement.
- Requirement: NOT SATISFIED — password policy does not enforce at least one uppercase character.

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
- Control requires at least one lowercase character in passwords.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'lowerCase' or equivalent complexity rule in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no lowercase requirement.
- Requirement: NOT SATISFIED — password policy does not enforce at least one lowercase character.

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
- Control requires at least one numeric character in passwords.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'digits' or equivalent complexity rule in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no numeric requirement.
- Requirement: NOT SATISFIED — password policy does not enforce at least one numeric character.

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
- Control requires at least one special character in passwords.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'specialChars' or equivalent complexity rule in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no special character requirement.
- Requirement: NOT SATISFIED — password policy does not enforce at least one special character.

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
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'passwordChange' or similar policy enforcing minimum changed characters.
- File: security-documents/keycloak.json — same passwordPolicy, no such rule.
- Requirement: NOT SATISFIED — password policy does not enforce minimum changed characters on password change.

Remediation:
Configure the application to require the change of at least eight characters in the password when passwords are changed.

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires only cryptographic representations of passwords to be stored (no plaintext; no MD5).
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "hashIterations(27500)" (PBKDF2)
- File: security-documents/keycloak.json — same passwordPolicy: "hashIterations(27500)"
- Keycloak stores passwords using PBKDF2 with 27,500 iterations and random salt; plaintext passwords are never persisted.
- Requirement: SATISFIED — passwords are stored only as strong cryptographic hashes (PBKDF2-SHA256); no plaintext or MD5.

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
- Control requires passwords to be transmitted only over cryptographically protected channels (e.g., TLS).
- File: deploy/keycloak/dev-realm.json — sslRequired: "none"
- File: security-documents/keycloak.json — sslRequired: "none"
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak and API do not statically enforce HTTPS-only access; Keycloak realm allows non-SSL connections.
- Requirement: NOT SATISFIED — static configuration does not enforce cryptographic protection (TLS) for password transmission; sslRequired is set to "none".

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
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'minimumPasswordAge' or equivalent policy in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no minimum lifetime rule.
- Requirement: NOT SATISFIED — password policy does not enforce a minimum password lifetime.

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
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of 'expiration' or equivalent maximum lifetime rule in passwordPolicy.
- File: security-documents/keycloak.json — same passwordPolicy, no maximum lifetime rule.
- Requirement: NOT SATISFIED — password policy does not enforce a maximum password lifetime.

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
- Control requires prohibition of password reuse for at least five generations.
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "passwordHistory(3)"
- File: security-documents/keycloak.json — same passwordPolicy: "passwordHistory(3)"
- Only the last 3 passwords are prevented from reuse; requirement is 5 generations minimum.
- Requirement: NOT SATISFIED — password history policy only enforces 3 generations; must be at least 5.

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
- File: deploy/keycloak/dev-realm.json — user credentials include "temporary": false for all users; resetPasswordAllowed: false
- File: security-documents/keycloak.json — same configuration; no evidence of temporary password enforcement or forced change on first use.
- Requirement: NOT SATISFIED — no static evidence that temporary passwords are supported or enforced for first logon password change.

Remediation:
Configure the application to specify when a password is temporary and change the temporary password on the first use.

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses Keycloak for authentication and user management, with password change/reset policies enforced by Keycloak realm configuration.
- File: deploy/keycloak/dev-realm.json — "resetPasswordAllowed": false, "editUsernameAllowed": false
- User profile config restricts password changes to the user or admin only (see "permissions": {"edit":["admin"]} for username, but password changes are not allowed except by the user or admin via Keycloak flows)
- Password reset is disabled for users ("resetPasswordAllowed": false), so users cannot reset other users' passwords
- No evidence in application code or documentation of any custom password change endpoint that would allow User A to change User B's password
- Requirement: SATISFIED — Only the user or admin can change a user's password; users cannot change passwords for other users

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
- The application uses Keycloak for authentication and session management, but there is no explicit evidence in the provided static configuration or code that user sessions are forcibly terminated upon account deletion.
- File: deploy/keycloak/dev-realm.json — Keycloak manages users and sessions, but no explicit session termination policy on user deletion is shown
- File: api/README.md — API relies on JWT tokens issued by Keycloak; session invalidation on user deletion is not described
- No evidence in application code or documentation of a webhook or listener that terminates sessions when a user is deleted
- Requirement: PARTIALLY SATISFIED — Keycloak can be configured to terminate sessions on user deletion, but static evidence of this configuration is not present

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
- The application uses Keycloak for authentication, which supports PKI-based authentication and certificate validation, but there is no explicit evidence in the provided configuration that certificate path validation to a trust anchor is enabled or enforced.
- File: deploy/keycloak/dev-realm.json — No explicit PKI or certificate validation configuration present
- File: api/README.md — Authentication is via JWT tokens from Keycloak, but no mention of PKI/certificate login flows
- Requirement: PARTIALLY SATISFIED — Keycloak supports PKI, but static evidence of certificate path validation is not present

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
- The application does not appear to perform code signing or cryptographic operations requiring a private key at the application layer, but Keycloak and the deployment stack may use private keys for SSL/TLS and JWT signing.
- File: deploy/aws/iris-stack.yaml — SSL certificates and private keys are retrieved from AWS Secrets Manager and written to /opt/iris/ui/ssl/nginx.key with chmod 600
- File: deploy/keycloak/dev-realm.json — No evidence of private key storage or access control
- File: api/README.md — JWT verification uses public keys from Keycloak JWKS; private key handling is not described
- Requirement: PARTIALLY SATISFIED — SSL private keys are protected via file permissions, but no evidence of application-layer access controls for cryptographic module private keys

Remediation:
Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak maps authenticated identities to individual users and groups, and includes user and group information in JWT tokens.
- File: deploy/keycloak/dev-realm.json — Users have unique usernames and group memberships; protocol mappers include 'groups' and 'realm-roles' in tokens
- File: api/README.md — JWT tokens decoded by API include user claims and roles; user object is injected into endpoints
- Requirement: SATISFIED — Authenticated identity is mapped to individual user or group account for PKI-based authentication (if enabled)

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
- No evidence found of a local cache of revocation data (CRL) for PKI-based authentication in the Keycloak configuration or application code.
- File: deploy/keycloak/dev-realm.json — No CRL or OCSP configuration present
- File: api/README.md — No mention of certificate revocation checking
- Requirement: NOT SATISFIED — No static evidence of CRL caching or fallback for PKI-based authentication

Remediation:
Implement a CRL import process and configure the application to check the CRL if OCSP is not available.

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses Keycloak for authentication, and the login UI is provided by Keycloak with a custom theme.
- File: deploy/keycloak/themes/README.md — Login form uses password input fields (HTML <input type="password">), which obfuscate password entry
- File: deploy/keycloak/dev-realm.json — No evidence of password display in clear text
- Requirement: SATISFIED — Passwords/PINs are not displayed as clear text during entry

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
- The application uses cryptographic modules for JWT verification and possibly for SSL/TLS, but there is no explicit evidence that only FIPS-approved modules are used.
- File: api/README.md — JWT verification uses RS256 (asymmetric) algorithm, but no evidence of FIPS 140-2 validated crypto modules
- File: deploy/aws/iris-stack.yaml — SSL certificates are used, but no evidence of FIPS mode or module validation
- Requirement: PARTIALLY SATISFIED — Cryptographic modules are used, but FIPS validation is not confirmed in static configuration

Remediation:
Use FIPS-approved cryptographic modules.

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak requires unique usernames for all users, and JWT tokens include user identity information for all authenticated sessions.
- File: deploy/keycloak/dev-realm.json — "duplicateEmailsAllowed": false, unique usernames per user
- File: api/README.md — All endpoints (except /health) require authentication; user object is injected and includes unique identity
- Requirement: SATISFIED — All users (including non-organizational) are uniquely identified and authenticated

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
- No evidence found in the Keycloak configuration or application documentation that PIV credentials from other federal agencies are accepted.
- File: deploy/keycloak/dev-realm.json — No mention of PIV or external identity provider configuration
- File: api/README.md — Authentication is via Keycloak, no mention of PIV support
- Requirement: NOT SATISFIED — No static evidence of PIV credential acceptance

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
- No evidence found in the Keycloak configuration or application documentation that PIV credentials from other federal agencies are electronically verified.
- File: deploy/keycloak/dev-realm.json — No mention of PIV or external credential verification
- File: api/README.md — No mention of PIV verification
- Requirement: NOT SATISFIED — No static evidence of PIV credential verification

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
- No evidence found in the Keycloak configuration or application documentation that FICAM-approved third-party credentials are accepted.
- File: deploy/keycloak/dev-realm.json — No mention of FICAM or external identity provider configuration
- File: api/README.md — No mention of FICAM support
- Requirement: NOT SATISFIED — No static evidence of FICAM-approved credential acceptance

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
- No evidence found in the Keycloak configuration or application documentation that the application conforms to FICAM-issued profiles (e.g., SAML, OpenID with FICAM compliance).
- File: deploy/keycloak/dev-realm.json — Protocol is 'openid-connect', but no evidence of FICAM profile conformance
- File: api/README.md — No mention of FICAM profile conformance
- Requirement: NOT SATISFIED — No static evidence of FICAM profile conformance

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- The application does not provide non-local maintenance or diagnostic sessions via the application itself.
- File: README.md — No mention of remote maintenance or diagnostic session capability
- File: api/README.md — No mention of remote maintenance functions
- Requirement: NOT APPLICABLE — No non-local maintenance session capability present

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
- No static evidence found of automated race condition analysis or code review results for race conditions.
- File: api/README.md — No mention of race condition testing or static analysis tools for concurrency issues
- File: pointcloud-project/colmap_ingest.py — Uses batch database operations and context managers, but no explicit race condition mitigation or analysis
- Requirement: NOT SATISFIED — No static evidence of race condition testing or mitigation

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
- The control requires that the application terminate all network connections associated with a communications session at the end of the session.
- No explicit code or configuration was found in the provided files (API, UI, or infrastructure) that forcibly closes network connections at session end.
- The API uses JWT-based authentication via Keycloak (api/README.md: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'), which is stateless and does not manage server-side sessions or network connections directly.
- Keycloak is responsible for session management, but no evidence was found in the provided files that the application explicitly terminates network connections at session end.
- No web server (nginx, etc.) configuration was provided that would enforce connection termination.
- Requirement: PARTIALLY SATISFIED — JWT stateless auth means the API does not maintain server-side sessions, but there is no explicit evidence that all network connections are terminated at session end. Further review of runtime behavior and Keycloak session configuration is required.

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
- The control requires the use of FIPS-validated cryptographic modules when signing application components, and prohibits SHA1/MD5.
- No evidence of code signing or package signing was found in the provided files (no references to signing tools, cryptographic signing libraries, or signature verification in Dockerfiles, deployment scripts, or application code).
- No explicit documentation of a code signing process or cryptographic module selection is present in README.md or api/README.md.
- No references to SHA1 or MD5 for signing were found.
- Requirement: PARTIALLY SATISFIED — No use of SHA1/MD5 for signing is evident, but there is also no evidence that FIPS-validated modules are used for signing application components. If signing is not performed, a documented acceptance of risk is required. Further evidence is needed.

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
- The control requires FIPS-validated cryptographic modules for generating cryptographic hashes, and prohibits SHA1/MD5.
- In vlm-testing/fpv_analyzer_rag.py: 'import hashlib' and 'file_hash = hashlib.md5(f.read()).hexdigest()' are used for document deduplication (not for security purposes).
- No evidence of cryptographic hash generation for security (e.g., password storage, integrity checks) was found in the provided files.
- No explicit configuration or documentation of FIPS-validated modules for hashing is present.
- Requirement: PARTIALLY SATISFIED — MD5 is used for non-security deduplication, but there is no evidence of FIPS-validated modules for security-relevant hashing. If cryptographic hashes are used for security, FIPS-validated modules must be used. Further review required.

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
- The control requires FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.
- The application uses AWS S3 for storage (api/app/config.py: 'S3_RAW_BUCKET', 'S3_PROCESSED_BUCKET'), but no explicit evidence of encryption configuration (e.g., S3 SSE, KMS, or FIPS modules) is present in the provided files.
- No explicit references to FIPS-validated cryptographic modules for data protection in storage or transit were found.
- Requirement: PARTIALLY SATISFIED — AWS infrastructure may provide FIPS-validated cryptography, but no explicit configuration or documentation is present in the codebase. Further evidence required.

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
- No evidence of SAML assertion generation, SAML libraries, or SAML configuration was found in the provided files (no references to SAML, SessionIndex, or AuthnStatement).
- Authentication is handled via Keycloak using OAuth2/OpenID Connect (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- Requirement: NOT APPLICABLE — Application does not use SAML assertions.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 186. APSC-DV-002150 | SV-222574r1117171

- Rule ID: SV-222574r1117171
- Severity: medium
- Rule Title: The application user interface must be either physically or logically separated from data storage and management interfaces.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires logical or physical separation between the user interface and data storage/management interfaces.
- The architecture is multi-tiered: UI (React, port 3000), API (FastAPI, port 5000), Keycloak (port 8080), and database (PostgreSQL, port 5432) are separate services (README.md: 'The IRIS system uses a layered Docker Compose configuration', 'Services are automatically networked and include health checks for reliability. The startup order is: db → keycloak → api → ui.').
- The UI communicates with the API via REST endpoints; the API handles all data access and management.
- No direct access from the UI to the database or management interfaces is present.
- Requirement: SATISFIED — User interface and data storage/management interfaces are logically separated by service boundaries and network segmentation.

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
- The application uses Keycloak for authentication (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence in the provided code or documentation that the HTTPOnly flag is set on session cookies (no web server config, no Set-Cookie headers, no cookie management code in UI or API).
- Keycloak's default behavior is to set HTTPOnly on session cookies, but this is not confirmed in the provided realm or deployment configuration.
- Requirement: PARTIALLY SATISFIED — Likely handled by Keycloak, but explicit evidence (e.g., Keycloak config, HTTP response headers) is missing.

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
- The control requires the Secure flag to be set on session cookies.
- The application uses Keycloak for authentication (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence in the provided code or documentation that the Secure flag is set on session cookies (no web server config, no Set-Cookie headers, no cookie management code in UI or API).
- Keycloak's default behavior is to set Secure on cookies only when accessed via HTTPS; the provided docker-compose and deployment scripts do not show forced HTTPS for all environments.
- Requirement: PARTIALLY SATISFIED — Secure flag may be set in production with HTTPS, but explicit evidence is missing.

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
- The control requires that session IDs are not exposed unencrypted across network segments.
- The application uses JWT tokens for authentication (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence of forced HTTPS/TLS for all API and UI endpoints is present in the provided files (no nginx config, no forced HTTPS in docker-compose, no explicit TLS enforcement in Keycloak config).
- The AWS CloudFormation template (deploy/aws/iris-stack.yaml) configures an Application Load Balancer with HTTPS (port 443) and ACM certificate, but local development and some Docker Compose environments may not enforce HTTPS.
- Requirement: PARTIALLY SATISFIED — Production deployment uses HTTPS, but local/dev environments may not. Explicit enforcement of TLS for all environments is not confirmed.

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
- The control requires destruction of session ID/cookie on logoff or browser close.
- The application uses JWT-based authentication (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit code or documentation was found in the provided files that destroys JWT tokens or session cookies on logoff or browser close (no logout endpoint implementation, no cookie clearing code in UI, no session invalidation logic).
- Keycloak provides logout endpoints, but no evidence is present that the UI or API invokes them or clears tokens/cookies on logout.
- Requirement: PARTIALLY SATISFIED — JWT tokens are stateless and expire, but explicit destruction on logoff/browser close is not confirmed.

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
- The application uses JWT tokens issued by Keycloak (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- JWT tokens are generated by Keycloak and are not user-supplied, but no explicit evidence of session fixation protection (e.g., token regeneration on login, session invalidation on logout) is present in the provided files.
- Requirement: PARTIALLY SATISFIED — JWTs are system-generated, but explicit session fixation protection is not confirmed.

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
- The API verifies JWT tokens using Keycloak's public keys (api/README.md: 'The API verifies JWT tokens using Keycloak's public keys (JWKS) without requiring a client secret.').
- JWT signature, expiration, and audience are validated (api/README.md: 'Verifies token signature, expiration, and audience').
- No explicit code for session validation is present in the provided files, but FastAPI dependency injection is used for authentication.
- Requirement: PARTIALLY SATISFIED — JWT validation is described, but explicit code or configuration for session validation is not shown.

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
- The control prohibits use of URL-embedded session IDs.
- The application uses JWT tokens in the Authorization header (api/README.md: 'Protected endpoints require a valid JWT token in the Authorization header.').
- No evidence of session IDs in URLs, query parameters, or URL rewriting for session management was found in the provided files (no code in UI or API that appends session IDs to URLs).
- Requirement: SATISFIED — Session IDs are not transmitted via URLs.

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
- The application uses JWT tokens issued by Keycloak (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence of session ID (JWT) invalidation or prevention of reuse after logout is present in the provided files.
- Requirement: PARTIALLY SATISFIED — JWTs are unique per login, but explicit prevention of reuse after logout is not confirmed.

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
- The application uses JWT tokens generated by Keycloak (api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence that Keycloak is configured to use a FIPS-approved RNG for JWT/session ID generation is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Session IDs are unique and system-generated, but FIPS RNG usage is not confirmed.

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
- The AWS CloudFormation template (deploy/aws/iris-stack.yaml) configures an Application Load Balancer with HTTPS and ACM certificate (AcmCertificateArn parameter), but does not specify the CA or restrict to DoD-approved CAs.
- No explicit documentation or configuration was found that restricts certificate validation to DoD-approved CAs.
- Requirement: PARTIALLY SATISFIED — HTTPS is used in production, but explicit restriction to DoD-approved CAs is not confirmed.

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
- No explicit code or documentation was found in the provided files that describes secure failure handling (e.g., closing database connections, disabling access, or protecting data on failure).
- No test plans or procedures for failure scenarios are present.
- Requirement: PARTIALLY SATISFIED — No evidence of insecure failure, but explicit secure failure handling is not documented.

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
- No explicit logging configuration or error event logging code was found in the provided files (no references to persistent logs, error event storage, or operational requirements documentation).
- api/app/logging_config.py is referenced in some imports, but its content was not provided.
- Requirement: PARTIALLY SATISFIED — Logging may be present, but explicit evidence of required information retention is missing.

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
- The control requires protection of confidentiality and integrity of stored information when required by DOD policy or the information owner.
- The application stores data in AWS S3 and PostgreSQL (api/app/config.py: 'S3_RAW_BUCKET', 'S3_PROCESSED_BUCKET', 'POSTGRES_HOST').
- No explicit evidence of encryption at rest or integrity protection (e.g., S3 SSE, database encryption, or checksums) is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Data is stored in cloud services that may support encryption, but explicit configuration or documentation is missing.

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
- The application stores data in AWS S3 and PostgreSQL (api/app/config.py: 'S3_RAW_BUCKET', 'S3_PROCESSED_BUCKET', 'POSTGRES_HOST').
- No explicit evidence of cryptographic integrity protection (e.g., digital signatures, HMACs, or database-level checksums) is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Data is stored in cloud services that may support integrity protection, but explicit configuration or documentation is missing.

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
- The control requires encryption of stored DoD information when required by policy or data owner. Evidence of cryptographic storage for sensitive data is not directly visible in the provided files. However, the following is observed:
- File: api/README.md — Mentions S3 buckets for storage (e.g., 'iris-dev-raw', 'iris-dev-processed'), PostgreSQL for metadata, and Qdrant for vector data. No explicit evidence of S3 bucket encryption settings, database encryption at rest, or application-level encryption for sensitive fields.
- File: deploy/aws/iris-stack.yaml — S3 bucket is created with 'BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets', but no explicit 'BucketEncryption' property is set. RDS (Postgres) is provisioned, but encryption at rest is not specified in the CloudFormation template.
- File: api/app/process/services/scene_summarization.py — No evidence of encryption for processed data written to S3.
- No evidence of application-level encryption for sensitive fields in the database or vector store.
- Requirement: PARTIALLY SATISFIED — S3 and RDS are used, but explicit encryption-at-rest configuration is not confirmed in static artifacts. Application-level encryption for sensitive data is not evidenced. S3 and RDS support encryption, but explicit enforcement is not shown. Further review of S3 and RDS configuration and runtime settings is required.

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
- The control requires isolation of security functions from non-security functions (e.g., RBAC, ACLs). Evidence:
- File: api/README.md — 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'
- File: api/README.md — 'The API implements role-based access control (RBAC) for protected endpoints.'
- File: api/app/process/router.py — All endpoints except /health require authentication via dependency injection. Admin endpoints require specific roles (role_maintainer, role_engineer, admin).
- File: README.md — 'Keycloak provides enterprise-grade authentication and authorization for the IRIS system: Single Sign-On (SSO), Role-Based Access Control (RBAC), User Management, OAuth 2.0 / OpenID Connect.'
- File: deploy/keycloak/dev-realm.json (referenced in README.md) — Pre-configured realm with roles and groups.
- Security configuration (RBAC, authentication) is handled by Keycloak and enforced at the API layer, separate from business logic.
- Requirement: SATISFIED — Security functions (authentication, RBAC) are isolated and protected from non-security functions via Keycloak and FastAPI dependency injection.

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
- The control requires separate execution domains for each process. The application is deployed as a set of containerized microservices (see README.md, docker-compose.yml, deploy/aws/iris-stack.yaml), each running in its own container or EC2 instance. Each service (API, UI, Keycloak, Qdrant, DB) runs as a separate OS process/container. There is no evidence of multi-tenant process sharing within a single process. The architecture is inherently process-isolated via Docker/Kubernetes.
- Requirement: NOT APPLICABLE — The application is architected as containerized microservices, each with its own execution domain. No shared process space.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires prevention of unauthorized information transfer via shared system resources. Evidence:
- File: README.md — All services are containerized and networked via Docker Compose or Kubernetes. S3 buckets are used for storage, with access controlled via IAM roles and policies (see deploy/aws/iris-stack.yaml).
- File: deploy/aws/iris-stack.yaml — S3 bucket 'PublicAccessBlockConfiguration' disables public access. RDS security group only allows access from EC2 SG. No evidence of file shares or shared disk resources exposed to other applications.
- File: api/README.md — All storage is via S3, PostgreSQL, or Qdrant, with access controlled by credentials and network policies.
- Requirement: SATISFIED — Application data is not shared via system resources accessible to unauthorized users or processes. S3 and RDS are access-controlled. No file sharing protocols or shared disk exposure.

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
- The control applies only to XML-based applications. No evidence of XML processing, XML web services, or XML parsers is present in the provided files:
- File: api/app/process/router.py — All endpoints use JSON schemas and models.
- File: README.md, api/README.md — All API endpoints are RESTful and use JSON for data interchange.
- No XML parsing libraries or XML configuration is present in the manifest or code.
- Requirement: NOT APPLICABLE — The application does not process or expose XML-based APIs or services.

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
- The control requires anti-DoS protections. Evidence:
- File: README.md — No mention of rate limiting, anti-DoS, or traffic throttling at the application layer.
- File: api/app/process/router.py — No evidence of request rate limiting, circuit breakers, or anti-DoS middleware.
- File: deploy/aws/iris-stack.yaml — ALB is used, which provides some basic DoS protection at the AWS infrastructure level, but no explicit WAF or rate limiting is configured in the template.
- No evidence of application-level logic to prevent self-DoS or outbound DoS attacks.
- Requirement: PARTIALLY SATISFIED — AWS ALB provides some infrastructure-level protection, but no explicit application-level anti-DoS controls are present in static code/configuration. Further review of runtime WAF, rate limiting, or API gateway configuration is required.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires redundancy mechanisms for high-availability systems. Evidence:
- File: README.md — Describes support for production deployment on EKS (Kubernetes), use of ALB, multi-AZ subnets, and Docker Compose for local development. Mentions 'multi-site deployment' and 'server clusters' as future enhancements.
- File: deploy/aws/iris-stack.yaml — Defines ALB, two subnets in different AZs, MultiAZ RDS, and EC2 instance. However, only a single EC2 instance is provisioned for the application stack (IrisEC2Instance). No evidence of multiple application servers or auto-scaling group for EC2.
- File: deploy/terraform/kubernetes/iris-api-hpa.yaml (not included in context) — Manifest exists, but content not reviewed.
- Requirement: PARTIALLY SATISFIED — Infrastructure supports high availability (ALB, MultiAZ RDS, multi-AZ subnets), but application server redundancy is not fully implemented in the provided CloudFormation. Kubernetes manifests may provide redundancy, but static evidence is incomplete. Further review of production deployment topology is required.

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
- The control requires protection of confidentiality and integrity of transmitted information (e.g., TLS). Evidence:
- File: README.md — 'Configure all of the application systems to require TLS encryption.' ALB is configured with ACM certificate for HTTPS (deploy/aws/iris-stack.yaml: 'AppListener443' uses 'Protocol: HTTPS').
- File: deploy/aws/iris-stack.yaml — ALB listener on port 443 with ACM certificate. Security groups allow 443 only. However, backend EC2 instance and internal service communication (e.g., between API, Keycloak, Qdrant, DB) are not explicitly shown as using TLS. No evidence of TLS enforcement for API-to-DB or API-to-Qdrant communication.
- File: api/README.md — API endpoints are exposed on HTTP (http://localhost:5000), not HTTPS. No evidence of HTTPS enforcement at the API container level.
- Requirement: PARTIALLY SATISFIED — ALB provides TLS for external traffic, but internal service communication (API, DB, Qdrant) is not confirmed to use TLS. Further review of internal network encryption is required.

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
- The control requires cryptographic mechanisms to prevent unauthorized disclosure and detect changes during transmission. Evidence:
- File: deploy/aws/iris-stack.yaml — ALB listener uses HTTPS with ACM certificate for external access.
- File: README.md — Mentions 'Configure all of the application systems to require TLS encryption.'
- File: api/README.md — API is exposed on HTTP (http://localhost:5000), not HTTPS. No evidence of message-level integrity (e.g., digital signatures, HMAC) for data in transit between internal services.
- No evidence of TLS for API-to-DB or API-to-Qdrant communication.
- Requirement: PARTIALLY SATISFIED — External traffic is protected by TLS via ALB, but internal service communication and message-level integrity are not confirmed. Further review of internal encryption and integrity mechanisms is required.

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
- The control requires confidentiality and integrity during preparation for transmission (e.g., automatic HTTPS redirect, TLS by default). Evidence:
- File: deploy/aws/iris-stack.yaml — ALB listener on port 443 (HTTPS) with ACM certificate. No evidence of HTTP-to-HTTPS redirect at the ALB or application level.
- File: README.md — API and UI are exposed on HTTP (http://localhost:5000, http://localhost:3000) in local development. No evidence of HTTPS enforcement for backend API or internal service communication.
- No evidence of TLS for API-to-DB or API-to-Qdrant communication.
- Requirement: PARTIALLY SATISFIED — External access via ALB is HTTPS, but backend and internal service communication is not confirmed to use TLS. No evidence of automatic redirect from HTTP to HTTPS at the application or ALB level. Further review required.

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
- The control requires confidentiality and integrity during reception (e.g., TLS for incoming connections). Evidence:
- File: deploy/aws/iris-stack.yaml — ALB listener on port 443 (HTTPS) with ACM certificate for external access.
- File: README.md — API and UI are exposed on HTTP (http://localhost:5000, http://localhost:3000) in local development. No evidence of TLS enforcement for backend API or internal service communication.
- No evidence of TLS for API-to-DB or API-to-Qdrant communication.
- Requirement: PARTIALLY SATISFIED — External access via ALB is HTTPS, but backend and internal service communication is not confirmed to use TLS. Further review required.

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
- The control requires the application not to disclose unnecessary information to users (e.g., technical details in error messages). Evidence:
- File: api/app/process/router.py — API endpoints raise HTTPException with detail messages, including exception strings (e.g., 'detail=f"Failed to process video: {str(e)}"'). Some error messages may include exception details or stack traces, which could leak technical information.
- File: README.md — No mention of custom error pages or generic error handling.
- No evidence of custom error pages for the UI or API. No evidence of error message sanitization.
- Requirement: NOT SATISFIED — API may disclose technical details in error responses. No evidence of generic error handling or custom error pages. Further review of error handling and UI error display is required.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that sensitive information is not stored in hidden fields. Evidence:
- No static code or configuration for frontend forms or hidden fields is present in the provided files. No evidence of sensitive data being stored in hidden fields, but also no evidence of automated testing or code review for this issue.
- File: README.md — No mention of hidden field handling or testing.
- Requirement: OPEN — No evidence of sensitive data in hidden fields, but also no evidence of automated testing or code review for this issue. Further review of frontend code and vulnerability scan results is required.

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
- The control requires protection from XSS vulnerabilities. Evidence:
- File: README.md — End-to-end tests are run with Playwright, including accessibility checks, but no explicit mention of XSS testing.
- No evidence of input sanitization, output encoding, or use of a web template system with auto-escaping in the provided backend code. Frontend code is not included in the context.
- Requirement: OPEN — No evidence of XSS vulnerabilities, but also no evidence of automated XSS testing or input/output sanitization in the provided static code. Further review of frontend code and vulnerability scan results is required.

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
- The control requires protection from CSRF vulnerabilities. Evidence:
- File: README.md, api/README.md — No mention of CSRF protection mechanisms.
- File: api/app/process/router.py — No evidence of CSRF tokens, origin/referrer checks, or anti-CSRF middleware.
- No evidence of automated CSRF testing or scan results.
- Requirement: OPEN — No evidence of CSRF vulnerabilities, but also no evidence of CSRF protection mechanisms or automated testing. Further review of frontend code, API design (statelessness), and vulnerability scan results is required.

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
- The control requires protection from command injection. Evidence:
- File: README.md, api/README.md — No mention of command injection testing or mitigation.
- File: api/app/process/services/scene_summarization.py — Uses ffmpeg and cv2.VideoCapture for frame extraction, but no evidence of user-controlled input being passed to shell commands. However, some endpoints accept user-supplied file paths or session IDs, which could be used in file operations.
- No evidence of input sanitization or validation for file paths or command arguments.
- Requirement: OPEN — No evidence of command injection vulnerabilities, but also no evidence of input sanitization or automated testing for command injection. Further review of code paths that invoke shell commands or subprocesses is required.

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
- The control requires protection from canonical representation vulnerabilities (e.g., Unicode normalization, encoding issues). Evidence:
- File: README.md, api/README.md — No mention of canonicalization or encoding handling.
- File: api/app/process/services/scene_summarization.py — No evidence of input canonicalization or encoding enforcement.
- No evidence of scan results or code review for canonicalization issues.
- Requirement: OPEN — No evidence of canonicalization vulnerabilities, but also no evidence of encoding enforcement or automated testing. Further review of input handling and scan results is required.

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
- The control requires validation of all input. Evidence:
- File: api/app/process/router.py — API endpoints use Pydantic models for request validation (e.g., ProcessVideoRequest, GenerateThumbnailRequest), which provides some input validation for API requests.
- File: api/README.md — 'All API endpoints (except /health) use FastAPI dependency injection for authentication.' No explicit mention of input validation beyond schema enforcement.
- No evidence of input validation for file uploads, query parameters, or frontend forms.
- Requirement: PARTIALLY SATISFIED — API endpoints use Pydantic models for request validation, but no evidence of comprehensive input validation for all entry points (e.g., file uploads, frontend forms). Further review of input validation coverage is required.

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
- The control requires protection from SQL injection. Evidence:
- File: README.md, api/README.md — PostgreSQL is used for metadata storage. No evidence of ORM usage or parameterized queries in the provided files.
- File: api/app/process/router.py — No direct SQL queries are present in the router code. Database access is abstracted (e.g., via DatabaseManager), but implementation is not included in context.
- No evidence of automated SQL injection testing or scan results.
- Requirement: OPEN — No evidence of SQL injection vulnerabilities, but also no evidence of parameterized queries, ORM usage, or automated testing. Further review of database access code and scan results is required.

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
- The control applies only to XML-oriented attacks. No evidence of XML processing, XML web services, or XML parsers is present in the provided files:
- File: api/app/process/router.py — All endpoints use JSON schemas and models.
- File: README.md, api/README.md — All API endpoints are RESTful and use JSON for data interchange.
- No XML parsing libraries or XML configuration is present in the manifest or code.
- Requirement: NOT APPLICABLE — The application does not process or expose XML-based APIs or services.

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
- Control requires evidence of input validation and vulnerability scanning for input handling vulnerabilities.
- File: api/app/process/router.py — API endpoints use FastAPI, which provides some input validation via Pydantic models (e.g., 'request: ProcessVideoRequest', 'request: ProcessDocumentsRequest'), but there is no explicit evidence of comprehensive input sanitization or validation logic for all user inputs.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Streamlit-based apps accept file uploads and text input, but no explicit input sanitization is shown.
- File: api/README.md — No mention of static analysis tools or vulnerability scanning for input validation vulnerabilities.
- No scan results or configuration for vulnerability scanning tools are present in the provided files.
- Requirement: PARTIALLY SATISFIED — Some input validation is present via FastAPI/Pydantic, but there is no evidence of comprehensive input sanitization, vulnerability scan results, or documented risk acceptance. Full compliance cannot be confirmed from static artifacts alone.

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
- Control requires error messages to avoid revealing sensitive information to end users.
- File: api/app/process/router.py — Error handling uses FastAPI's HTTPException with generic messages (e.g., 'Failed to process video: {str(e)}'), but in some cases, the exception detail includes the stringified exception, which may leak internal error details if not properly sanitized.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Streamlit apps display errors using 'st.error', which may show exception details and tracebacks to users (e.g., 'st.error(f"Error extracting text from PDF: {str(e)}")').
- No evidence of a global error handler that sanitizes or redacts sensitive error details before returning to non-privileged users.
- Requirement: PARTIALLY SATISFIED — API endpoints generally avoid leaking stack traces, but Streamlit apps may expose sensitive error details. No evidence of a policy or mechanism to ensure only generic error messages are shown to non-privileged users.

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
- File: api/app/process/router.py — Error messages returned via HTTPException may include exception details (e.g., 'detail=f"Failed to process video: {str(e)}"'), which could expose sensitive information if not filtered. No evidence of role-based error message differentiation.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Errors are displayed to all users via 'st.error', with possible tracebacks.
- No evidence of logic that restricts detailed error messages to privileged users only.
- Requirement: NOT SATISFIED — No static evidence that error messages are restricted to privileged users; detailed errors may be exposed to all users.

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
- Control concerns overflow attacks (buffer, stack, heap, integer, format string). Python (used in api/app/process/router.py, vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py) is a memory-safe language and not subject to classic buffer/stack/heap overflows due to automatic bounds checking and managed memory.
- File: api/app/process/router.py — All code is Python, using FastAPI and Pydantic.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — All code is Python.
- Requirement: NOT APPLICABLE — Application is implemented in Python, which is not vulnerable to classic overflow attacks by design.

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
- File: api/README.md — Describes Docker-based deployment and local development, but does not mention any process for removing old versions or cleaning up obsolete components after updates.
- File: deploy/aws/iris-stack.yaml — UserData script clones the repository and deploys the stack, but does not explicitly remove old versions beyond 'rm -rf "${IRIS_DIR}"' before cloning.
- No explicit evidence of a version cleanup or old component removal process in the provided files.
- Requirement: PARTIALLY SATISFIED — The EC2 bootstrap script removes the IRIS directory before re-cloning, but there is no evidence of a systematic process for removing old versions of all components after updates.

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
- Control requires security-relevant software updates and patches to be kept up to date.
- File: .github/workflows/deploy-eks-ironbank.yml — CI/CD pipeline builds and deploys images, but there is no evidence of a process for checking for upstream security patches or applying them on a weekly basis.
- File: api/README.md — No mention of patch management or update cadence.
- File: deploy/aws/iris-stack.yaml — Installs packages via dnf and pip, but does not show a scheduled update process.
- Requirement: PARTIALLY SATISFIED — CI/CD pipeline automates deployments, but there is no evidence of a documented or automated process for regular patching or update checks.

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
- File: api/README.md — Describes authentication and RBAC via Keycloak, but does not mention any security function self-tests or verification routines.
- File: api/app/process/router.py — No evidence of security function verification endpoints or logic.
- No logs or documentation indicating security function testing is performed.
- Requirement: NOT SATISFIED — No static evidence that the application verifies correct operation of security functions.

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
- Control requires verification of security functions on startup, restart, or privileged command.
- File: api/README.md, api/app/process/router.py — No evidence of security function verification on startup, restart, or by privileged user command.
- No logs or code indicating such checks are performed.
- Requirement: NOT SATISFIED — No static evidence of security function verification on startup/restart/command.

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
- Control requires notification to ISSO/ISSM of failed security verification tests.
- File: api/README.md, api/app/process/router.py — No evidence of notification logic or configuration for failed security verification tests.
- No logs, email, or alerting configuration for ISSO/ISSM notification.
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
- Control concerns unsigned Category 1A mobile code provided for client consumption (e.g., ActiveX, Java applets, browser plugins).
- File: README.md, api/README.md, ui/src/components/video-player/video-player.tsx — Application is a web-based system using React (UI) and FastAPI (API), with no evidence of mobile code (ActiveX, Java applets, or similar) being delivered to clients.
- No browser-executed mobile code artifacts present in the repository.
- Requirement: NOT APPLICABLE — Application does not provide or require Category 1A mobile code.

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
- Control requires a documented account management process for user creation, termination, and expiration.
- File: api/README.md — Describes Keycloak-based authentication and RBAC, but does not provide documentation of account management processes or procedures for removing inactive/suspended/terminated accounts.
- File: deploy/keycloak/dev-realm.json (not included in context) — Not reviewed for account lifecycle policies.
- Requirement: PARTIALLY SATISFIED — Keycloak provides account management capabilities, but no documentation or process evidence is present in the reviewed files.

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires web servers to be on a separate network segment from application and database servers if operating in the DoD DMZ.
- File: deploy/aws/iris-stack.yaml — Defines VPC, subnets, security groups, and places EC2, RDS, and ALB in separate subnets and security groups. However, there is no explicit documentation or diagram confirming DMZ segmentation or that the application is hosted in the DoD DMZ.
- File: README.md — No explicit mention of DMZ deployment or network segmentation compliance.
- Requirement: PARTIALLY SATISFIED — Infrastructure code suggests some separation, but there is no explicit evidence of DMZ compliance or network diagrams.

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
- Control requires audit trails to be retained for at least 30 months (or 5 years for SAMI data).
- File: api/README.md, api/app/process/router.py — No evidence of audit log retention policy, configuration, or implementation.
- No log retention settings or documentation found.
- Requirement: NOT SATISFIED — No static evidence of audit trail retention policy or mechanism.

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
- File: api/README.md, api/app/process/router.py — No evidence of a process or documentation for periodic audit log review.
- Requirement: NOT SATISFIED — No static evidence of audit log review process or documentation.

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
- Control requires a policy for reporting IA violations.
- File: api/README.md, README.md — No evidence of an IA violation reporting policy or SOP.
- Requirement: NOT SATISFIED — No static evidence of IA violation reporting policy.

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
- Control requires active vulnerability testing and fuzz testing, with results and procedures documented.
- File: api/README.md — No mention of vulnerability or fuzz testing procedures or results.
- File: .github/workflows/deploy-eks-ironbank.yml — CI/CD pipeline does not include vulnerability scanning steps.
- Requirement: NOT SATISFIED — No static evidence of active vulnerability or fuzz testing.

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

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires execution flow diagrams and design documents showing mitigation of deadlock and recursion issues in web services.
- File: api/README.md, README.md — No execution flow diagrams or design documents addressing deadlock/recursion in web services are present in the repository.
- Requirement: NOT SATISFIED — No static evidence of deadlock/recursion mitigation documentation.

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
- Control requires configuration and control files to be stored separately from user data.
- File: api/README.md — Documents that environment files ('.env', '.env.example') and configuration files are in 'api/' and 'api/app/', while user data (videos, documents) are stored in S3 buckets ('iris-video/raw/', 'iris-video/clips/').
- File: deploy/aws/iris-stack.yaml — S3 buckets are created for data storage, and application code/configuration is deployed to '/opt/iris'.
- However, no explicit file permission settings or enforcement of separation are shown in the provided files.
- Requirement: PARTIALLY SATISFIED — Logical separation is present, but no explicit evidence of file permission enforcement or documentation of separation.

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
- Control requires configuration according to DoD STIG/NSA guide, or, if not available, according to best practices, independent testing, or vendor guidance.
- File: api/README.md, README.md — No evidence of following a specific STIG, NSA guide, or alternative guidance for third-party products (e.g., Qdrant, Keycloak, FastAPI, Streamlit).
- No documentation of configuration hardening or reference to vendor lock down guides.
- Requirement: NOT SATISFIED — No static evidence of configuration according to STIG, NSA, or alternative guidance.

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
- Control requires all application ports, protocols, and services to be documented and in compliance with DoD PPSM guidance.
- File: deploy/aws/iris-stack.yaml — Defines ports for ALB (443), EC2 (22, 443, 3000), RDS (5432), and S3, but does not include documentation mapping these to PPSM compliance or accreditation documentation.
- File: README.md — Lists service ports (API: 5000, UI: 3000, Keycloak: 8080, Qdrant: 6333), but no evidence of PPSM compliance review.
- Requirement: NOT SATISFIED — No static evidence of PPSM compliance documentation or port/service approval.

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
- Control requires registration of the application and all used ports in the DoD Ports and Protocols Database for a production site.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml, .github/workflows/deploy-eks.yml, .github/workflows/deploy-eks-ironbank.yml) confirms registration in the DoD Ports and Protocols Database.
- Provided documentation and deployment manifests specify ports (e.g., 443, 8080, 3000, 5000, 6333, 5432) and protocols (TCP), but do not reference DoD registration or PPDB identifiers.
- Requirement: PARTIALLY SATISFIED — Ports and protocols are documented in infrastructure-as-code and documentation, but no evidence of DoD PPDB registration is present.

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
- Control requires the CM repository to be patched and STIG compliant.
- .github/workflows/deploy-eks.yml and .github/workflows/deploy-eks-ironbank.yml automate CI/CD, including image builds and deployments, but do not reference patch management or STIG compliance for the CM system itself (e.g., GitHub, ECR, or other repository).
- No evidence of patch management process documentation or STIG compliance for the CM repository system in the provided files.
- Requirement: PARTIALLY SATISFIED — Automated build and deployment pipelines exist, but no static evidence of patch management or STIG compliance for the CM repository system.

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
- No static artifact in README.md, api/README.md, or CI/CD workflows (.github/workflows/deploy-eks.yml, .github/workflows/deploy-eks-ironbank.yml) describes a process or schedule for reviewing repository access privileges.
- No evidence of access review logs, schedules, or documentation.
- Requirement: NOT SATISFIED — No evidence of periodic access review for the CM repository.

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
- Control requires a Software Configuration Management (SCM) plan describing configuration control, change management, roles, and responsibilities.
- No SCM plan or equivalent documentation is present in README.md, api/README.md, or any referenced documentation locations.
- No evidence of a document listing configuration control procedures, object types, roles, tools, version numbers, or access/audit mechanisms.
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
- Control requires a Configuration Control Board (CCB) that meets at least every release cycle, with charter documentation.
- No evidence of a CCB, its membership, meeting schedule, or charter documentation in README.md, api/README.md, or CI/CD workflows.
- Requirement: NOT SATISFIED — No CCB documentation or evidence found.

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
- Control requires application services and interfaces to be compatible with DoD IPv6 Standards Profile for servers.
- No explicit evidence in README.md, api/README.md, or deployment manifests that IPv6 is enabled or tested (e.g., no IPv6 addresses, no IPv6-specific configuration in deploy/aws/iris-stack.yaml or Kubernetes manifests).
- Requirement: NOT SATISFIED — No evidence of IPv6 compatibility or configuration.

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
- Control requires that critical/high-availability applications are not hosted on general purpose machines shared with less critical applications.
- This is a deployment/hosting architecture control; static code and manifest review cannot confirm server co-hosting or application criticality assignments.
- Requirement: NOT REVIEWED — Requires runtime/server inventory and criticality designation.

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
- Control requires a contingency plan based on the application's availability requirements.
- No contingency plan or reference to one is present in README.md, api/README.md, or deployment documentation.
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
- No disaster recovery plan or reference to one is present in README.md, api/README.md, or deployment documentation.
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
- Control requires documented backup procedures at intervals based on risk level, with offsite storage and testing.
- README.md and api/README.md reference S3 storage for video and metadata, but do not document backup intervals, offsite storage policies, or backup testing procedures.
- No evidence of backup schedule, offsite backup validation, or recovery testing.
- Requirement: PARTIALLY SATISFIED — S3 is used for storage (which is offsite/cloud), but no documented backup procedures or testing evidence.

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
- README.md and api/README.md do not mention backup storage locations or fire-rated/offsite storage for source code or application software.
- No evidence of offsite backup or fire-rated storage for source code.
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
- No backup and restoration procedures are documented in README.md, api/README.md, or deployment manifests.
- No evidence of protection mechanisms for backup assets.
- Requirement: NOT SATISFIED — No backup/restoration protection procedures found.

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
- Control requires encryption for key exchange and endpoint authentication using FIPS-140-2 validated modules.
- README.md and api/README.md reference JWT-based authentication and HTTPS endpoints, but do not specify FIPS-validated cryptographic modules for key exchange.
- deploy/aws/iris-stack.yaml provisions ACM certificates for HTTPS, but does not specify FIPS-validated ciphers or modules.
- No evidence of explicit FIPS-140-2 validation for cryptographic modules.
- Requirement: PARTIALLY SATISFIED — Encryption is used for communication, but FIPS-140-2 validation is not evidenced.

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
- Control prohibits embedded authentication data (e.g., passwords, certificates) in code or configuration files.
- pointcloud-project/docker-compose.yml contains: POSTGRES_PASSWORD: secure_password_here
- No other hardcoded secrets found in the reviewed files, but .env.example and api/.env.example are not included in this context.
- Requirement: NOT SATISFIED — Embedded database password found in pointcloud-project/docker-compose.yml.

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
- Control requires the application to have the capability to mark sensitive/classified output when required.
- No evidence in README.md, api/README.md, or UI code (ui/src/components/video-player/video-player.tsx) of marking sensitive/classified output (e.g., banners, footers, or labels for CUI/SECRET/TOP SECRET).
- No classification guide or marking procedures referenced.
- Requirement: NOT SATISFIED — No output marking capability or documentation found.

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
- Control requires test plans and procedures to be created and executed prior to each release or patch.
- README.md and api/README.md reference end-to-end and unit testing (e.g., Playwright, pytest), but do not provide or reference formal test plans, procedures, or test result documentation for each release.
- No evidence of versioned test plans or test execution records.
- Requirement: PARTIALLY SATISFIED — Automated tests exist, but no formal test plan/procedure documentation or release-specific test results.

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
- Control requires application files to be cryptographically hashed prior to deployment to DoD operational networks.
- No evidence in README.md, api/README.md, or CI/CD workflows of a cryptographic hash validation process (e.g., sha256sum, Get-FileHash) for application files prior to deployment.
- No hash values or validation steps are documented in deployment scripts or workflows.
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
- Control requires at least one tester to be designated for security testing in addition to functional testing.
- README.md and api/README.md reference automated testing (e.g., Playwright, pytest), but do not designate personnel or roles for security testing.
- No organization chart or personnel assignment documentation found.
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
- Control requires annual execution of test procedures to ensure secure state on initialization, shutdown, and aborts.
- No process documentation or test procedures for system initialization, shutdown, or aborts are present in README.md, api/README.md, or test directories.
- No evidence of annual testing or test dates.
- Requirement: NOT SATISFIED — No annual security state test procedures or records found.

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
- Control requires an application code review to be performed, documented, and to cover all known security flaws.
- README.md and api/README.md reference code quality checks (e.g., ruff, lint), but do not reference or provide code review process documentation or code review reports.
- No evidence of code review results or security flaw identification.
- Requirement: NOT SATISFIED — No code review process documentation or results found.

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
- File: api/README.md — 'To run unit tests with code coverage, run the following:\ncoverage run -m pytest && coverage html'
- File: ui/README.md — 'Ensure to review the coverage directory for code coverage details.\nnpm run test:coverage'
- File: e2e/README.md — 'View test report\nnpm run test:report'
- The documentation for both backend (API) and frontend (UI) explicitly instructs developers to run code coverage tools and review coverage reports as part of the test process.
- Requirement: SATISFIED — code coverage statistics are maintained and documented for both backend and frontend.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Flaws found during a code review must be tracked in a defect tracking system.
- No static evidence of a defect tracking system or configuration management repository is present in the provided files (e.g., no references to Jira, GitHub Issues, or similar in README.md, api/README.md, or ui/README.md).
- No explicit mention of code review flaw tracking in documentation or code comments.
- Requirement: PARTIALLY SATISFIED — code review and testing are documented, but there is no static evidence of a defect tracking system capturing code review flaws.

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
- No static evidence of a formal IA impact assessment or CCB process documentation is present in the provided files.
- No references to change management, CCB, or accreditation process in README.md, api/README.md, or deployment scripts.
- Requirement: NOT SATISFIED — no evidence of IA impact analysis or change assessment process.

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
- No project plan or process documentation for integrating security flaws into planning is present in the provided files.
- No references to security flaw tracking or remediation in README.md, api/README.md, or ui/README.md.
- Requirement: NOT SATISFIED — no evidence of security flaw tracking or integration into project planning.

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
- File: api/README.md — 'To run code quality checks, run the following:\nruff check .'
- File: ui/README.md — 'To make sure your changes adhere to additional code quality standards, run the following:\nnpm run lint\nnpm run format'
- The presence of code quality tools (ruff for Python, lint/format for JavaScript/TypeScript) and explicit instructions in documentation indicate that coding standards are enforced and followed.
- Requirement: SATISFIED — coding standards are documented and enforced via automated tooling.

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
- README.md references 'Detailed technical specifications and API documentation are maintained in the /docs directory', but the actual design document is not present in the provided files.
- No static evidence of a design document containing required details (interfaces, roles, protections, restoration priority, etc.) is available in the reviewed files.
- Requirement: NOT SATISFIED — reference to documentation exists, but the actual design document is not included in the provided evidence.

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
- No static evidence of a threat model document or its contents (identified threats, vulnerabilities, countermeasures, etc.) is present in the provided files.
- README.md references 'threat model' in the context of design documentation, but no actual threat model document is included.
- Requirement: NOT SATISFIED — no threat model documentation found.

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
- File: api/README.md — 'To run unit tests, run the following:\npytest' and 'To run unit tests with code coverage, run the following:\ncoverage run -m pytest && coverage html'
- File: api/app/process/router.py — All API endpoints use try/except blocks to catch ValueError and Exception, returning appropriate HTTP status codes and error messages (e.g., 'raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))').
- File: ui/README.md — 'To make sure your changes do not break any unit tests, run the following:\nnpm run test'
- File: e2e/README.md — End-to-end tests are documented and run via Playwright, which can include error handling scenarios.
- Requirement: SATISFIED — error handling is implemented throughout the application, and testing procedures are documented.

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
- No static evidence of an incident response plan or process documentation for tracking, confirming, and remediating vulnerabilities and notifying users is present in the provided files.
- Requirement: NOT SATISFIED — no incident response plan documentation found.

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
- README.md and api/README.md list core technologies and dependencies, but there is no explicit documentation of support status for all software components.
- No static evidence (e.g., support contracts, vendor support references) is present in the provided files.
- Requirement: NOT SATISFIED — no proof of support for all components.

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
- No static evidence of maintenance contracts or decommissioning procedures is present in the provided files.
- Requirement: NOT SATISFIED — no evidence of maintenance/support tracking or decommissioning process.

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
- No static evidence of user notification procedures for decommissioning is present in the provided files.
- Requirement: NOT SATISFIED — no notification procedures documented.

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
- README.md (Keycloak section) documents default admin credentials for development: Username: 'admin', Password: 'TestPassword123!'.
- It is noted: 'Change default credentials before deploying to production environments.'
- No static evidence of disabling or changing built-in accounts for production is present in the provided files.
- Requirement: PARTIALLY SATISFIED — development credentials are documented, but no evidence of disabling/changing for production.

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
- README.md (Keycloak section) documents default admin credentials for development: Username: 'admin', Password: 'TestPassword123!'.
- It is noted: 'Change default credentials before deploying to production environments.'
- No static evidence of password change enforcement for production is present in the provided files.
- Requirement: PARTIALLY SATISFIED — default passwords are documented for development, but no evidence of enforced change for production.

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
- README.md references 'Detailed technical specifications and API documentation are maintained in the /docs directory', but the actual Application Configuration Guide is not present in the provided files.
- No static evidence of a configuration guide covering encryption, PKI, password, auditing, backup, deployment, or environment details is included.
- Requirement: NOT SATISFIED — reference to documentation exists, but the actual configuration guide is not included in the provided evidence.

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
- No evidence in README.md, api/README.md, or any configuration files that the application processes classified information.
- Requirement: NOT APPLICABLE — application does not process classified data.

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
- No evidence of uncategorized or emerging mobile code (e.g., Java applets, ActiveX, Flash, Silverlight) in the provided file manifest or codebase.
- The application uses standard web technologies (React, FastAPI, Python, TypeScript, etc.) and does not include mobile code types requiring waivers.
- Requirement: SATISFIED — no uncategorized or emerging mobile code present.

Remediation:
Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Production database exports must have database administration credentials and sensitive data removed before releasing the export.
- No static evidence of database export sanitization procedures or scripts is present in the provided files.
- No documentation of export/import process for test or development databases.
- Requirement: NOT SATISFIED — no evidence of sensitive data removal from database exports.

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
- No static evidence of DoS threat identification or mitigation (e.g., rate limiting, circuit breakers, WAF, etc.) is present in the provided files.
- README.md references a threat model but does not include it or describe DoS mitigations.
- Requirement: NOT SATISFIED — no evidence of DoS protections or threat model documentation.

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
- No static evidence of resource monitoring, alerting, or automated notification mechanisms is present in the provided files.
- No references to monitoring tools, alerting scripts, or configuration for low resource conditions.
- Requirement: NOT SATISFIED — no evidence of administrator alerting for low resource conditions.

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
- The control requires that at least one application administrator is registered to receive update notifications or security alerts for all application components.
- File: deploy/keycloak/dev-realm.json — users array includes an 'admin' user:
- "username": "admin",
- "email": "admin@example.com",
- "realmRoles": ["admin", "user"]
- File: deploy/keycloak/dev-realm.json — Keycloak realm is configured for user management and RBAC, but there is no static evidence of a notification/alert registration mechanism for update notifications or security alerts.
- File: api/README.md — No mention of automated update notification registration for administrators.
- No evidence in code or configuration of a process or system for registering administrators to receive update/security notifications for custom-developed software, libraries, or third-party tools.
- Requirement: PARTIALLY SATISFIED — Admin users exist in Keycloak, but there is no evidence of a notification registration mechanism for update/security alerts. Manual or external process may exist but is not statically documented.

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
- The control requires the application to provide notifications or alerts when product updates and security-related patches are available, including a description, risk summary, mitigations, and how to obtain the update.
- File: api/README.md — No mention of any application-level notification or alerting process for product updates or security patches.
- File: deploy/keycloak/dev-realm.json — No evidence of update notification process or alerting for administrators.
- No static code, configuration, or documentation describing a notification process for updates or security patches, nor any mechanism for distributing update information to administrators or users.
- Requirement: NOT SATISFIED — No evidence of an application notification process for updates or security patches, nor any mechanism for communicating risk, mitigations, or update availability.

Remediation:
Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.

---

### 283. APSC-DV-003350 | SV-222671r961863

- Rule ID: SV-222671r961863
- Severity: medium
- Rule Title: Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that connections between the DoD enclave and the Internet or other public/commercial WANs must require a DMZ if the application is publicly accessible.
- File: deploy/aws/iris-stack.yaml — The AWS CloudFormation template provisions an Application Load Balancer (ALB) with Scheme: internet-facing, exposing port 443 to 0.0.0.0/0 (public Internet):
- AlbSecurityGroup:
- SecurityGroupIngress:
- IpProtocol: tcp
- FromPort: 443
- ToPort: 443
- CidrIp: 0.0.0.0/0
- AppLoadBalancer:
- Scheme: internet-facing
- The ALB forwards traffic to EC2 instances in public subnets (MapPublicIpOnLaunch: true), but there is no explicit DMZ network segment or firewall layer statically defined in this template.
- No evidence of a dedicated DMZ subnet or explicit separation between public and private network zones in the provided infrastructure-as-code.
- Requirement: PARTIALLY SATISFIED — Application is publicly accessible via ALB, but static evidence of a DMZ (segregated network zone between public and enclave) is not present in the provided configuration. Further network architecture documentation or VPC/subnet design may be required to confirm DMZ implementation.

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
- The control requires the application to generate audit records when concurrent logons from different workstations occur, including recording the source IP address.
- File: api/README.md — Authentication is handled via Keycloak (OIDC), with JWT-based authentication and RBAC. No mention of application-level audit logging for concurrent logons or source IP tracking.
- File: deploy/keycloak/dev-realm.json — No evidence of audit log configuration or IP address logging for concurrent logons.
- File: api/app/process/router.py — No code for audit logging of logon events or IP addresses.
- No static evidence in application code or configuration of audit record generation for concurrent logons from different workstations, nor of IP address capture in logs.
- Requirement: NOT SATISFIED — No evidence of audit record generation for concurrent logons from different workstations or IP address logging.

Remediation:
Configure the application to log concurrent logons from different workstations.

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires evidence of annual security training for program managers, designers, developers, and testers. This is a process/documentation control, not a technical or code-based control.
- No static artifacts (certificates, rosters, or documentation) are present in the codebase to demonstrate annual security training.
- Requirement: NOT REVIEWED — This control is purely process/documentation-based and cannot be assessed via static source code review.

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
- The control requires NSA-approved cryptography for protecting classified information, but only applies if the application processes classified data.
- File: api/README.md — No mention of processing classified data; S3 buckets and data flows are described for maintenance videos and documents, but no reference to classified or SAMI data.
- File: api/app/config.py — S3 buckets are named 'iris-raw', 'iris-processed', 'iris-maintenance-docs', and 'iris-audio', with no indication of classified data handling.
- File: deploy/aws/iris-stack.yaml — S3 buckets, RDS, and other resources are provisioned, but there is no indication of classified data storage or NSA-approved cryptography requirements.
- Requirement: NOT APPLICABLE — No evidence that the application processes classified information; therefore, this control does not apply.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
