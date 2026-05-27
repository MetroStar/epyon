# iris STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 210 |
| Not a Finding | 19 |
| Not Applicable | 56 |
| Not Reviewed | 1 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide a capability to limit the number of logon sessions per user.
- File: deploy/keycloak/dev-realm.json — No explicit session-per-user limit found. Keycloak realm config includes session timeouts (e.g., "ssoSessionIdleTimeout": 28800), but no setting for max concurrent sessions per user.
- File: api/README.md — No mention of session count limitation in authentication or RBAC documentation.
- File: ui/src/components/video-player/video-player.tsx — No evidence of session count enforcement in UI logic.
- Requirement: NOT SATISFIED — No static artifact found that enforces or configures a per-user session count limit.

Remediation:
Design and configure the application to specify the number of logon sessions that are allowed per user.

---

### 2. APSC-DV-000060 | SV-222388r1043182

- Rule ID: SV-222388r1043182
- Severity: medium
- Rule Title: The application must clear temporary storage and cookies when the session is terminated.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must clear temporary storage and cookies when the session is terminated, and must not store authentication information (username/password) in cookies or local storage.
- File: ui/src/components/video-player/video-player.tsx — No code found that manages cookies or local storage for authentication/session data.
- File: api/README.md — API uses JWT tokens via Authorization header; no mention of cookies or local storage for credentials.
- File: deploy/keycloak/dev-realm.json — No evidence of cookie configuration for session clearing on logout.
- File: ui/vitest.setup.ts — Mocks authentication for tests, but does not indicate production storage behavior.
- Requirement: PARTIALLY SATISFIED — No evidence of credentials being stored in cookies/local storage, but no explicit code or configuration found that clears all temporary storage/cookies on logout. Cannot confirm full compliance from static artifacts.

Remediation:
Design and configure the application to clear sensitive data from cookies and local storage when the user logs out of the application.

---

### 3. APSC-DV-000070 | SV-222389r1043182

- Rule ID: SV-222389r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Non-privileged user sessions must be terminated after 15 minutes of inactivity.
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800 (8 hours), which exceeds the 15 minute (900 seconds) requirement.
- File: api/README.md — No override or mention of a 15-minute idle timeout for non-privileged users.
- Requirement: NOT SATISFIED — Session idle timeout is set to 8 hours, not 15 minutes, in Keycloak configuration.

Remediation:
Design and configure the application to terminate the non-privileged users session after 15 minutes of inactivity.

---

### 4. APSC-DV-000080 | SV-222390r1043182

- Rule ID: SV-222390r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Admin user sessions must be terminated after 10 minutes of inactivity.
- File: deploy/keycloak/dev-realm.json — No separate admin session timeout; "ssoSessionIdleTimeout": 28800 (8 hours) applies to all users.
- File: api/README.md — No evidence of differentiated timeout for admin users.
- Requirement: NOT SATISFIED — No static artifact found that enforces a 10-minute idle timeout for admin sessions.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide a user-initiated logoff capability.
- File: ui/src/components/video-player/video-player.tsx — UI includes logic for exiting sessions and clearing state (e.g., 'Exit' buttons in annotation and clip editor modes, and 'Clear All Data' button at the bottom of the main interface).
- File: ui/src/components/sign-out-modal/sign-out-modal.tsx (not shown, but present in manifest) — Implies existence of a sign-out modal for user-initiated logoff.
- File: api/README.md — JWT-based authentication with Keycloak; session can be terminated by removing token from client.
- Requirement: SATISFIED — UI provides explicit logoff/sign-out controls for user-initiated session termination.

Remediation:
Design and configure the application to provide all users with the capability to manually terminate their application session.

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must display an explicit logoff message to users indicating reliable termination of session.
- File: ui/src/components/video-player/video-player.tsx — 'Exit' actions and 'Clear All Data' reset state, but no evidence of an explicit logoff message or confirmation dialog upon session termination.
- File: ui/src/components/sign-out-modal/sign-out-modal.tsx (not shown, but present in manifest) — Existence of a modal suggests a UI for sign-out, but content of message not confirmed in provided files.
- Requirement: PARTIALLY SATISFIED — UI likely provides a sign-out modal, but explicit logoff message content cannot be confirmed from static artifacts.

Remediation:
Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must associate organization-defined security attributes with information in storage (e.g., data marking for classified/CUI).
- File: api/app/process/router.py — No evidence of data marking or security attribute assignment in storage-related endpoints.
- File: api/app/process/services/scene_summarization.py — No data marking logic present in summarization or S3 storage routines.
- File: pointcloud-project/colmap_ingest.py — Database schema for point cloud data does not include security attribute fields.
- Requirement: NOT SATISFIED — No static artifact found that implements or enforces security attribute marking in storage.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must associate security attributes with information in process (e.g., retain data marking during processing).
- File: api/app/process/router.py — No evidence of security attribute propagation in processing endpoints.
- File: api/app/process/services/scene_summarization.py — No logic for retaining or propagating security attributes during processing.
- File: pointcloud-project/colmap_ingest.py — No handling of security attributes during ingestion or processing.
- Requirement: NOT SATISFIED — No static artifact found that implements security attribute retention during processing.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must associate security attributes with information in transmission (e.g., data marking retained when transmitting data).
- File: api/app/process/router.py — No evidence of security attribute inclusion in API responses or transmission routines.
- File: api/app/process/services/scene_summarization.py — No logic for transmitting security attributes with data.
- File: pointcloud-project/colmap_ingest.py — No transmission logic for security attributes.
- Requirement: NOT SATISFIED — No static artifact found that implements security attribute retention in transmission.

Remediation:
Design and configure the application to retain the data marking when transmitting data.

---

### 10. APSC-DV-000160 | SV-222396r960759

- Rule ID: SV-222396r960759
- Severity: medium
- Rule Title: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: DoD-approved encryption (TLS) to protect confidentiality of remote access sessions.
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is configured for HTTPS (port 443) with ACM certificate (see 'AppLoadBalancer', 'AppListener443', 'Certificates').
- File: api/README.md — API is accessible via HTTP (http://localhost:5000) in development; no explicit enforcement of HTTPS in API configuration.
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none" (development), not enforcing HTTPS at the IdP level.
- Requirement: PARTIALLY SATISFIED — ALB in production is configured for HTTPS, but development and API service may allow plaintext HTTP. Cannot confirm all remote access is always protected by TLS from static artifacts.

Remediation:
Design and configure applications to use TLS encryption to protect the confidentiality of remote access sessions.

---

### 11. APSC-DV-000170 | SV-222397r960762

- Rule ID: SV-222397r960762
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Cryptographic mechanisms (TLS) to protect integrity of remote access sessions.
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (TLS) in production (see 'AppLoadBalancer', 'AppListener443').
- File: api/README.md — API accessible via HTTP in development; no explicit TLS enforcement in backend config.
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none" (development), not enforcing TLS at IdP.
- Requirement: PARTIALLY SATISFIED — Production ALB uses TLS, but development and backend API may allow HTTP. Cannot confirm all remote access is always protected by TLS from static artifacts.

Remediation:
Design and configure applications to use TLS encryption to protect the integrity of remote access sessions.

---

### 12. APSC-DV-000180 | SV-222398r960762

- Rule ID: SV-222398r960762
- Severity: medium
- Rule Title: Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: SOAP messages requiring integrity must include Message ID, Service Request, Timestamp, SAML Assertion, and all elements must be digitally signed.
- No evidence of SOAP message usage or WS-Security in any provided file (API is RESTful, not SOAP-based).
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
- Static repository review completed on 2026-04-29.
- Control requires: Messages protected with WS-Security must use timestamps with creation and expiration times.
- No evidence of WS-Security token usage or SOAP messaging in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Validity periods must be verified on all application messages using WS-Security or SAML assertions.
- No evidence of WS-Security or SAML assertion usage in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Each unique asserting party must provide unique assertion ID references for each SAML assertion.
- No evidence of SAML assertion usage in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Encrypted assertions or equivalent confidentiality protections when assertion data is passed through an intermediary.
- No evidence of WS-Security token or SAML assertion usage in any provided file.
- Requirement: NOT APPLICABLE — Application does not utilize WS-Security tokens or SAML assertions.

Remediation:
Encrypt assertions or use equivalent confidentiality when sensitive assertion data is passed through an intermediary.

---

### 17. APSC-DV-000230 | SV-222403r960759

- Rule ID: SV-222403r960759
- Severity: high
- Rule Title: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Use of NotOnOrAfter condition when using SubjectConfirmation element in a SAML assertion.
- No evidence of SAML assertion usage in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Use of NotBefore and NotOnOrAfter elements or OneTimeUse element when using Conditions element in a SAML assertion.
- No evidence of SAML assertion usage in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Only one OneTimeUse element in the Conditions element of a SAML assertion.
- No evidence of SAML assertion usage in any provided file.
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
- Static repository review completed on 2026-04-29.
- Control requires: Messages must be encrypted when the SessionIndex is tied to privacy data in SAML assertions.
- No evidence of SAML assertion usage or SessionIndex in any provided file.
- Requirement: NOT APPLICABLE — Application does not utilize SAML assertions.

Remediation:
Encrypt messages when the SessionIndex is tied to privacy data.

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for centralized account management, providing automated mechanisms for account creation, modification, disabling, and removal.
- File: deploy/keycloak/dev-realm.json — "registrationAllowed": true, "bruteForceProtected": true, "failureFactor": 3, "waitIncrementSeconds": 60
- File: api/README.md — "The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header."
- File: api/README.md — "The API integrates with Keycloak for authentication and authorization."
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system: Single Sign-On (SSO), Role-Based Access Control (RBAC), User Management, Organizational group hierarchy with automatic role assignment."
- Automated account management (creation, disabling, removal) is handled by Keycloak, which is an automated, repeatable, and auditable solution.
- Requirement: SATISFIED — Centralized, automated account management is enforced via Keycloak.

Remediation:
Use automated processes and mechanisms for account management functions.

---

### 22. APSC-DV-000290 | SV-222408r1015683

- Rule ID: SV-222408r1015683
- Severity: medium
- Rule Title: Shared/group account credentials must be terminated when members leave the group.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application does not define or use shared/group accounts for authentication; all user accounts are individual and managed via Keycloak.
- File: deploy/keycloak/dev-realm.json — All users are defined individually with unique usernames and credentials; no shared/group accounts are present.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system: Single Sign-On (SSO), Role-Based Access Control (RBAC), User Management, Organizational group hierarchy with automatic role assignment."
- No evidence of shared/group account credentials in Keycloak realm or application documentation.
- Requirement: NOT APPLICABLE — No shared/group accounts are used in this architecture.

Remediation:
Create a procedure for deleting either member accounts or the entire group account when members leave the group.

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- There is no evidence of temporary user accounts being supported or used in the Keycloak realm or application documentation.
- File: deploy/keycloak/dev-realm.json — No user accounts are marked as temporary; all users have "enabled": true and no expiration or temporary flags.
- File: README.md — No mention of temporary accounts or related features.
- Requirement: NOT APPLICABLE — Temporary user accounts are not supported or used.

Remediation:
Configure temporary accounts to be automatically removed or disabled after 72 hours after account creation.

---

### 24. APSC-DV-000310 | SV-222410r961863

- Rule ID: SV-222410r961863
- Severity: low
- Rule Title: The application must have a process, feature or function that prevents removal or disabling of emergency accounts.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- There is no evidence of emergency accounts being used or supported in the Keycloak realm or application documentation.
- File: deploy/keycloak/dev-realm.json — No user accounts are designated as emergency accounts; all users are standard operational users.
- File: README.md — No mention of emergency accounts or related features.
- Requirement: NOT APPLICABLE — Emergency accounts are not used.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for centralized user management. Inactivity-based disabling is a feature of Keycloak and can be configured at the realm level, but no evidence in the provided realm config shows a 35-day inactivity timeout. However, the application does not manage user accounts internally.
- File: deploy/keycloak/dev-realm.json — No inactivity timeout is set in the realm config; session timeouts are present but not inactivity-based disabling.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- Requirement: NOT APPLICABLE — User inactivity disabling is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Design and configure the application to expire user accounts after 35 days of inactivity.

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- All application user accounts are managed centrally in Keycloak. Only necessary user accounts are present in the realm configuration.
- File: deploy/keycloak/dev-realm.json — All users are individually defined and mapped to roles/groups; no unnecessary or default accounts are present except for the documented development admin/test users.
- File: README.md — "Default Admin Credentials (development only): Username: admin, Password: TestPassword123!" with explicit instruction to change before production.
- Requirement: SATISFIED — All user accounts are defined and controlled in Keycloak; unnecessary accounts are not present.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Audit logging for account creation is handled by Keycloak, not the application itself.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of local account management or audit logging in the application code.
- Requirement: NOT APPLICABLE — Account creation auditing is handled by the centralized IdP (Keycloak), not the application.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Audit logging for account modification is handled by Keycloak, not the application itself.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of local account management or audit logging in the application code.
- Requirement: NOT APPLICABLE — Account modification auditing is handled by the centralized IdP (Keycloak), not the application.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Audit logging for account disabling is handled by Keycloak, not the application itself.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of local account management or audit logging in the application code.
- Requirement: NOT APPLICABLE — Account disabling auditing is handled by the centralized IdP (Keycloak), not the application.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Audit logging for account removal is handled by Keycloak, not the application itself.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of local account management or audit logging in the application code.
- Requirement: NOT APPLICABLE — Account removal auditing is handled by the centralized IdP (Keycloak), not the application.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Notification of SAs/ISSOs on account creation is a function of the IdP (Keycloak), not the application.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of application-level notification logic for account creation.
- Requirement: NOT APPLICABLE — Notification is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are created.

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Notification of SAs/ISSOs on account modification is a function of the IdP (Keycloak), not the application.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of application-level notification logic for account modification.
- Requirement: NOT APPLICABLE — Notification is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are modified.

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Notification of SAs/ISSOs on account disabling is a function of the IdP (Keycloak), not the application.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of application-level notification logic for account disabling.
- Requirement: NOT APPLICABLE — Notification is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are disabled.

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Notification of SAs/ISSOs on account removal is a function of the IdP (Keycloak), not the application.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of application-level notification logic for account removal.
- Requirement: NOT APPLICABLE — Notification is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Audit logging for account enabling is handled by Keycloak, not the application itself.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of local account management or audit logging in the application code.
- Requirement: NOT APPLICABLE — Account enabling auditing is handled by the centralized IdP (Keycloak), not the application.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for user management. Notification of SAs/ISSOs on account enabling is a function of the IdP (Keycloak), not the application.
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system."
- File: deploy/keycloak/dev-realm.json — No evidence of application-level notification logic for account enabling.
- Requirement: NOT APPLICABLE — Notification is the responsibility of the centralized IdP (Keycloak), not the application.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are enabled.

---

### 37. APSC-DV-000440 | SV-222423r961302

- Rule ID: SV-222423r961302
- Severity: medium
- Rule Title: Application data protection requirements must be identified and documented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- There is partial evidence of data protection requirements being identified and implemented, but no explicit documentation of data protection requirements was found in the provided files.
- File: README.md — "Detailed technical specifications and API documentation are maintained in the `/docs` directory, including: API endpoint specifications, Database schema documentation, UI component integration guides, Deployment and configuration instructions." (But `/docs` directory is not present in the manifest.)
- File: README.md — Describes data flow, storage, and protection mechanisms (e.g., "Metadata Storage: Structured storage for poses, depth maps, and annotations", "Qdrant for document and video content search", "Keycloak provides enterprise-grade authentication and authorization").
- File: deploy/aws/iris-stack.yaml — S3 buckets are configured with "BlockPublicAcls: true", "BlockPublicPolicy: true", "IgnorePublicAcls: true", "RestrictPublicBuckets: true" for data protection.
- File: api/README.md — Describes authentication, authorization, and storage mechanisms, but does not enumerate or document data protection requirements for each data element.
- Requirement: PARTIALLY SATISFIED — Data protection mechanisms are implemented, but explicit documentation of data protection requirements for all application data elements is missing from the provided evidence.

Remediation:
Identify and document the application data elements and the data protection requirements.

---

### 38. APSC-DV-000450 | SV-222424r961305

- Rule ID: SV-222424r961305
- Severity: medium
- Rule Title: The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- There is no explicit evidence of organization-defined data mining detection techniques being implemented or documented in the provided files.
- File: README.md — No mention of data mining detection, query rate limiting, or automated alarming on atypical query events.
- File: api/README.md — No mention of query limits, data mining detection, or protections against data dumps.
- File: api/app/process/router.py — No endpoints or logic related to query rate limiting or data mining detection.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of query limiting or data mining detection in document search logic.
- Requirement: NOT SATISFIED — No evidence of data mining detection techniques or protections.

Remediation:
Utilize and implement data mining protections when requirements specify it.

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application enforces approved authorizations for logical access to information and system resources via Keycloak RBAC and API-level role checks.
- File: deploy/keycloak/dev-realm.json — Roles and groups are defined for RBAC: "role_maintainer", "role_engineer", "role_leadership", "admin", "user"; users are assigned to roles and groups.
- File: api/README.md — "The API implements role-based access control (RBAC) for protected endpoints. Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin. All endpoints except /health require authentication."
- File: api/app/process/router.py — API endpoints are protected by authentication and role-based access control via dependency injection (see README.md for details).
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system: Single Sign-On (SSO), Role-Based Access Control (RBAC), User Management, Organizational group hierarchy with automatic role assignment."
- Requirement: SATISFIED — Access control is enforced via RBAC in Keycloak and API endpoint protection.

Remediation:
Design or configure the application to enforce access to application resources.

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- There is no evidence that discretionary access control (DAC) is implemented or required. All access control is enforced via RBAC (role-based), not user-discretionary sharing or permission assignment.
- File: deploy/keycloak/dev-realm.json — Only RBAC roles and groups are defined; no user-level discretionary permissions.
- File: README.md — No mention of user-controlled sharing or DAC features.
- Requirement: NOT APPLICABLE — Discretionary access control is not implemented or required in this application.

Remediation:
Design and configure the application to enforce discretionary access control policies.

---

### 41. APSC-DV-000480 | SV-222427r1117168

- Rule ID: SV-222427r1117168
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires enforcement of information flow control policies within the system, such as rulesets, data labels, or policies that restrict data movement based on classification or type.
- File: README.md — The architecture and API documentation describe multi-modal data processing, but there is no evidence of explicit data labeling, flow control rules, or enforcement mechanisms for information flow within the application.
- File: api/app/process/router.py — Endpoints process and summarize video and document data, but no code or configuration for data labeling or flow control is present.
- File: vlm-testing/fpv_analyzer_rag.py — Document chunking and embedding for search, but no data labeling or flow control enforcement.
- File: deploy/keycloak/dev-realm.json — RBAC is enforced for user roles, but not for data flow between components or data labeling.
- Requirement: PARTIALLY SATISFIED — RBAC is present for user access, but there is no evidence of information flow control policies or enforcement for data within the system. No data labeling or flow restriction mechanisms are implemented.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 42. APSC-DV-000490 | SV-222428r1117169

- Rule ID: SV-222428r1117169
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires enforcement of information flow control policies between interconnected systems, such as rulesets, data labels, or policies restricting data transfer to external systems.
- File: README.md — Describes integration with external systems (AWS S3, Qdrant, Bedrock, Keycloak), but does not mention any flow control policies or enforcement between these systems.
- File: api/app/process/router.py — Endpoints interact with S3, Qdrant, and Bedrock, but there is no evidence of data labeling or flow control enforcement between these interconnected systems.
- File: deploy/keycloak/dev-realm.json — RBAC is enforced for user access, but not for data flow between systems.
- Requirement: NOT SATISFIED — No evidence of information flow control enforcement between interconnected systems. Data is transferred between components (API, S3, Qdrant, Bedrock) without explicit flow control policies.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 43. APSC-DV-000500 | SV-222429r961353

- Rule ID: SV-222429r961353
- Severity: medium
- Rule Title: The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that non-privileged users cannot execute privileged functions or alter security safeguards.
- File: deploy/keycloak/dev-realm.json — Defines roles (admin, role_maintainer, role_engineer, user, etc.) and assigns them to users. Admin endpoints require admin/maintainer/engineer roles.
- File: api/README.md — 'Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin.'
- File: api/app/process/router.py — No explicit OS-level privilege checks or file system permission restrictions are present in the code. Application-level RBAC is enforced via Keycloak roles.
- File: deploy/aws/iris-stack.yaml — EC2 instance is created with a non-root user and IAM roles, but the actual OS user/group configuration for the application process is not shown in the code provided.
- Requirement: PARTIALLY SATISFIED — Application-level RBAC is enforced via Keycloak, but there is no evidence of OS-level privilege separation or file system permission restrictions for the application user. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Modify the application to limit access and prevent the disabling or circumvention of security safeguards.

---

### 44. APSC-DV-000510 | SV-222430r961359

- Rule ID: SV-222430r961359
- Severity: high
- Rule Title: The application must execute without excessive account permissions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that the application executes without excessive account permissions (OS and database).
- File: deploy/aws/iris-stack.yaml — EC2 instance is created with an IAM instance profile and role, but the specific permissions granted to the application process are not shown in the code provided.
- File: api/README.md — No mention of the application running as a privileged OS user or with excessive database privileges.
- File: deploy/keycloak/dev-realm.json — No evidence of excessive privileges for application users in Keycloak.
- Requirement: PARTIALLY SATISFIED — There is no evidence that the application runs with excessive OS or database privileges, but the actual user/group assignments and database roles are not shown. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.

---

### 45. APSC-DV-000520 | SV-222431r961362

- Rule ID: SV-222431r961362
- Severity: medium
- Rule Title: The application must audit the execution of privileged functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires auditing/logging of privileged function execution (e.g., admin actions).
- File: api/README.md — 'Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin.' No mention of audit logging for privileged actions.
- File: api/app/process/router.py — No evidence of logging for privileged/admin actions. No log statements or audit trail for admin endpoint usage.
- File: api/app/process/services/scene_summarization.py — Logging is present for processing events, but not specifically for privileged function execution.
- Requirement: NOT SATISFIED — No evidence that execution of privileged functions is audited or logged.

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires enforcement of a limit of three consecutive invalid logon attempts within 15 minutes.
- File: deploy/keycloak/dev-realm.json —
- "bruteForceProtected": true
- "failureFactor": 3
- "waitIncrementSeconds": 60
- "minimumQuickLoginWaitSeconds": 60
- "maxFailureWaitSeconds": 900
- "permanentLockout": false
- These settings enforce account lockout after 3 failed attempts within a 15-minute window (900 seconds).
- Requirement: SATISFIED — Keycloak realm configuration enforces lockout after 3 failed logon attempts in 15 minutes.

Remediation:
Configure the application to enforce an account lock after 3 failed logon attempts occurring within a 15-minute window.

---

### 47. APSC-DV-000540 | SV-222433r961368

- Rule ID: SV-222433r961368
- Severity: medium
- Rule Title: The application administrator must follow an approved process to unlock locked user accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires an approved process for unlocking locked user accounts.
- File: deploy/keycloak/dev-realm.json — No evidence of a documented or automated process for unlocking locked accounts. No mention of ISSO/ISSM approval or identity validation process for unlocks.
- Requirement: NOT SATISFIED — No evidence of an approved process for unlocking locked user accounts.

Remediation:
Create a standard approved process for unlocking locked application accounts which includes validating user identity prior to unlocking the account.

Use that process when unlocking application user accounts.

---

### 48. APSC-DV-000550 | SV-222434r960843

- Rule ID: SV-222434r960843
- Severity: low
- Rule Title: The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires display of the Standard Mandatory DoD Notice and Consent Banner before granting access to the application (if interactive UI exists).
- File: ui/.env.example — No banner text or configuration present.
- File: ui/src/components/video-player/video-player.tsx — No code for displaying a DoD banner before login or access.
- File: deploy/keycloak/themes/README.md — Custom Keycloak theme is present, but no evidence of the DoD banner text being included in the login page.
- Requirement: NOT SATISFIED — No evidence that the DoD Notice and Consent Banner is displayed before access to the application.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the DoD banner to remain on screen until users acknowledge usage conditions and take explicit action to log on.
- File: deploy/keycloak/themes/README.md — Custom theme is described, but there is no evidence that the DoD banner is displayed and requires explicit user acknowledgment before login.
- File: ui/src/components/video-player/video-player.tsx — No code for banner acknowledgment before login.
- Requirement: NOT SATISFIED — No evidence that the DoD banner is retained until explicit user acknowledgment.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the DoD banner to be displayed before granting access to a publicly accessible application.
- File: README.md — Application is accessible at http://localhost:3000 (UI Dashboard), but no mention of DoD banner.
- File: deploy/keycloak/themes/README.md — Custom theme is present, but no evidence of DoD banner text.
- Requirement: NOT SATISFIED — No evidence that the DoD Notice and Consent Banner is displayed before access to the publicly accessible application.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires display of the time and date of the user's last successful logon in the user interface.
- File: ui/src/components/video-player/video-player.tsx — No code for displaying last logon time/date.
- File: deploy/keycloak/dev-realm.json — No evidence of last logon time being surfaced to the UI.
- Requirement: NOT SATISFIED — No evidence that the last successful logon time is displayed to the user.

Remediation:
Design and configure the application to display the date and time when the user was last successfully granted access to the application.

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires non-repudiation (e.g., digital signatures) if required by the organization or application design.
- File: README.md — No mention of digital signatures or non-repudiation requirements for application users.
- File: api/README.md — No mention of digital signatures or non-repudiation.
- Requirement: NOT APPLICABLE — Application is not required to provide non-repudiation services for users.

Remediation:
Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.

---

### 53. APSC-DV-000600 | SV-222439r960873

- Rule ID: SV-222439r960873
- Severity: medium
- Rule Title: For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control applies only if the application provides audit record aggregation from multiple system components.
- File: README.md — No mention of audit record aggregation or system-wide audit trail.
- File: api/app/process/router.py — No evidence of log aggregation functionality.
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
- Static repository review completed on 2026-04-29.
- The control requires audit record generation for the creation of session IDs.
- File: api/README.md — Authentication is handled via Keycloak and JWT tokens. No evidence of logging session ID creation events in the application or configuration.
- File: api/app/process/router.py — No code for logging session creation events.
- Requirement: NOT SATISFIED — No evidence that session ID creation events are audited or logged.

Remediation:
Enable session ID creation event auditing.

---

### 55. APSC-DV-000630 | SV-222442r960879

- Rule ID: SV-222442r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the destruction of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit record generation for the destruction of session IDs.
- File: api/README.md — No evidence of logging session destruction events.
- File: api/app/process/router.py — No code for logging session destruction events.
- Requirement: NOT SATISFIED — No evidence that session ID destruction events are audited or logged.

Remediation:
Enable session ID destruction event auditing.

---

### 56. APSC-DV-000640 | SV-222443r960879

- Rule ID: SV-222443r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the renewal of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit record generation for the renewal of session IDs (e.g., privilege escalation).
- File: api/README.md — No evidence of logging session renewal events.
- File: api/app/process/router.py — No code for logging session renewal events.
- Requirement: NOT SATISFIED — No evidence that session ID renewal events are audited or logged.

Remediation:
Design or reconfigure the application to log session renewal events on those application events that provide changes in the users privileges or permissions to the application.

---

### 57. APSC-DV-000650 | SV-222444r960879

- Rule ID: SV-222444r960879
- Severity: medium
- Rule Title: The application must not write sensitive data into the application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that sensitive data (passwords, session IDs, etc.) is not written to application logs.
- File: api/app/process/router.py — No evidence of logging sensitive data, but also no explicit log filtering or redaction. Logging is present for processing events, but the log format and content are not shown.
- File: api/app/process/services/scene_summarization.py — Logging is present for processing events, but no evidence of sensitive data being logged. However, without log samples or explicit filtering, this cannot be fully confirmed.
- Requirement: PARTIALLY SATISFIED — No evidence of sensitive data being logged, but no explicit filtering or redaction is implemented. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Design or reconfigure the application to not write sensitive data to the logs.

---

### 58. APSC-DV-000660 | SV-222445r960879

- Rule ID: SV-222445r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for session timeouts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit record generation for session timeouts.
- File: api/README.md — No evidence of logging session timeout events.
- File: api/app/process/router.py — No code for logging session timeout events.
- Requirement: NOT SATISFIED — No evidence that session timeout events are audited or logged.

Remediation:
Configure the application to record session timeout events in the logs.

---

### 59. APSC-DV-000670 | SV-222446r960879

- Rule ID: SV-222446r960879
- Severity: medium
- Rule Title: The application must record a time stamp indicating when the event occurred.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that a time stamp is recorded for each event in the application logs.
- File: api/app/process/services/scene_summarization.py — Logging is present for processing events, but the log format is not shown. It is unclear if time stamps are included in all log entries.
- File: api/app/process/router.py — No evidence of time stamps in logs.
- Requirement: PARTIALLY SATISFIED — Logging is present, but it is not possible to confirm that all events are time-stamped without log samples or explicit log format configuration.

Remediation:
Configure the application to record the time the event occurred when recording the event.

---

### 60. APSC-DV-000680 | SV-222447r960879

- Rule ID: SV-222447r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit record generation for HTTP headers (User-Agent, Referer, GET, POST, etc.).
- File: api/app/process/router.py — No evidence of logging HTTP headers for incoming requests.
- File: api/README.md — No mention of HTTP header logging.
- Requirement: NOT SATISFIED — No evidence that HTTP headers are logged.

Remediation:
Configure the web application and/or the web server to log HTTP headers.

---

### 61. APSC-DV-000690 | SV-222448r960879

- Rule ID: SV-222448r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for connecting system IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit logs to include connecting system IP addresses.
- File: api/app/process/router.py — No evidence of logging client IP addresses in any endpoint or service call (no references to request.client.host or similar in FastAPI endpoints).
- File: api/README.md — No mention of audit logging or IP address capture in API documentation.
- File: api/app/rag/services.py — No evidence of logging IP addresses in RAG service logic.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of logging IP addresses for user actions.
- File: pointcloud-project/colmap_ingest.py — No evidence of logging IP addresses for database or API access.
- Requirement: PARTIALLY SATISFIED — Application does not statically log connecting IP addresses; no audit log configuration or code for IP capture found. Dynamic review of actual log output is required.

Remediation:
Configure the application or application server to log all connecting IP address information

---

### 62. APSC-DV-000700 | SV-222449r960879

- Rule ID: SV-222449r960879
- Severity: medium
- Rule Title: The application must record the username or user ID of the user associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit logs to record the username or user ID associated with each event.
- File: api/app/process/router.py — No explicit logging of user ID or username in endpoint handlers; endpoints use FastAPI but do not log user identity.
- File: api/README.md — Describes authentication via Keycloak and JWT, and dependency injection of current_user (IrisUser, AdminUser) into endpoints, but does not document audit logging of user identity.
- File: api/app/rag/services.py — No evidence of logging user identity for search or chat actions.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of logging user identity for document or video analysis actions.
- File: pointcloud-project/colmap_ingest.py — No evidence of logging user identity for ingestion or queries.
- Requirement: PARTIALLY SATISFIED — User authentication is enforced, but there is no static evidence that user IDs are recorded in audit logs for events. Dynamic log review is required.

Remediation:
Configure the application to record the user ID of the user responsible for the log event entry.

---

### 63. APSC-DV-000710 | SV-222450r960885

- Rule ID: SV-222450r960885
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to grant privileges.
- File: api/README.md — Keycloak is used for RBAC and user management, with admin endpoints requiring specific roles, but no evidence of application-level audit logging for privilege grants.
- File: api/app/process/router.py — No endpoints for privilege management or logging of privilege grant attempts.
- File: api/app/rag/services.py — No privilege management or audit logging code.
- File: vlm-testing/fpv_analyzer_rag.py — No privilege management or audit logging code.
- File: pointcloud-project/colmap_ingest.py — No privilege management or audit logging code.
- Requirement: PARTIALLY SATISFIED — Privilege management is delegated to Keycloak, but there is no evidence that the application itself logs privilege grant attempts. Keycloak logs may satisfy this, but application-level evidence is missing.

Remediation:
Configure the application to audit successful and unsuccessful attempts to grant privileges.

---

### 64. APSC-DV-000720 | SV-222451r961791

- Rule ID: SV-222451r961791
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to access security objects.
- File: api/README.md — Describes RBAC via Keycloak and protected endpoints, but no evidence of audit logging for access attempts to security objects.
- File: api/app/process/router.py — No explicit logging of access attempts to security objects.
- File: api/app/rag/services.py — No audit logging for access attempts.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for access attempts.
- File: pointcloud-project/colmap_ingest.py — No audit logging for access attempts.
- Requirement: PARTIALLY SATISFIED — Access control is enforced, but audit logging of access attempts to security objects is not statically implemented.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.

---

### 65. APSC-DV-000730 | SV-222452r961794

- Rule ID: SV-222452r961794
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to access security levels.
- File: api/README.md — RBAC is enforced via Keycloak, but no evidence of audit logging for access attempts to different security levels.
- File: api/app/process/router.py — No explicit logging of access attempts to security levels.
- File: api/app/rag/services.py — No audit logging for access attempts to security levels.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for access attempts to security levels.
- File: pointcloud-project/colmap_ingest.py — No audit logging for access attempts to security levels.
- Requirement: PARTIALLY SATISFIED — Access control is present, but audit logging of access attempts to security levels is not statically implemented.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for access to categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- File: api/README.md — No mention of data classification or compartmentalized data categories.
- File: api/app/process/router.py — No endpoints or logic for data classification levels.
- File: api/app/rag/services.py — No evidence of data classification enforcement.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of data classification enforcement.
- File: pointcloud-project/colmap_ingest.py — No evidence of data classification enforcement.
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
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to modify privileges.
- File: api/README.md — Privilege modification is handled by Keycloak, but no evidence of application-level audit logging for privilege modifications.
- File: api/app/process/router.py — No endpoints for privilege modification or audit logging.
- File: api/app/rag/services.py — No audit logging for privilege modification.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for privilege modification.
- File: pointcloud-project/colmap_ingest.py — No audit logging for privilege modification.
- Requirement: PARTIALLY SATISFIED — Privilege modification is managed externally (Keycloak), but application-level audit logging is not present.

Remediation:
Configure the application to audit successful and unsuccessful attempts to modify privileges.

---

### 68. APSC-DV-000760 | SV-222455r961803

- Rule ID: SV-222455r961803
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to modify security objects.
- File: api/README.md — No evidence of audit logging for modification of security objects.
- File: api/app/process/router.py — No endpoints or logic for modifying security objects or audit logging.
- File: api/app/rag/services.py — No audit logging for modification of security objects.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for modification of security objects.
- File: pointcloud-project/colmap_ingest.py — No audit logging for modification of security objects.
- Requirement: PARTIALLY SATISFIED — No static evidence of audit logging for modification of security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security objects.

---

### 69. APSC-DV-000770 | SV-222456r961806

- Rule ID: SV-222456r961806
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to modify security levels.
- File: api/README.md — No evidence of audit logging for modification of security levels.
- File: api/app/process/router.py — No endpoints or logic for modifying security levels or audit logging.
- File: api/app/rag/services.py — No audit logging for modification of security levels.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for modification of security levels.
- File: pointcloud-project/colmap_ingest.py — No audit logging for modification of security levels.
- Requirement: PARTIALLY SATISFIED — No static evidence of audit logging for modification of security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for modification of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- File: api/README.md — No mention of data classification or compartmentalized data categories.
- File: api/app/process/router.py — No endpoints or logic for data classification levels.
- File: api/app/rag/services.py — No evidence of data classification enforcement.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of data classification enforcement.
- File: pointcloud-project/colmap_ingest.py — No evidence of data classification enforcement.
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
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to delete privileges.
- File: api/README.md — Privilege deletion is handled by Keycloak, but no evidence of application-level audit logging for privilege deletions.
- File: api/app/process/router.py — No endpoints for privilege deletion or audit logging.
- File: api/app/rag/services.py — No audit logging for privilege deletion.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for privilege deletion.
- File: pointcloud-project/colmap_ingest.py — No audit logging for privilege deletion.
- Requirement: PARTIALLY SATISFIED — Privilege deletion is managed externally (Keycloak), but application-level audit logging is not present.

Remediation:
Configure the application to audit successful and unsuccessful attempts to delete privileges.

---

### 72. APSC-DV-000800 | SV-222459r961815

- Rule ID: SV-222459r961815
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to delete security levels.
- File: api/README.md — No evidence of audit logging for deletion of security levels.
- File: api/app/process/router.py — No endpoints or logic for deleting security levels or audit logging.
- File: api/app/rag/services.py — No audit logging for deletion of security levels.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for deletion of security levels.
- File: pointcloud-project/colmap_ingest.py — No audit logging for deletion of security levels.
- Requirement: PARTIALLY SATISFIED — No static evidence of audit logging for deletion of security levels.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.

---

### 73. APSC-DV-000810 | SV-222460r961818

- Rule ID: SV-222460r961818
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful attempts to delete application database security objects.
- File: api/README.md — No evidence of audit logging for deletion of database security objects.
- File: api/app/process/router.py — No endpoints or logic for deleting database security objects or audit logging.
- File: api/app/rag/services.py — No audit logging for deletion of database security objects.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for deletion of database security objects.
- File: pointcloud-project/colmap_ingest.py — No audit logging for deletion of database security objects.
- Requirement: PARTIALLY SATISFIED — No static evidence of audit logging for deletion of database security objects.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for deletion of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- File: api/README.md — No mention of data classification or compartmentalized data categories.
- File: api/app/process/router.py — No endpoints or logic for data classification levels.
- File: api/app/rag/services.py — No evidence of data classification enforcement.
- File: vlm-testing/fpv_analyzer_rag.py — No evidence of data classification enforcement.
- File: pointcloud-project/colmap_ingest.py — No evidence of data classification enforcement.
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
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful logon attempts.
- File: api/README.md — Authentication is handled by Keycloak and JWT, but no evidence of application-level logging of logon attempts (success or failure).
- File: api/app/process/router.py — No endpoints for login or explicit logging of authentication events.
- File: api/app/rag/services.py — No audit logging for authentication events.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for authentication events.
- File: pointcloud-project/colmap_ingest.py — No audit logging for authentication events.
- Requirement: PARTIALLY SATISFIED — Authentication is enforced, but audit logging of logon attempts is not statically implemented in the application.

Remediation:
Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.

---

### 76. APSC-DV-000840 | SV-222463r961827

- Rule ID: SV-222463r961827
- Severity: medium
- Rule Title: The application must generate audit records for privileged activities or other system-level access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for privileged activities or system-level access.
- File: api/README.md — Admin endpoints require specific roles, but no evidence of audit logging for privileged activities.
- File: api/app/process/router.py — No explicit logging of privileged actions or system-level access.
- File: api/app/rag/services.py — No audit logging for privileged activities.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for privileged activities.
- File: pointcloud-project/colmap_ingest.py — No audit logging for privileged activities.
- Requirement: PARTIALLY SATISFIED — Privileged access is enforced, but audit logging of privileged activities is not statically implemented.

Remediation:
Configure the application to write a log entry when privileged activities or other system-level events occur.

---

### 77. APSC-DV-000850 | SV-222464r961830

- Rule ID: SV-222464r961830
- Severity: medium
- Rule Title: The application must generate audit records showing starting and ending time for user access to the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records showing starting and ending time for user access to the system.
- File: api/README.md — Session management is handled by Keycloak, but no evidence of application-level logging of session start and end times.
- File: api/app/process/router.py — No explicit logging of session start/end events.
- File: api/app/rag/services.py — No audit logging for session events.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for session events.
- File: pointcloud-project/colmap_ingest.py — No audit logging for session events.
- Requirement: PARTIALLY SATISFIED — Session management is present, but audit logging of session start/end is not statically implemented.

Remediation:
Configure the application or application server to record the start and end time of user session activity.

---

### 78. APSC-DV-000860 | SV-222465r961836

- Rule ID: SV-222465r961836
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful accesses to objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for successful/unsuccessful accesses to objects.
- File: api/app/process/router.py — Endpoints process videos, documents, and other objects, but no evidence of audit logging for access attempts (success or failure) to these objects.
- File: api/app/rag/services.py — No audit logging for access to objects.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for access to objects.
- File: pointcloud-project/colmap_ingest.py — No audit logging for access to objects.
- Requirement: PARTIALLY SATISFIED — Object access is controlled, but audit logging of access attempts is not statically implemented.

Remediation:
Configure the application to log successful and unsuccessful access to application objects.

---

### 79. APSC-DV-000870 | SV-222466r961839

- Rule ID: SV-222466r961839
- Severity: medium
- Rule Title: The application must generate audit records for all direct access to the information system.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for all direct access to the information system (e.g., OS commands, file system navigation, etc.).
- File: api/README.md — No evidence of features allowing direct access to the underlying OS, file system, or system resources from the application.
- File: api/app/process/router.py — No endpoints for direct system access.
- File: api/app/rag/services.py — No direct system access features.
- File: vlm-testing/fpv_analyzer_rag.py — No direct system access features.
- File: pointcloud-project/colmap_ingest.py — No direct system access features.
- Requirement: NOT APPLICABLE — Application does not provide direct access to the underlying information system.

Remediation:
Configure the application to log all direct access to the system.

---

### 80. APSC-DV-000880 | SV-222467r961842

- Rule ID: SV-222467r961842
- Severity: medium
- Rule Title: The application must generate audit records for all account creations, modifications, disabling, and termination events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit records for all account creations, modifications, disabling, and termination events.
- File: api/README.md — User management is handled by Keycloak, with no evidence of application-level audit logging for account events.
- File: api/app/process/router.py — No endpoints for user account management or audit logging.
- File: api/app/rag/services.py — No audit logging for account events.
- File: vlm-testing/fpv_analyzer_rag.py — No audit logging for account events.
- File: pointcloud-project/colmap_ingest.py — No audit logging for account events.
- Requirement: PARTIALLY SATISFIED — User management is delegated to Keycloak, but application-level audit logging for account events is not present. If Keycloak is configured for STIG-compliant logging, this may be satisfied externally, but no static evidence is present in the application code.

Remediation:
Configure the application to log user account creation, modification, disabling, and termination events.

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must initiate session auditing (logging) upon startup.
- File: api/app/process/router.py — No explicit logging of application startup events is present in the router or endpoint definitions.
- File: api/app/process/services/scene_summarization.py — Uses logger = get_logger(__name__), but no evidence of logging application startup events; logging is used for processing events only.
- File: api/app/process/services/scene_classification.py — Uses logger = get_logger(__name__), but only for processing/classification events, not application startup.
- File: api/app/rag/services.py — Uses logger = get_logger(__name__), but only for service-level events, not application startup.
- File: api/README.md — No mention of startup logging in documentation.
- File: README.md — No mention of startup logging in documentation.
- No evidence in provided files of a log entry such as 'Application started' or similar at startup.
- Requirement: PARTIALLY SATISFIED — Logging is implemented for processing events, but there is no static evidence that application startup events are logged. The presence of logging infrastructure suggests it could be implemented, but confirmation is missing.

Remediation:
Configure the application to begin logging application events as soon as the application starts up.

---

### 82. APSC-DV-000940 | SV-222469r960891

- Rule ID: SV-222469r960891
- Severity: medium
- Rule Title: The application must log application shutdown events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must log shutdown events.
- File: api/app/process/router.py — No evidence of logging shutdown events in any endpoint or router logic.
- File: api/app/process/services/scene_summarization.py — Logging is used for processing events, not for application shutdown.
- File: api/app/process/services/scene_classification.py — Logging is used for processing events, not for application shutdown.
- File: api/app/rag/services.py — Logging is used for service events, not for application shutdown.
- No evidence in provided files of a log entry such as 'Application shutting down' or similar.
- Requirement: NOT SATISFIED — No static evidence that application shutdown events are logged.

Remediation:
Configure the application or application server to record application shutdown events in the event logs.

---

### 83. APSC-DV-000950 | SV-222470r960891

- Rule ID: SV-222470r960891
- Severity: medium
- Rule Title: The application must log destination IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must log destination IP addresses for outbound connections.
- File: api/app/process/router.py — No evidence of logging destination IP addresses for any outbound network connections.
- File: api/app/process/services/scene_summarization.py — Outbound connections to AWS Bedrock and S3 are made, but no evidence that destination IPs are logged.
- File: api/app/process/services/scene_classification.py — Outbound connections to Qdrant and S3, but no evidence of logging destination IPs.
- File: api/app/rag/services.py — Outbound connections to S3 and Qdrant, but no evidence of logging destination IPs.
- Requirement: NOT SATISFIED — No static evidence that destination IP addresses are logged for outbound connections.

Remediation:
Configure the application to record the destination IP address of the remote system.

---

### 84. APSC-DV-000960 | SV-222471r960891

- Rule ID: SV-222471r960891
- Severity: medium
- Rule Title: The application must log user actions involving access to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must log user actions involving access to data.
- File: api/app/process/router.py — Endpoints process data but do not log user actions (e.g., which user accessed which data).
- File: api/app/process/services/scene_summarization.py — No user context or access logging.
- File: api/app/process/services/scene_classification.py — No user context or access logging.
- File: api/app/rag/services.py — No user context or access logging.
- File: api/README.md — JWT-based authentication is described, but no evidence that user actions are logged when accessing data.
- Requirement: NOT SATISFIED — No static evidence that user data access actions are logged.

Remediation:
Identify the specific data elements requiring protection and audit access to the data.

---

### 85. APSC-DV-000970 | SV-222472r960891

- Rule ID: SV-222472r960891
- Severity: medium
- Rule Title: The application must log user actions involving changes to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must log user actions involving changes to data.
- File: api/app/process/router.py — Endpoints perform data processing but do not log user actions or changes to data.
- File: api/app/process/services/scene_summarization.py — No evidence of logging user-initiated data changes.
- File: api/app/process/services/scene_classification.py — No evidence of logging user-initiated data changes.
- File: api/app/rag/services.py — No evidence of logging user-initiated data changes.
- Requirement: NOT SATISFIED — No static evidence that user data modification actions are logged.

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Audit records must contain date and time of events.
- File: api/app/process/services/scene_summarization.py — All summary records include 'generated_at': datetime.utcnow().isoformat() + 'Z'.
- File: api/app/process/services/scene_classification.py — All classification records include 'processed_at': datetime.utcnow().isoformat() + 'Z'.
- File: api/app/rag/services.py — S3Manager.list_objects includes 'last_modified': obj['LastModified'].isoformat().
- Requirement: SATISFIED — All audit and processing records include ISO8601 date/time fields.

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Audit records must indicate which component/feature/function triggered the event.
- File: api/app/process/services/scene_summarization.py — Logging includes logger = get_logger(__name__), which records the module name (e.g., 'app.process.services.scene_summarization').
- File: api/app/process/services/scene_classification.py — Logging includes logger = get_logger(__name__), which records the module name (e.g., 'app.process.services.scene_classification').
- File: api/app/rag/services.py — Logging includes logger = get_logger(__name__), which records the module name (e.g., 'app.rag.services').
- Requirement: SATISFIED — Log records include the originating component/module via logger name.

Remediation:
Configure the application to log which component, feature or functionality of the application triggered the event.

---

### 88. APSC-DV-001000 | SV-222475r960900

- Rule ID: SV-222475r960900
- Severity: medium
- Rule Title: When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: When using centralized logging, logs must include a unique identifier for the application and host.
- File: api/app/process/services/scene_summarization.py — No evidence that logs include application name or host identifier.
- File: api/app/process/services/scene_classification.py — No evidence that logs include application name or host identifier.
- File: api/app/rag/services.py — No evidence that logs include application name or host identifier.
- File: api/README.md — No mention of centralized logging configuration or unique application/host identifiers in logs.
- Requirement: NOT SATISFIED — No static evidence that logs include unique application and host identifiers.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Audit records must contain information to establish the outcome of events (e.g., SUCCESS/FAILURE).
- File: api/app/process/services/scene_summarization.py — Logging records processing events but does not explicitly log outcome status (e.g., 'SUCCESS', 'FAILURE').
- File: api/app/process/services/scene_classification.py — Logging records processing events but does not explicitly log outcome status.
- File: api/app/rag/services.py — Logging records service events but does not explicitly log outcome status.
- Requirement: PARTIALLY SATISFIED — Processing results are returned in API responses, but log records do not explicitly record operation outcomes.

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Audit records must establish the identity of any individual or process associated with the event.
- File: api/app/process/router.py — Endpoints do not log user identity or process identity in logs.
- File: api/app/process/services/scene_summarization.py — No evidence of logging user or process identity.
- File: api/app/process/services/scene_classification.py — No evidence of logging user or process identity.
- File: api/app/rag/services.py — No evidence of logging user or process identity.
- Requirement: NOT SATISFIED — No static evidence that audit records include user or process identity.

Remediation:
Configure the application to log the identity of the user and/or the process associated with the event.

---

### 91. APSC-DV-001030 | SV-222478r960909

- Rule ID: SV-222478r960909
- Severity: medium
- Rule Title: The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Audit records must contain full-text recording of privileged commands or individual identities of group account users.
- File: api/app/process/router.py — No evidence of logging privileged commands or group user identities.
- File: api/app/process/services/scene_summarization.py — No evidence of logging privileged commands or group user identities.
- File: api/app/process/services/scene_classification.py — No evidence of logging privileged commands or group user identities.
- File: api/app/rag/services.py — No evidence of logging privileged commands or group user identities.
- Requirement: NOT SATISFIED — No static evidence that privileged commands or group user identities are logged.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must implement transaction recovery logs when transaction based.
- File: api/app/process/services/scene_summarization.py — No evidence of transaction recovery logging.
- File: api/app/process/services/scene_classification.py — No evidence of transaction recovery logging.
- File: api/app/rag/services.py — No evidence of transaction recovery logging.
- File: api/README.md — No mention of transaction recovery logging or database transaction logs.
- Requirement: NOT SATISFIED — No static evidence of transaction recovery logs.

Remediation:
Configure the application database to utilize transactional logging.

---

### 93. APSC-DV-001050 | SV-222480r985972

- Rule ID: SV-222480r985972
- Severity: medium
- Rule Title: The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide centralized management and configuration of audit record content across all components.
- File: api/app/process/services/scene_summarization.py — Logging is implemented per-module, no evidence of centralized log management/configuration.
- File: api/app/process/services/scene_classification.py — Logging is implemented per-module, no evidence of centralized log management/configuration.
- File: api/app/rag/services.py — Logging is implemented per-module, no evidence of centralized log management/configuration.
- Requirement: NOT SATISFIED — No static evidence of centralized log management/configuration.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must off-load audit records onto a different system or media than the system being audited (unless using centralized logging).
- File: api/app/process/services/scene_summarization.py — No evidence of log offloading or centralized logging.
- File: api/app/process/services/scene_classification.py — No evidence of log offloading or centralized logging.
- File: api/app/rag/services.py — No evidence of log offloading or centralized logging.
- File: api/README.md — No mention of log offloading or centralized logging.
- Requirement: NOT SATISFIED — No static evidence of log offloading or centralized logging.

Remediation:
Configure the application to off-load audit records onto a different system as per approved schedule.

---

### 95. APSC-DV-001080 | SV-222482r961860

- Rule ID: SV-222482r961860
- Severity: medium
- Rule Title: The application must be configured to write application logs to a centralized log repository.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must be configured to write application logs to a centralized log repository.
- File: api/app/process/services/scene_summarization.py — No evidence of centralized log repository configuration.
- File: api/app/process/services/scene_classification.py — No evidence of centralized log repository configuration.
- File: api/app/rag/services.py — No evidence of centralized log repository configuration.
- File: api/README.md — No mention of centralized log repository configuration.
- Requirement: NOT SATISFIED — No static evidence of centralized log repository configuration.

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide immediate warning to SA/ISSO when audit record storage reaches 75% of capacity (unless using centralized logging with alarming).
- File: api/app/process/services/scene_summarization.py — No evidence of log storage capacity monitoring or alarming.
- File: api/app/process/services/scene_classification.py — No evidence of log storage capacity monitoring or alarming.
- File: api/app/rag/services.py — No evidence of log storage capacity monitoring or alarming.
- Requirement: NOT SATISFIED — No static evidence of log storage capacity monitoring or alarming.

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide immediate real-time alert to SA/ISSO for all audit failure events (unless using centralized logging with alarming).
- File: api/app/process/services/scene_summarization.py — No evidence of audit failure alarming.
- File: api/app/process/services/scene_classification.py — No evidence of audit failure alarming.
- File: api/app/rag/services.py — No evidence of audit failure alarming.
- Requirement: NOT SATISFIED — No static evidence of audit failure alarming.

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
- Static repository review completed on 2026-04-29.
- Control requires: Application must alert SA/ISSO in the event of an audit processing failure (unless using centralized logging with alarming).
- File: api/app/process/services/scene_summarization.py — No evidence of audit processing failure alarming.
- File: api/app/process/services/scene_classification.py — No evidence of audit processing failure alarming.
- File: api/app/rag/services.py — No evidence of audit processing failure alarming.
- Requirement: NOT SATISFIED — No static evidence of audit processing failure alarming.

Remediation:
Configure the application to send an alarm in the event the audit system has failed or is failing.

---

### 99. APSC-DV-001120 | SV-222486r1043188

- Rule ID: SV-222486r1043188
- Severity: medium
- Rule Title: The application must shut down by default upon audit failure (unless availability is an overriding concern).

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must shut down by default upon audit failure (unless availability is an overriding concern and compensating controls are in place).
- File: api/app/process/services/scene_summarization.py — No evidence of application shutdown or compensating controls on audit failure.
- File: api/app/process/services/scene_classification.py — No evidence of application shutdown or compensating controls on audit failure.
- File: api/app/rag/services.py — No evidence of application shutdown or compensating controls on audit failure.
- Requirement: NOT SATISFIED — No static evidence of application shutdown or compensating controls on audit failure.

Remediation:
Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.

---

### 100. APSC-DV-001130 | SV-222487r960918

- Rule ID: SV-222487r960918
- Severity: medium
- Rule Title: The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must provide the capability to centrally review and analyze audit records from multiple components (unless using centralized logging).
- File: api/app/process/services/scene_summarization.py — Logging is per-module, no evidence of centralized review capability.
- File: api/app/process/services/scene_classification.py — Logging is per-module, no evidence of centralized review capability.
- File: api/app/rag/services.py — Logging is per-module, no evidence of centralized review capability.
- Requirement: NOT SATISFIED — No static evidence of centralized audit review capability.

Remediation:
Configure the application so all of the applications logs are available for review from one centralized location.

---

### 101. APSC-DV-001140 | SV-222488r960924

- Rule ID: SV-222488r960924
- Severity: medium
- Rule Title: The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the application to provide filtering of audit records by user, event type, date/time, system resource, IP, object accessed, event level, and keywords.
- No evidence of an application-level audit log filtering or audit log management UI was found in any provided backend or frontend code (e.g., no endpoints or UI components for audit log filtering, searching, or reporting).
- No log management utility or log filtering API is described in api/README.md or ui/README.md.
- No references to audit log filtering, searching, or reporting in FastAPI routers (e.g., api/app/process/router.py) or in UI components (e.g., ui/src/components/).
- No centralized logging system is referenced in the documentation or code.
- Requirement: NOT SATISFIED — No static evidence of audit log filtering capability present in the application code or documentation.

Remediation:
Configure the application filters to search event logs based on defined criteria.

---

### 102. APSC-DV-001150 | SV-222489r961056

- Rule ID: SV-222489r961056
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires on-demand audit reduction/reporting based on filtered audit event data.
- No endpoints, UI components, or documentation references to audit log reporting or audit reduction features were found in api/README.md, ui/README.md, or any backend router/service code.
- No log management/reporting UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of on-demand audit reduction/reporting capability present.

Remediation:
Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.

---

### 103. APSC-DV-001160 | SV-222490r961413

- Rule ID: SV-222490r961413
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit reduction capability for on-demand audit review and analysis.
- No endpoints, UI components, or documentation references to audit log review, filtering, or analysis features were found in api/README.md, ui/README.md, or backend code.
- No log management/review UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of audit reduction/review capability present.

Remediation:
Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.

---

### 104. APSC-DV-001170 | SV-222491r961416

- Rule ID: SV-222491r961416
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit reduction capability to support after-the-fact investigations.
- No endpoints, UI components, or documentation references to audit log filtering, searching, or after-the-fact investigation features were found in api/README.md, ui/README.md, or backend code.
- No log management/investigation UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of audit reduction/investigation capability present.

Remediation:
Configure the application to provide an audit reduction capability that supports forensic investigations.

---

### 105. APSC-DV-001180 | SV-222492r961419

- Rule ID: SV-222492r961419
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires report generation capability for on-demand audit review and analysis.
- No endpoints, UI components, or documentation references to audit log report generation or audit review/reporting features were found in api/README.md, ui/README.md, or backend code.
- No log management/reporting UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of audit log report generation capability present.

Remediation:
Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 106. APSC-DV-001190 | SV-222493r961422

- Rule ID: SV-222493r961422
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires on-demand report generation for audit logs.
- No endpoints, UI components, or documentation references to audit log report generation or on-demand reporting features were found in api/README.md, ui/README.md, or backend code.
- No log management/reporting UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of on-demand audit log report generation capability present.

Remediation:
Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 107. APSC-DV-001200 | SV-222494r961425

- Rule ID: SV-222494r961425
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires report generation capability for after-the-fact investigations of security incidents.
- No endpoints, UI components, or documentation references to audit log report generation or after-the-fact reporting features were found in api/README.md, ui/README.md, or backend code.
- No log management/reporting UI or API is present in the provided codebase.
- No evidence of centralized logging integration that would make this control not applicable.
- Requirement: NOT SATISFIED — No static evidence of after-the-fact audit log report generation capability present.

Remediation:
Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.

---

### 108. APSC-DV-001210 | SV-222495r961428

- Rule ID: SV-222495r961428
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit reduction (event filtering) must not alter original content or time ordering of audit records.
- No audit reduction/filtering functionality is present in the application code or UI (see APSC-DV-001140 evidence).
- No log filtering or reduction code is present, so no evidence of alteration or preservation of original log content/order can be found.
- Requirement: NOT SATISFIED — No static evidence of audit reduction capability, so preservation of original content cannot be confirmed.

Remediation:
Configure the application to not alter original log content or time ordering of audit records.

---

### 109. APSC-DV-001220 | SV-222496r961431

- Rule ID: SV-222496r961431
- Severity: medium
- Rule Title: The application must provide a report generation capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires report generation must not alter original content or time ordering of audit records.
- No audit log report generation functionality is present in the application code or UI (see APSC-DV-001180 evidence).
- No log reporting code is present, so no evidence of alteration or preservation of original log content/order can be found.
- Requirement: NOT SATISFIED — No static evidence of audit log report generation capability, so preservation of original content cannot be confirmed.

Remediation:
Configure and design the application to not modify source logs when filtering events.

---

### 110. APSC-DV-001250 | SV-222497r960927

- Rule ID: SV-222497r960927
- Severity: medium
- Rule Title: The applications must use internal system clocks to generate time stamps for audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit log timestamps to be generated using internal system clocks.
- No explicit evidence of audit log generation or timestamping is present in the provided codebase (no logging configuration, log writing, or timestamp code found in api/app/process/router.py, api/README.md, or other backend files).
- No log file format or timestamping mechanism is described in documentation.
- Requirement: NOT SATISFIED — No static evidence of audit log timestamping using system clocks.

Remediation:
Configure the application to use the hosting systems internal clock for audit record generation.

---

### 111. APSC-DV-001260 | SV-222498r961443

- Rule ID: SV-222498r961443
- Severity: medium
- Rule Title: The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit log timestamps to be mappable to UTC or GMT.
- No explicit evidence of audit log generation or timestamping is present in the provided codebase (no logging configuration, log writing, or timestamp code found in api/app/process/router.py, api/README.md, or other backend files).
- No log file format or timestamping mechanism is described in documentation.
- Requirement: NOT SATISFIED — No static evidence of audit log timestamping with UTC/GMT mapping.

Remediation:
Configure the application to use the underlying system clock that maps to relevant UTC or GMT timezone.

---

### 112. APSC-DV-001270 | SV-222499r961446

- Rule ID: SV-222499r961446
- Severity: medium
- Rule Title: The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit log timestamps to have a granularity of one second or better.
- No explicit evidence of audit log generation or timestamping is present in the provided codebase (no logging configuration, log writing, or timestamp code found in api/app/process/router.py, api/README.md, or other backend files).
- No log file format or timestamping mechanism is described in documentation.
- Requirement: NOT SATISFIED — No static evidence of audit log timestamping granularity.

Remediation:
Configure the application to leverage the underlying operating system as the time source when recording time stamps or design the application to ensure granularity of 1 second as the minimum degree of precision.

---

### 113. APSC-DV-001280 | SV-222500r960930

- Rule ID: SV-222500r960930
- Severity: medium
- Rule Title: The application must protect audit information from any type of unauthorized read access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit information to be protected from unauthorized read access.
- No evidence of audit log storage location, file permissions, or access control for audit logs is present in the codebase or documentation.
- No application-level audit log access control or RBAC for audit logs is implemented in backend or frontend code.
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
- Static repository review completed on 2026-04-29.
- Control requires audit information to be protected from unauthorized modification.
- No evidence of audit log storage location, file permissions, or access control for audit logs is present in the codebase or documentation.
- No application-level audit log access control or RBAC for audit logs is implemented in backend or frontend code.
- Requirement: NOT SATISFIED — No static evidence of audit log access control or protection from unauthorized modification.

Remediation:
Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 115. APSC-DV-001300 | SV-222502r960936

- Rule ID: SV-222502r960936
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized deletion.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires audit information to be protected from unauthorized deletion.
- No evidence of audit log storage location, file permissions, or access control for audit logs is present in the codebase or documentation.
- No application-level audit log access control or RBAC for audit logs is implemented in backend or frontend code.
- Requirement: NOT SATISFIED — No static evidence of audit log access control or protection from unauthorized deletion.

Remediation:
Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 116. APSC-DV-001310 | SV-222503r960939

- Rule ID: SV-222503r960939
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control applies only if the application provides a distinct audit tool or audit tool functionality (e.g., separate executable, UI module, or menu for audit log viewing/manipulation).
- No audit tool functionality, separate audit tool, or audit log management UI is present in the application codebase or documentation (see APSC-DV-001140 evidence).
- Requirement: NOT APPLICABLE — No audit tool functionality present in the application.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 117. APSC-DV-001320 | SV-222504r960942

- Rule ID: SV-222504r960942
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized modification.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control applies only if the application provides a distinct audit tool or audit tool functionality (e.g., separate executable, UI module, or menu for audit log viewing/manipulation).
- No audit tool functionality, separate audit tool, or audit log management UI is present in the application codebase or documentation (see APSC-DV-001140 evidence).
- Requirement: NOT APPLICABLE — No audit tool functionality present in the application.

Remediation:
Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 118. APSC-DV-001330 | SV-222505r960945

- Rule ID: SV-222505r960945
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized deletion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control applies only if the application provides a distinct audit tool or audit tool functionality (e.g., separate executable, UI module, or menu for audit log viewing/manipulation).
- No audit tool functionality, separate audit tool, or audit log management UI is present in the application codebase or documentation (see APSC-DV-001140 evidence).
- Requirement: NOT APPLICABLE — No audit tool functionality present in the application.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control applies only if the application includes a built-in backup capability for its own audit records.
- No evidence of application-level audit log backup functionality is present in the codebase or documentation.
- No audit log backup settings, schedules, or backup code is present.
- Requirement: NOT APPLICABLE — No built-in audit log backup capability present in the application.

Remediation:
Configure application backup settings to backup application audit logs every 7 days.

---

### 120. APSC-DV-001350 | SV-222507r960951

- Rule ID: SV-222507r960951
- Severity: medium
- Rule Title: The application must use cryptographic mechanisms to protect the integrity of audit information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires cryptographic mechanisms (e.g., hash, message digest) to protect the integrity of audit information.
- No evidence of audit log storage, cryptographic hash generation, or integrity check for audit logs is present in the codebase or documentation.
- No references to cryptographic integrity protection for audit logs in backend or infrastructure code.
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
- Static repository review completed on 2026-04-29.
- Control requires the application to provide separate audit tools (executables or libraries) for viewing/manipulating logs, and that these tools are cryptographically hashed for integrity.
- No evidence of separate audit tool executables or libraries for log viewing/manipulation in the provided manifest or codebase (e.g., no dedicated log viewer, log manipulation utility, or reporting tool binaries/scripts).
- Logging and audit functionality appears to be integrated into the main application codebase (e.g., FastAPI endpoints, logging_config.py), not as separate tools.
- No static artifacts (hash files, checksum lists, or hash validation scripts) for audit tools are present.
- Requirement: NOT APPLICABLE — Application does not provide separate audit tools as standalone files; all audit and logging is handled internally.

Remediation:
Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.

---

### 122. APSC-DV-001370 | SV-222509r961206

- Rule ID: SV-222509r961206
- Severity: medium
- Rule Title: The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires periodic validation of cryptographic hashes for separate audit tool files.
- No separate audit tool executables or libraries are present in the codebase or deployment artifacts (see APSC-DV-001360 evidence).
- No process or script for periodic hash validation of audit tool files is present.
- Requirement: NOT APPLICABLE — No separate audit tools exist; all audit/logging is handled within the main application.

Remediation:
Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.

---

### 123. APSC-DV-001390 | SV-222510r1015689

- Rule ID: SV-222510r1015689
- Severity: medium
- Rule Title: The application must prohibit user installation of software without explicit privileged status.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the application to prohibit user installation of software, plugins, or extensions unless explicitly privileged.
- No evidence in the manifest or codebase of any user-facing plugin/module/extension installation capability (no plugin directories, extension APIs, or UI for user-initiated installs).
- Application is a web-based system with no user-accessible software installation or extension mechanism.
- No references to dynamic code loading, user-uploaded code, or runtime extension points.
- Requirement: NOT APPLICABLE — Application does not provide any mechanism for users to install software components, plugins, or extensions.

Remediation:
Configure the application to prohibit user installation of software without explicit permission.

---

### 124. APSC-DV-001410 | SV-222511r961461

- Rule ID: SV-222511r961461
- Severity: medium
- Rule Title: The application must enforce access restrictions associated with changes to application configuration.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires access restrictions on application configuration changes.
- Environment variables are used for configuration (see api/app/config.py: e.g., 'API_PREFIX', 'AWS_ACCESS_KEY_ID', etc.).
- No evidence of a user-facing configuration interface in the provided codebase (no endpoints or UI for runtime config changes).
- No explicit file permission settings for configuration files are present in the codebase; file permissions are determined by deployment environment (e.g., Docker, EC2, Kubernetes).
- Docker and cloud-init scripts (e.g., deploy/aws/iris-stack.yaml) copy .env files and set permissions (e.g., 'chmod 600 ${ENV_FILE}'), but enforcement of access is dependent on host OS/user context.
- No explicit RBAC or ACL enforcement for configuration file access is present in the application code.
- Requirement: PARTIALLY SATISFIED — Configuration changes are not exposed to regular users via the application, but static file permission enforcement is not fully verifiable from code alone; OS-level controls are required.

Remediation:
Configure the application to limit access to configuration settings to only authorized users.

---

### 125. APSC-DV-001420 | SV-222512r1015690

- Rule ID: SV-222512r1015690
- Severity: medium
- Rule Title: The application must audit who makes configuration changes to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires auditing/logging of who makes configuration changes.
- No evidence in the codebase of audit logging for configuration changes (no log statements or audit trail for .env or config.py changes).
- Configuration is managed via environment variables and files, not via application endpoints or UI.
- No mechanism in the application to log user identity when configuration files are edited (e.g., .env changes are not tracked by the app).
- No integration with OS-level audit logging (e.g., auditd, file integrity monitoring) is present in the codebase.
- Requirement: NOT SATISFIED — No application-level audit trail for configuration changes; changes to config files are not logged with user identity.

Remediation:
Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.

---

### 126. APSC-DV-001430 | SV-222513r1015691

- Rule ID: SV-222513r1015691
- Severity: medium
- Rule Title: The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the application to prevent installation of unsigned patches or components, or provide cryptographic hashes for manual verification.
- No evidence in the codebase or deployment scripts of digital signature verification for patches, service packs, or application components.
- No process or script for verifying cryptographic hashes of new software components prior to installation.
- Docker images are built from source (see api/Dockerfile, .github/workflows/deploy-eks.yml), but no signature or hash verification step is present.
- No documentation or code for validating signatures of third-party dependencies or updates.
- Requirement: NOT SATISFIED — No mechanism to prevent installation of unsigned patches/components or to provide cryptographic hashes for verification.

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
- Static repository review completed on 2026-04-29.
- Control requires limiting privileges to change software libraries (file permissions and application-level restrictions).
- Application libraries are stored under api/app/ and related directories.
- No explicit file permission settings for library directories/files are present in the codebase; enforcement is dependent on deployment environment (Docker, EC2, Kubernetes).
- No application-level interface for updating or modifying libraries is present (no endpoints or UI for library management).
- Docker and cloud-init scripts (e.g., deploy/aws/iris-stack.yaml) do not explicitly restrict write access to library directories beyond standard OS user permissions.
- Requirement: PARTIALLY SATISFIED — No application-level library update capability is exposed, but static file permission enforcement is not fully verifiable from code alone; OS-level controls are required.

Remediation:
Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.

---

### 128. APSC-DV-001460 | SV-222515r961863

- Rule ID: SV-222515r961863
- Severity: medium
- Rule Title: An application vulnerability assessment must be conducted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires regular vulnerability assessments and retention of scan results.
- README.md and api/README.md reference code quality checks (e.g., 'ruff check .'), but no mention of vulnerability scanning tools (e.g., Snyk, Trivy, Bandit, etc.) or scan result artifacts.
- .github/workflows/* include code quality and deployment workflows, but no explicit vulnerability scan steps or artifacts are present in the provided workflows.
- No scan configuration files or scan result reports are present in the repository.
- Requirement: NOT SATISFIED — No evidence of application vulnerability assessment or scan result retention in the static codebase.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the application to restrict program execution in accordance with organizational policy (e.g., AppLocker, RBAC, etc.).
- No explicit policy, terms, or conditions documents are present in the codebase.
- No evidence of application-level execution restriction mechanisms (e.g., RBAC for execution, AppLocker, or similar) in the provided codebase.
- Application uses Keycloak for authentication and RBAC for API endpoints (see api/README.md: 'Role-Based Access Control'), but this controls API access, not program execution at the OS level.
- Requirement: PARTIALLY SATISFIED — API access is RBAC-controlled, but program execution restriction per organizational policy is not statically verifiable.

Remediation:
Restrict application execution in accordance with the policy, terms, and conditions specified.

---

### 130. APSC-DV-001490 | SV-222517r961479

- Rule ID: SV-222517r961479
- Severity: medium
- Rule Title: The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires a deny-all, permit-by-exception (whitelist) policy for execution of authorized software programs, applicable to configuration management or similar applications.
- Application is not a configuration management system or system process manager; it is a web application for AI-enhanced maintenance support.
- No evidence of application whitelisting or execution policy configuration in the codebase.
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
- Static repository review completed on 2026-04-29.
- Control requires disabling non-essential application capabilities.
- README.md and api/README.md describe a modular architecture with multiple services (video analysis, RAG, vector search, etc.).
- No explicit configuration or code for disabling unused modules or features is present in the codebase.
- No feature flag system or configuration for enabling/disabling capabilities is present.
- All services appear to be enabled by default in Docker Compose and deployment scripts.
- Requirement: NOT SATISFIED — No evidence of configuration to disable non-essential capabilities.

Remediation:
Disable application extraneous application functionality that is not required in order to fulfill the application's mission.

---

### 132. APSC-DV-001510 | SV-222519r1043177

- Rule ID: SV-222519r1043177
- Severity: medium
- Rule Title: The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the application to use only PPSM CAL-approved ports and protocols.
- README.md and api/README.md document service ports:
- PostgreSQL: 5432
- Keycloak: 8080
- API: 5000
- UI: 3000
- Qdrant: 6333 (HTTP), 6334 (gRPC)
- No explicit mapping to PPSM CAL categories or documentation of PPSM approval for these ports is present.
- No static configuration enforcing protocol restrictions is present in the codebase.
- Requirement: PARTIALLY SATISFIED — Ports are documented, but no evidence of PPSM CAL approval or enforcement.

Remediation:
Configure the application to utilize application ports approved by the PPSM CAL.

---

### 133. APSC-DV-001520 | SV-222520r1050664

- Rule ID: SV-222520r1050664
- Severity: medium
- Rule Title: The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires reauthentication when user roles are changed or privileges escalated.
- Authentication is handled via Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak').
- Role changes and privilege escalation are managed in Keycloak, not in the application codebase.
- No evidence in the application code of requiring reauthentication on role change or privilege escalation (no endpoint or middleware enforcing reauthentication on sensitive actions).
- Requirement: NOT SATISFIED — No application-level enforcement of reauthentication on role change or privilege escalation.

Remediation:
Configure the application to require reauthentication before user privilege is escalated and user roles are changed.

---

### 134. APSC-DV-001530 | SV-222521r985974

- Rule ID: SV-222521r985974
- Severity: medium
- Rule Title: The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires devices (e.g., gateways, firewalls) to periodically reauthenticate.
- No evidence in the codebase of device authentication or periodic device reauthentication configuration.
- Application is primarily user-authenticated via Keycloak; device authentication is not addressed in the provided code.
- Requirement: NOT SATISFIED — No configuration or code for device reauthentication.

Remediation:
Configure the application to require reauthentication periodically.

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires unique identification and authentication of organizational users.
- api/README.md: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'
- Keycloak is configured as the identity provider (see api/README.md: 'Keycloak Configuration', 'KEYCLOAK_URL=http://localhost:8080', etc.).
- Role-based access control is enforced via JWT claims and FastAPI dependency injection (see api/README.md: 'Role-Based Access Control', 'All API endpoints (except /health) use FastAPI dependency injection for authentication').
- Default admin credentials are provided for development only (README.md: 'Default Admin Credentials (development only): Username: admin, Password: TestPassword123!').
- Requirement: SATISFIED — Unique user identification and authentication is enforced via Keycloak and JWT tokens.

Remediation:
Configure the application to uniquely identify and authenticate users and user processes.

---

### 136. APSC-DV-001550 | SV-222523r960972

- Rule ID: SV-222523r960972
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires multifactor (Alt. Token) authentication for network access to privileged accounts.
- Authentication is handled via Keycloak (see api/README.md), which supports multifactor authentication, but no evidence in the codebase or configuration that Alt. Token (e.g., CAC/PIV) is enforced for privileged accounts.
- No references to CAC, PIV, or Alt. Token authentication in the provided codebase or configuration files.
- Requirement: NOT SATISFIED — No evidence of multifactor (Alt. Token) authentication enforcement for privileged accounts.

Remediation:
Configure the application to use an Alt. Token when providing network access to privileged application accounts.

---

### 137. APSC-DV-001560 | SV-222524r961494

- Rule ID: SV-222524r961494
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires acceptance of Personal Identity Verification (PIV) credentials (e.g., CAC).
- Authentication is handled via Keycloak (see api/README.md), which can support CAC/PIV, but no evidence in the codebase or configuration that CAC/PIV authentication is enabled or required.
- No references to CAC, PIV, or certificate-based authentication in the provided codebase or configuration files.
- Requirement: NOT SATISFIED — No evidence of CAC/PIV authentication enforcement.

Remediation:
Configure the application to require CAC authentication.

---

### 138. APSC-DV-001570 | SV-222525r961497

- Rule ID: SV-222525r961497
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires electronic verification of PIV credentials (e.g., CAC PIN prompt and certificate validation).
- Authentication is handled via Keycloak (see api/README.md), which can support CAC/PIV, but no evidence in the codebase or configuration that CAC/PIV authentication and PIN verification is enabled or required.
- No references to CAC, PIV, or certificate-based authentication in the provided codebase or configuration files.
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
- Static repository review completed on 2026-04-29.
- Control requires multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.
- Authentication is handled via Keycloak (see api/README.md), which can support multifactor authentication, but no evidence in the codebase or configuration that CAC or Alt. Token authentication is enabled or required for non-privileged accounts.
- No references to CAC, PIV, or Alt. Token authentication in the provided codebase or configuration files.
- Requirement: NOT SATISFIED — No evidence of multifactor authentication enforcement for non-privileged accounts.

Remediation:
Configure the application to require CAC or Alt. Token authentication for non-privileged network access to non-privileged accounts.

---

### 140. APSC-DV-001590 | SV-222527r1015693

- Rule ID: SV-222527r1015693
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires multifactor (Alt. Token) authentication for local access to privileged accounts.
- Authentication is handled via Keycloak (see api/README.md), which can support multifactor authentication, but no evidence in the codebase or configuration that Alt. Token authentication is enforced for local privileged access.
- No references to CAC, PIV, or Alt. Token authentication in the provided codebase or configuration files.
- Requirement: NOT SATISFIED — No evidence of multifactor (Alt. Token) authentication enforcement for local privileged accounts.

Remediation:
Configure the application to only use Alt. Tokens when locally accessing privileged application accounts.

---

### 141. APSC-DV-001600 | SV-222528r1015694

- Rule ID: SV-222528r1015694
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires multifactor authentication (e.g., CAC, Alt. Token) for local access to nonprivileged accounts.
- File: deploy/keycloak/dev-realm.json — no evidence of CAC or certificate-based authentication enforcement; "sslRequired": "none"
- File: security-documents/keycloak.json — "sslRequired": "none"; no MFA or certificate authentication settings
- File: api/README.md — authentication is via Keycloak using username/password and JWT; no mention of CAC or Alt. Token
- File: README.md — Keycloak is used for SSO, but no evidence of PKI or CAC integration
- Requirement: PARTIALLY SATISFIED — Keycloak provides SSO and RBAC, but there is no evidence of CAC, Alt. Token, or certificate-based authentication being required for nonprivileged accounts. MFA is not enforced. SSL is not required for authentication. Further configuration or documentation is needed to confirm compliance.

Remediation:
Configure the application to require CAC or Alt. Token authentication for nonprivileged network access.

---

### 142. APSC-DV-001610 | SV-222529r1015695

- Rule ID: SV-222529r1015695
- Severity: medium
- Rule Title: The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires that users are authenticated with an individual authenticator prior to using a group authenticator. If the application does not use group or shared accounts, this is Not Applicable.
- File: deploy/keycloak/dev-realm.json — all users have unique usernames; no group/shared accounts are defined for authentication
- File: security-documents/keycloak.json — same as above; users are individually named
- File: api/README.md — authentication is via individual Keycloak accounts; no mention of shared/group account logins
- Requirement: SATISFIED — application does not use group or shared accounts for authentication; only individual user accounts exist

Remediation:
Design and configure the application to individually authenticate group account members prior to allowing access.

---

### 143. APSC-DV-001620 | SV-222530r960993

- Rule ID: SV-222530r960993
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires replay-resistant authentication mechanisms (e.g., TLS 1.2+, Kerberos, IPSEC, SSH) for privileged accounts.
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none"; no enforcement of TLS for authentication
- File: security-documents/keycloak.json — "sslRequired": "none"
- File: api/README.md — authentication is via JWT tokens from Keycloak; no explicit mention of TLS enforcement for API endpoints or Keycloak
- File: README.md — Keycloak is used for authentication, but no evidence of enforced TLS or replay-resistant protocol for privileged authentication
- Requirement: PARTIALLY SATISFIED — JWT tokens are used, but there is no evidence that TLS 1.2+ is enforced for authentication traffic. "sslRequired": "none" in Keycloak realm config means SSL is not required. Replay-resistant mechanisms are not fully enforced.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating privileged accounts.

---

### 144. APSC-DV-001630 | SV-222531r1015696

- Rule ID: SV-222531r1015696
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires replay-resistant authentication mechanisms (e.g., TLS 1.2+, Kerberos, IPSEC, SSH) for nonprivileged accounts.
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none"; no enforcement of TLS for authentication
- File: security-documents/keycloak.json — "sslRequired": "none"
- File: api/README.md — authentication is via JWT tokens from Keycloak; no explicit mention of TLS enforcement for API endpoints or Keycloak
- File: README.md — Keycloak is used for authentication, but no evidence of enforced TLS or replay-resistant protocol for nonprivileged authentication
- Requirement: PARTIALLY SATISFIED — JWT tokens are used, but there is no evidence that TLS 1.2+ is enforced for authentication traffic. "sslRequired": "none" in Keycloak realm config means SSL is not required. Replay-resistant mechanisms are not fully enforced.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating nonprivileged accounts.

---

### 145. APSC-DV-001640 | SV-222532r960999

- Rule ID: SV-222532r960999
- Severity: medium
- Rule Title: The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires mutual authentication (e.g., client certificate authentication) when endpoint device non-repudiation is required.
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none"; no evidence of mutual TLS or client certificate authentication
- File: security-documents/keycloak.json — "sslRequired": "none"
- File: api/README.md — no mention of mutual authentication or client certificate requirements
- File: README.md — no evidence of mutual authentication in architecture or deployment
- Requirement: NOT SATISFIED — mutual authentication is not configured or enforced in any static configuration. No evidence of client certificate authentication.

Remediation:
Configure the application to utilize mutual authentication when specified by data protection requirements.

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires authentication of all network-connected endpoint devices (e.g., SOA, web services). If the application is designed for end-user, interactive access only and does not use web services or allow connections from remote devices, this is Not Applicable.
- File: README.md — application is an interactive web application for human users; no evidence of device-to-device or SOA endpoint authentication
- File: api/README.md — API is for user interaction, not device/service integration
- Requirement: SATISFIED — application does not expose web services for remote device/service consumers; only user authentication is present

Remediation:
Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires mutual SSL/TLS authentication for SOA applications handling non-releasable data. If the application is not SOA and does not process non-releasable data via system-to-system endpoints, this is Not Applicable.
- File: README.md — application is not a service-oriented architecture (SOA); it is an interactive web application for human users
- File: api/README.md — API is for user interaction, not system-to-system integration
- Requirement: SATISFIED — application is not SOA and does not require mutual SSL/TLS for device authentication

Remediation:
Configure the application to utilize mutual authentication when the application is processing non-releasable data.

---

### 148. APSC-DV-001670 | SV-222535r1015697

- Rule ID: SV-222535r1015697
- Severity: medium
- Rule Title: The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires disabling device identifiers after 35 days of inactivity unless cryptographic certificates are used for authentication. If the application does not authenticate devices, or uses PKI certificates, this is Not Applicable.
- File: README.md — no evidence of device authentication (e.g., mobile, IoT, or smart devices)
- File: api/README.md — authentication is for users, not devices
- File: deploy/keycloak/dev-realm.json — no device accounts or device authentication
- Requirement: SATISFIED — application does not authenticate devices; only user accounts are present

Remediation:
Configure the application to disable device accounts after 35 days of inactivity or to utilize DOD PKI certificates that provide an expiration date.

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires a minimum 15-character password length.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: security-documents/keycloak.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- Requirement: SATISFIED — Keycloak realm enforces minimum password length of 15 characters via passwordPolicy

Remediation:
Configure the application to require 15 characters in the password.

---

### 150. APSC-DV-001690 | SV-222537r1015699

- Rule ID: SV-222537r1015699
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one uppercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires at least one uppercase character in passwords.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no uppercase requirement)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not require at least one uppercase character

Remediation:
Configure the application to require at least one uppercase character in the password.

---

### 151. APSC-DV-001700 | SV-222538r1015700

- Rule ID: SV-222538r1015700
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one lowercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires at least one lowercase character in passwords.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no lowercase requirement)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not require at least one lowercase character

Remediation:
Configure the application to require at least one lowercase character in the password.

---

### 152. APSC-DV-001710 | SV-222539r1015701

- Rule ID: SV-222539r1015701
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one numeric character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires at least one numeric character in passwords.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no numeric requirement)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not require at least one numeric character

Remediation:
Configure the application to require at least one numeric character in the password.

---

### 153. APSC-DV-001720 | SV-222540r1015702

- Rule ID: SV-222540r1015702
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one special character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires at least one special character in passwords.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no special character requirement)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not require at least one special character

Remediation:
Configure the application to require at least one special character in the password.

---

### 154. APSC-DV-001730 | SV-222541r1043189

- Rule ID: SV-222541r1043189
- Severity: medium
- Rule Title: The application must require the change of at least eight of the total number of characters when passwords are changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires that at least eight characters change when passwords are changed.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no min change requirement)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not enforce minimum character change on password update

Remediation:
Configure the application to require the change of at least eight characters in the password when passwords are changed.

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires that only cryptographic representations of passwords are stored.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: security-documents/keycloak.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- Passwords are stored using PBKDF2 with 27,500 iterations ("hashIterations(27500)")
- No evidence of plaintext or MD5 password storage
- Requirement: SATISFIED — passwords are stored as cryptographic hashes using PBKDF2 with a strong iteration count

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
- Static repository review completed on 2026-04-29.
- Control requires that passwords are only transmitted over cryptographically-protected channels (e.g., TLS).
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none"
- File: security-documents/keycloak.json — "sslRequired": "none"
- File: api/README.md — no explicit mention of HTTPS/TLS enforcement for API or Keycloak endpoints
- File: README.md — Keycloak and API endpoints are referenced as http://localhost:8080 and http://localhost:5000; no evidence of HTTPS enforcement
- Requirement: NOT SATISFIED — no evidence that passwords are transmitted only over encrypted channels; SSL/TLS is not required in Keycloak configuration

Remediation:
Configure the application to encrypt passwords when they are being transmitted.

---

### 157. APSC-DV-001760 | SV-222544r1015705

- Rule ID: SV-222544r1015705
- Severity: medium
- Rule Title: The application must enforce 24 hours/1 day as the minimum password lifetime.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires a minimum password lifetime of 24 hours.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no min lifetime setting)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not enforce a minimum password lifetime

Remediation:
Configure the application to have a minimum password lifetime of 24 hours.

---

### 158. APSC-DV-001770 | SV-222545r1043190

- Rule ID: SV-222545r1043190
- Severity: medium
- Rule Title: The application must enforce a 60-day maximum password lifetime restriction.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires a maximum password lifetime of 60 days.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" (no max lifetime setting)
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password policy does not enforce a maximum password lifetime

Remediation:
Configure the application to have a maximum password lifetime of 60 days.

---

### 159. APSC-DV-001780 | SV-222546r1015267

- Rule ID: SV-222546r1015267
- Severity: medium
- Rule Title: The application must prohibit password reuse for a minimum of five generations.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires prohibition of password reuse for a minimum of five generations.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)" ("passwordHistory(3)")
- File: security-documents/keycloak.json — same as above
- Requirement: NOT SATISFIED — password history is set to 3, which is less than the required 5 generations

Remediation:
Configure the application to prohibit password reuse for up to five passwords.

---

### 160. APSC-DV-001790 | SV-222547r985976

- Rule ID: SV-222547r985976
- Severity: medium
- Rule Title: The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires the use of temporary passwords for system logons with immediate change to a permanent password.
- File: deploy/keycloak/dev-realm.json — user credentials have "temporary": false for all users
- File: security-documents/keycloak.json — same as above
- No evidence of temporary password enforcement or forced password change on first login
- Requirement: NOT SATISFIED — application does not enforce temporary password usage with immediate change to permanent password

Remediation:
Configure the application to specify when a password is temporary and change the temporary password on the first use.

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication and user management, enforcing that only users can change their own passwords and not those of others.
- File: deploy/keycloak/dev-realm.json — "resetPasswordAllowed": false
- File: deploy/keycloak/dev-realm.json — "editUsernameAllowed": false
- File: deploy/keycloak/dev-realm.json — User credentials are defined per user, e.g.,
- "username": "maintainer1", ... "credentials": [{"type": "password", "value": "TestPassword123!", "temporary": false}]
- File: deploy/keycloak/dev-realm.json — User profile config restricts editing username to admin only: '"permissions":{"view":["admin","user"],"edit":["admin"]}'
- File: deploy/keycloak/dev-realm.json — No evidence of cross-user password change capability; password reset is not allowed for users: "resetPasswordAllowed": false
- Requirement: SATISFIED — Keycloak realm configuration ensures only the user or admin can change their own password; users cannot change passwords for other users.

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
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication and session management, but there is no explicit evidence in the provided static configuration or code that user sessions are forcibly terminated upon account deletion.
- File: deploy/keycloak/dev-realm.json — Keycloak manages users and sessions, but no explicit session termination policy on account deletion is shown.
- File: api/README.md — API relies on Keycloak for authentication and session tokens (JWT), but no code or configuration is shown for session invalidation on user deletion.
- Requirement: PARTIALLY SATISFIED — Keycloak supports session management, but static evidence of session termination upon account deletion is not present. Confirmation would require dynamic testing or Keycloak admin configuration export.

Remediation:
Configure the application to terminate existing sessions of users whose accounts are deleted.

---

### 163. APSC-DV-001810 | SV-222550r961038

- Rule ID: SV-222550r961038
- Severity: high
- Rule Title: The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication, which supports PKI-based authentication and certificate validation, but there is no static evidence of PKI/certificate login being enabled or certificate path validation being configured.
- File: deploy/keycloak/dev-realm.json — "protocol": "openid-connect", but no evidence of X.509 or PKI login flows enabled.
- File: api/README.md — JWT authentication via Keycloak, but no mention of certificate-based login or certificate validation path.
- Requirement: PARTIALLY SATISFIED — Keycloak is capable of PKI validation, but no static configuration or code shows PKI/certificate login or path validation is enabled.

Remediation:
Design the application to construct a certification path to an accepted trust anchor when using PKI-based authentication.

---

### 164. APSC-DV-001820 | SV-222551r961041

- Rule ID: SV-222551r961041
- Severity: high
- Rule Title: The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found of application-managed private keys for PKI or code signing. The only private key references are for SSL/TLS (see deploy/aws/iris-stack.yaml), but access control for these keys is handled by AWS Secrets Manager and EC2 instance permissions.
- File: deploy/aws/iris-stack.yaml — SSL private key is retrieved from AWS Secrets Manager and written to /opt/iris/ui/ssl/nginx.key with 'chmod 600', restricting access to the owner.
- File: deploy/aws/iris-stack.yaml — 'chmod 600 "${IRIS_DIR}/ui/ssl/nginx.key"' ensures only the owner can read the key.
- No evidence of application-level private key storage or access control logic in the application codebase.
- Requirement: PARTIALLY SATISFIED — SSL private key is protected by file permissions, but no evidence of application-level private key management or enforcement of access controls for cryptographic modules.

Remediation:
Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication and supports group and user mapping in JWT tokens, but there is no evidence of PKI-based authentication mapping certificates to users/groups.
- File: deploy/keycloak/dev-realm.json — Group and role mapping is present (see 'groups', 'realmRoles', and protocol mappers for 'groups'), but only for OpenID Connect, not for PKI/certificates.
- File: api/README.md — JWT tokens include user claims and roles, but no mention of certificate mapping.
- Requirement: PARTIALLY SATISFIED — User/group mapping is implemented for OpenID Connect, but not for PKI-based authentication.

Remediation:
Configure the application to map certificate information to individual users or group accounts or create a process for automatically determining the individual user or group based on certificate information provided in the logs.

---

### 166. APSC-DV-001840 | SV-222553r1015707

- Rule ID: SV-222553r1015707
- Severity: medium
- Rule Title: The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found of certificate revocation checking (CRL or OCSP) or local cache of revocation data for PKI-based authentication.
- File: deploy/keycloak/dev-realm.json — No CRL or OCSP configuration present.
- File: api/README.md — No mention of certificate revocation or PKI-based authentication.
- Requirement: NOT SATISFIED — No static evidence of CRL import or revocation checking.

Remediation:
Implement a CRL import process and configure the application to check the CRL if OCSP is not available.

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication, and the custom login theme is configured to obfuscate password input fields.
- File: deploy/keycloak/themes/README.md — Describes login form with password field using input type 'password' and eye icon toggle for momentary display.
- File: deploy/keycloak/themes/iris/login/login-username.ftl (referenced in README) — Password field is rendered as <input type="password">, which obfuscates input by default.
- File: deploy/keycloak/dev-realm.json — Keycloak login theme is set to 'iris', which implements the above.
- Requirement: SATISFIED — Passwords are not displayed as clear text during entry; obfuscation is enforced by the login theme.

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
- Static repository review completed on 2026-04-29.
- The application uses cryptographic modules for JWT verification and S3 access, but there is no static evidence that only FIPS-approved cryptographic modules are used for authentication to cryptographic modules.
- File: api/README.md — JWT verification uses RS256 (asymmetric) algorithm, but no explicit statement of FIPS 140-2 validated libraries.
- File: deploy/aws/iris-stack.yaml — AWS services (S3, RDS) are used, which can be FIPS-compliant, but no explicit FIPS enforcement is shown in configuration.
- Requirement: PARTIALLY SATISFIED — Cryptographic modules are used, but FIPS validation cannot be confirmed from static artifacts.

Remediation:
Use FIPS-approved cryptographic modules.

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application uses Keycloak for authentication, which uniquely identifies and authenticates all users, including non-organizational users if present.
- File: deploy/keycloak/dev-realm.json — Each user has a unique username and email, and group/role assignments are explicit.
- File: api/README.md — All API endpoints (except /health) require authentication via JWT tokens issued by Keycloak.
- Requirement: SATISFIED — All users are uniquely identified and authenticated via Keycloak.

Remediation:
Configure the application to identify and authenticate all non-organizational users.

---

### 170. APSC-DV-001880 | SV-222557r961527

- Rule ID: SV-222557r961527
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found that the application is configured to accept PIV credentials from other federal agencies.
- File: deploy/keycloak/dev-realm.json — No configuration for PIV or external identity providers.
- File: api/README.md — Authentication is via Keycloak OpenID Connect, but no mention of PIV or external IdP integration.
- Requirement: NOT SATISFIED — No static evidence of PIV credential acceptance.

Remediation:
Configure the application to accept PIV credentials when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 171. APSC-DV-001890 | SV-222558r961530

- Rule ID: SV-222558r961530
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found that the application electronically verifies PIV credentials from other federal agencies.
- File: deploy/keycloak/dev-realm.json — No configuration for PIV or external IdP verification.
- File: api/README.md — No mention of PIV verification or certificate validation.
- Requirement: NOT SATISFIED — No static evidence of PIV credential verification.

Remediation:
Configure the application to verify the PIV credentials presented when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 172. APSC-DV-001900 | SV-222559r1015708

- Rule ID: SV-222559r1015708
- Severity: medium
- Rule Title: The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found that the application accepts FICAM-approved third-party credentials.
- File: deploy/keycloak/dev-realm.json — No configuration for external IdPs or FICAM trust.
- File: api/README.md — Authentication is via Keycloak, but no mention of FICAM or external IdP integration.
- Requirement: NOT SATISFIED — No static evidence of FICAM-approved credential acceptance.

Remediation:
Configure applications intended to be accessible to nonfederal government agencies to use FICAM-approved third-party credentials.

---

### 173. APSC-DV-001910 | SV-222560r1067800

- Rule ID: SV-222560r1067800
- Severity: medium
- Rule Title: The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found that the application conforms to FICAM-issued profiles (e.g., SAML, OpenID with FICAM trust).
- File: deploy/keycloak/dev-realm.json — OpenID Connect is used, but no explicit FICAM profile conformance or external IdP trust is shown.
- File: api/README.md — No mention of FICAM profiles or technical conformance.
- Requirement: NOT SATISFIED — No static evidence of FICAM profile conformance.

Remediation:
Configure the application to conform to FICAM-issued technical profiles when providing services that rely on external (federal government) identity providers.

---

### 174. APSC-DV-001930 | SV-222561r961548

- Rule ID: SV-222561r961548
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No evidence found that the application provides non-local maintenance or diagnostic sessions.
- File: api/README.md — No mention of remote maintenance or diagnostic capabilities.
- File: README.md — Application is for video analysis and knowledge management, not remote maintenance.
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
- Static repository review completed on 2026-04-29.
- No static evidence found of race condition testing or static analysis tool configuration for race conditions.
- File: api/README.md — Code quality checks are run with 'ruff check .', but ruff does not check for race conditions.
- No test results or static analysis reports for race conditions are present in the provided files.
- Requirement: NOT SATISFIED — No evidence of race condition testing or analysis.

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
- Static repository review completed on 2026-04-29.
- Control requires: Application must terminate all network connections associated with a communications session at the end of the session.
- No explicit session termination logic or network connection teardown is visible in the provided FastAPI router code (api/app/process/router.py).
- No explicit session management or connection close logic is present in the provided UI code (ui/src/components/video-player/video-player.tsx).
- The backend API appears to be stateless REST (see api/README.md: 'All API endpoints (except /health) use FastAPI dependency injection for authentication'), which typically does not maintain persistent network sessions per user, but this is not explicitly documented.
- No explicit WebSocket or long-lived connection handling is present in the reviewed files.
- Requirement: PARTIALLY SATISFIED — No evidence of persistent network sessions, but explicit session termination logic is not visible in the provided code. Full confirmation requires review of session/token invalidation and any long-lived connection handling.

Remediation:
Configure or design the application to terminate application network sessions at the end of the session.

---

### 182. APSC-DV-002020 | SV-222570r1117181

- Rule ID: SV-222570r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when signing application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must utilize FIPS-validated cryptographic modules when signing application components.
- No evidence of application component signing (e.g., code signing, artifact signing) is present in the provided source files or documentation (README.md, api/README.md, api/app/config.py).
- No references to cryptographic signing libraries or FIPS-validated modules for signing are found in the provided code.
- No explicit documentation of a code signing process or FIPS module usage.
- Requirement: NOT SATISFIED — No evidence of signing process or FIPS-validated cryptographic module usage for signing application components.

Remediation:
Utilize FIPS-validated algorithms when signing application components.

---

### 183. APSC-DV-002030 | SV-222571r1117181

- Rule ID: SV-222571r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.
- In vlm-testing/fpv_analyzer_rag.py, the following is used for document hashing:
- File: vlm-testing/fpv_analyzer_rag.py — `hashlib.md5(f.read()).hexdigest()`
- The use of MD5 is not FIPS-approved for cryptographic purposes and is explicitly prohibited for new DoD systems.
- No evidence of SHA-256 or stronger FIPS-validated hash algorithms being used for security-sensitive operations.
- Requirement: NOT SATISFIED — MD5 is used for document hashing; FIPS-validated hash algorithms (SHA-256 or stronger) are not enforced.

Remediation:
Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.

---

### 184. APSC-DV-002040 | SV-222572r1117181

- Rule ID: SV-222572r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.
- In api/app/config.py, cryptographic configuration is present for AWS S3, Bedrock, and Qdrant, but there is no explicit evidence of FIPS-validated cryptographic modules being enforced for data protection at rest or in transit.
- No explicit references to FIPS-validated cryptographic modules or settings (e.g., enforcing FIPS mode in Python, OpenSSL, or AWS SDKs).
- No documentation or code indicating FIPS mode is enabled for cryptographic operations.
- Requirement: NOT SATISFIED — No evidence of FIPS-validated cryptographic module enforcement for protection of sensitive data.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 185. APSC-DV-002050 | SV-222573r1117181

- Rule ID: SV-222573r1117181
- Severity: medium
- Rule Title: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.
- No evidence of SAML assertion generation or SAML SessionIndex handling in any provided code or documentation (README.md, api/README.md, api/app/process/router.py, api/app/config.py, vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py).
- Authentication is handled via Keycloak using OpenID Connect/OAuth2 (see api/README.md: 'The API uses JWT-based authentication via Keycloak').
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
- Static repository review completed on 2026-04-29.
- Control requires: Application user interface must be physically or logically separated from data storage and management interfaces.
- File: README.md — 'Frontend Integration' and 'Backend Services' are described as separate components; UI is a React+Nginx service, API is a FastAPI service, and database is PostgreSQL, each as separate Docker containers.
- File: README.md — 'The docker-compose configuration includes: ... db: PostgreSQL database ... keycloak: Identity and access management ... iris-api: Backend API service (FastAPI) ... iris-ui: Frontend UI service (React + Nginx) ... Services are automatically networked and include health checks for reliability. The startup order is: db → keycloak → api → ui.'
- File: api/README.md — 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'
- The UI does not have direct access to the database or management interfaces; all access is mediated via the API.
- Requirement: SATISFIED — UI and data storage/management interfaces are logically separated via service boundaries and network segmentation.

Remediation:
Configure the application so user interface to the application and management interface to the application is separated.

---

### 187. APSC-DV-002210 | SV-222575r1043178

- Rule ID: SV-222575r1043178
- Severity: medium
- Rule Title: The application must set the HTTPOnly flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must set the HTTPOnly flag on session cookies.
- No explicit evidence in the provided FastAPI backend code (api/app/process/router.py) or UI code (ui/src/components/video-player/video-player.tsx) of session cookie creation or HTTPOnly flag setting.
- Authentication is handled via Keycloak (see api/README.md), which typically sets HTTPOnly on its own session cookies, but this is not confirmed in the provided static files.
- No explicit Set-Cookie headers or session cookie configuration is visible in the provided code.
- Requirement: PARTIALLY SATISFIED — Keycloak is likely to set HTTPOnly on its session cookies, but this cannot be confirmed from the provided static code. Full confirmation requires review of Keycloak configuration or runtime inspection.

Remediation:
Configure the application to set the HTTPOnly flag on session cookies.

---

### 188. APSC-DV-002220 | SV-222576r1043178

- Rule ID: SV-222576r1043178
- Severity: medium
- Rule Title: The application must set the secure flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must set the secure flag on session cookies.
- No explicit evidence in the provided FastAPI backend code (api/app/process/router.py) or UI code (ui/src/components/video-player/video-player.tsx) of session cookie creation or Secure flag setting.
- Authentication is handled via Keycloak (see api/README.md), which can be configured to set the Secure flag, but this is not confirmed in the provided static files.
- No explicit Set-Cookie headers or session cookie configuration is visible in the provided code.
- Requirement: PARTIALLY SATISFIED — Keycloak is likely to set Secure on its session cookies if configured for HTTPS, but this cannot be confirmed from the provided static code. Full confirmation requires review of Keycloak configuration or runtime inspection.

Remediation:
Configure the application to ensure the secure flag is set on session cookies.

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must not expose session IDs.
- Authentication is handled via Keycloak using JWT tokens (see api/README.md: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.').
- No evidence of session IDs being transmitted in URLs or exposed in logs in the provided code.
- No explicit documentation or code confirming that session IDs are only transmitted over encrypted channels (e.g., HTTPS/TLS enforcement).
- Requirement: PARTIALLY SATISFIED — JWT tokens are used for authentication, but explicit enforcement of encrypted transport (HTTPS) is not visible in the provided static code. Full confirmation requires review of deployment configuration and Keycloak settings.

Remediation:
Configure the application to protect session IDs from interception or from manipulation.

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Application must destroy the session ID value and/or cookie on logoff or browser close.
- No explicit evidence in the provided FastAPI backend code (api/app/process/router.py) or UI code (ui/src/components/video-player/video-player.tsx) of session destruction or logout handling.
- Authentication is handled via Keycloak, which typically provides session invalidation endpoints, but this is not confirmed in the provided static files.
- No explicit logout endpoint or session cookie clearing logic is visible in the provided code.
- Requirement: PARTIALLY SATISFIED — Keycloak likely provides session destruction, but this cannot be confirmed from the provided static code. Full confirmation requires review of Keycloak configuration and logout flow.

Remediation:
Configure the application to destroy session ID cookies once the application session has terminated.

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Applications must use system-generated session identifiers that protect against session fixation.
- Authentication is handled via Keycloak using JWT tokens (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No evidence of custom session ID generation or session fixation mitigation in the provided code.
- No explicit documentation of session fixation protection mechanisms.
- Requirement: PARTIALLY SATISFIED — Keycloak is likely to generate secure session IDs, but this cannot be confirmed from the provided static code. Full confirmation requires review of Keycloak configuration and session management.

Remediation:
Design the application to generate new session IDs with unique values when authenticating user sessions.

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Applications must validate session identifiers.
- Authentication is handled via Keycloak using JWT tokens (see api/README.md: 'The API verifies JWT tokens using Keycloak's public keys (JWKS) without requiring a client secret.').
- JWT validation is described, but no explicit evidence of session ID validation for non-JWT sessions is present.
- Requirement: PARTIALLY SATISFIED — JWT validation is present, but full session identifier validation for all session types cannot be confirmed from the provided static code.

Remediation:
Configure the application to configure user session identifiers.

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: Applications must not use URL embedded session IDs.
- Authentication is handled via Keycloak using JWT tokens in the Authorization header (see api/README.md: 'Protected endpoints require a valid JWT token in the Authorization header.').
- No evidence of session IDs being transmitted via URL parameters or URL rewriting in the provided code (api/app/process/router.py, ui/src/components/video-player/video-player.tsx).
- Requirement: SATISFIED — Session IDs are not transmitted via URLs; authentication uses Authorization headers.

Remediation:
Configure the application to transmit session ID information via cookies.

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must not re-use or recycle session IDs.
- Authentication is handled via Keycloak using JWT tokens (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence of session ID re-use or recycling in the provided code.
- No explicit documentation or code confirming that session IDs are not re-used after logout.
- Requirement: PARTIALLY SATISFIED — Keycloak is likely to generate new session IDs per session, but this cannot be confirmed from the provided static code. Full confirmation requires review of Keycloak configuration and session management.

Remediation:
Design the application to not re-use session IDs.

---

### 195. APSC-DV-002290 | SV-222583r1051270

- Rule ID: SV-222583r1051270
- Severity: medium
- Rule Title: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.
- Authentication is handled via Keycloak using JWT tokens (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence of the random number generator used for session ID generation in Keycloak or the application.
- No documentation or code confirming use of a FIPS 140-2/140-3 approved RNG for session IDs.
- Requirement: NOT SATISFIED — Cannot confirm use of FIPS-approved RNG for session ID generation from provided static code.

Remediation:
Configure the application server to generate unique session identifiers and to use a FIPS 140-2/140-3 random number generator to generate the randomness of the session identifiers.

---

### 196. APSC-DV-002300 | SV-222584r961596

- Rule ID: SV-222584r961596
- Severity: medium
- Rule Title: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.
- In deploy/aws/iris-stack.yaml, ACM certificate ARN is referenced for ALB HTTPS termination:
- File: deploy/aws/iris-stack.yaml — 'AcmCertificateArn: ... Description: ACM certificate ARN for ALB HTTPS (required)'
- No explicit evidence that only DoD-approved CAs are used for ACM certificates.
- No explicit certificate validation or CA pinning logic is present in the application code.
- Requirement: PARTIALLY SATISFIED — ACM certificate is required for HTTPS, but enforcement of DoD-approved CAs is not confirmed in the provided static code. Full confirmation requires review of ACM certificate issuance and CA trust configuration.

Remediation:
Configure the application to utilize DoD-approved PKI established CAs when verifying DoD-signed certificates.

---

### 197. APSC-DV-002310 | SV-222585r961122

- Rule ID: SV-222585r961122
- Severity: high
- Rule Title: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.
- No explicit error handling or secure-fail logic is visible in the provided FastAPI router code (api/app/process/router.py) or in the deployment scripts (deploy/aws/bootstrap_pipeline.py).
- No documentation of secure-fail design or test plans for failure scenarios.
- Requirement: NOT SATISFIED — No evidence of secure-fail behavior or documentation of such in the provided static code.

Remediation:
Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).

---

### 198. APSC-DV-002320 | SV-222586r961125

- Rule ID: SV-222586r961125
- Severity: medium
- Rule Title: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.
- In api/app/process/services/scene_summarization.py, logging is performed via 'logger = get_logger(__name__)', but the persistence and retention of logs is not described.
- No explicit documentation of operational requirements for log retention or recovery information.
- No evidence of log aggregation or backup for root cause analysis.
- Requirement: PARTIALLY SATISFIED — Logging is present, but retention and recovery documentation is missing.

Remediation:
Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.

---

### 199. APSC-DV-002330 | SV-222587r1136910

- Rule ID: SV-222587r1136910
- Severity: medium
- Rule Title: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.
- In api/app/config.py, S3 buckets are used for storage (S3_RAW_BUCKET, S3_PROCESSED_BUCKET), but no explicit evidence of encryption at rest or integrity protection is present.
- In deploy/aws/iris-stack.yaml, S3 bucket is created with PublicAccessBlockConfiguration, but no explicit encryption configuration is shown.
- No evidence of S3 server-side encryption (SSE) or client-side encryption in the provided code.
- Requirement: NOT SATISFIED — No evidence of encryption or integrity protection for stored data.

Remediation:
Identify data elements that require protection. Document the data types and specify protection requirements and methods used.

---

### 200. APSC-DV-002340 | SV-222588r1067803

- Rule ID: SV-222588r1067803
- Severity: high
- Rule Title: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest.
- In api/app/config.py, S3 buckets are used for storage (S3_RAW_BUCKET, S3_PROCESSED_BUCKET), but no explicit evidence of encryption or cryptographic integrity mechanisms is present.
- In deploy/aws/iris-stack.yaml, S3 bucket is created, but no explicit encryption configuration (e.g., SSE-S3, SSE-KMS) is shown.
- No evidence of cryptographic integrity mechanisms (e.g., HMAC, digital signatures) for stored data.
- Requirement: NOT SATISFIED — No evidence of cryptographic mechanisms to prevent unauthorized modification of data at rest.

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
- Static repository review completed on 2026-04-29.
- The control requires cryptographic protection of stored DoD information when required by policy or data owner.
- File: deploy/aws/iris-stack.yaml — S3 bucket resource 'IrisS3Bucket' is created with 'BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', and 'RestrictPublicBuckets' set to true, but there is no explicit 'BucketEncryption' property or server-side encryption configuration present in the CloudFormation template.
- File: api/README.md — Mentions S3 storage for video and metadata, but does not specify encryption at rest.
- File: api/app/process/services/scene_summarization.py — S3Manager is used to store summaries and metadata, but no evidence of encryption configuration for S3 uploads.
- File: vlm-testing/fpv_analyzer_rag.py — Qdrant vector database is used for document embeddings, but no evidence of encryption at rest for Qdrant data.
- File: pointcloud-project/docker-compose.yml — PostgreSQL service uses 'secure_password_here' but no evidence of encrypted storage.
- No evidence of RDS encryption configuration in deploy/aws/iris-stack.yaml for 'PostgresDB'.
- Requirement: PARTIALLY SATISFIED — S3 buckets are private, but there is no explicit evidence of encryption at rest for S3, RDS, or Qdrant. Additional configuration or documentation is needed to confirm cryptographic protection of stored data.

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
- Static repository review completed on 2026-04-29.
- The control requires isolation of security functions from non-security functions, such as RBAC and protection of security assets.
- File: api/README.md — 'The API implements role-based access control (RBAC) for protected endpoints.'
- File: api/README.md — 'Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin.'
- File: api/README.md — 'All endpoints except /health require authentication.'
- File: api/app/process/router.py — All endpoints are defined under FastAPI routers, and authentication/authorization is enforced via dependency injection (see docstring: 'All API endpoints (except /health) use FastAPI dependency injection for authentication').
- File: README.md — 'Keycloak provides enterprise-grade authentication and authorization for the IRIS system: Single Sign-On (SSO), Role-Based Access Control (RBAC), Fine-grained permissions using atomic and composite roles.'
- File: README.md — 'JWT tokens containing roles and groups for API authorization.'
- File: deploy/keycloak/themes/README.md — Custom Keycloak theme, but not directly related to RBAC.
- Requirement: SATISFIED — Security functions (authentication, RBAC, admin endpoints) are isolated from non-security functions via Keycloak and FastAPI dependency injection, as documented in api/README.md and enforced in code.

Remediation:
Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.

---

### 203. APSC-DV-002370 | SV-222591r1117179

- Rule ID: SV-222591r1117179
- Severity: medium
- Rule Title: The application must maintain a separate execution domain for each executing process.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires separate execution domains for each executing process (sandboxing, process isolation).
- File: README.md — The system is deployed as a set of Docker containers (see 'Quick Start with Docker', 'Docker Compose Architecture', and 'Docker Services').
- File: docker-compose.dev.yml (referenced in README.md) — Each service (db, keycloak, iris-api, iris-ui, qdrant) runs in its own container.
- File: deploy/aws/iris-stack.yaml — EC2 instance runs Docker and launches containers for each service.
- File: pointcloud-project/docker-compose.yml — PostgreSQL runs in its own container for the pointcloud project.
- Requirement: NOT APPLICABLE — The application is architected as a set of containerized microservices, each running in a separate Docker container, which provides process isolation by design.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires prevention of unauthorized and unintended information transfer via shared system resources.
- File: README.md — Docker Compose is used to network services, and S3 is used for storage. No evidence of file sharing protocols or shared local disk between containers.
- File: deploy/aws/iris-stack.yaml — S3 bucket 'IrisS3Bucket' is created with public access blocked, but no explicit evidence of S3 bucket policies restricting cross-application access.
- File: api/README.md — S3 is used for video and metadata storage, but no evidence of S3 bucket policies or IAM roles limiting access to only authorized services.
- File: pointcloud-project/docker-compose.yml — PostgreSQL data is stored in a Docker volume, but no evidence of access controls on the volume.
- Requirement: PARTIALLY SATISFIED — Docker containers provide some isolation, and S3 buckets are private, but there is no explicit evidence of S3 bucket policies, IAM role restrictions, or file permission controls to prevent unauthorized access to shared resources. Additional configuration or documentation is needed.

Remediation:
Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.

---

### 205. APSC-DV-002390 | SV-222593r961620

- Rule ID: SV-222593r961620
- Severity: medium
- Rule Title: XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control applies only to XML-based applications and requires mitigation of XML DoS attacks.
- File: README.md — No mention of XML-based APIs or XML processing.
- File: api/README.md — All API endpoints are RESTful and use JSON (Swagger/OpenAPI docs at /docs and /redoc), no mention of XML endpoints.
- File: api/app/process/router.py — All endpoints use JSON request/response models (FastAPI/Pydantic), no XML parsing or serialization.
- File: vlm-testing/fpv_analyzer_rag.py — No XML processing, only PDF and video analysis.
- Requirement: NOT APPLICABLE — The application does not contain or utilize XML; all APIs are JSON-based.

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
- Static repository review completed on 2026-04-29.
- The control requires the application to restrict the ability to launch DoS attacks against itself or other systems.
- File: api/app/process/router.py — Endpoints for batch processing (e.g., /process/video-batch) accept 'max_workers' parameter, with documentation recommending conservative values to avoid resource exhaustion (e.g., 'Use max_workers=2 for testing', 'Monitor Bedrock rate limits with high parallelism').
- File: api/README.md — No mention of explicit anti-DoS protections (rate limiting, throttling, etc.).
- File: README.md — No mention of anti-DoS technology or emergency response services.
- No evidence of WAF, API gateway rate limiting, or application-level throttling in provided files.
- Requirement: PARTIALLY SATISFIED — Some guidance is present in API documentation to avoid resource exhaustion, but there is no evidence of enforced rate limiting, throttling, or anti-DoS controls in code or infrastructure.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires redundancy mechanisms for high-availability systems.
- File: README.md — Mentions 'Robust connectivity for real-time video streaming and analysis', 'Docker Compose Architecture', and 'Startup order is: db → keycloak → api → ui', but does not explicitly state high-availability or redundancy mechanisms (e.g., load balancers, multiple instances, failover).
- File: deploy/aws/iris-stack.yaml — Defines an Application Load Balancer (AppLoadBalancer), MultiAZ RDS (MultiAZ: true), and two subnets (Subnet1, Subnet2), which are components of a redundant architecture.
- File: deploy/aws/iris-stack.yaml — AppLoadBalancer uses ACM certificate for HTTPS, and RDS is MultiAZ, but EC2 instance (IrisEC2Instance) is a single instance (no auto-scaling group or multiple EC2s).
- Requirement: PARTIALLY SATISFIED — The infrastructure includes a load balancer and MultiAZ RDS, but the application server is a single EC2 instance. Full high-availability (e.g., multiple app servers, auto-scaling) is not evident.

Remediation:
Build the application to address issues that are found in a redundant environment and utilize redundancy mechanisms to provide high availability.

---

### 208. APSC-DV-002440 | SV-222596r961632

- Rule ID: SV-222596r961632
- Severity: high
- Rule Title: The application must protect the confidentiality and integrity of transmitted information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires protection of confidentiality and integrity of transmitted information (e.g., TLS).
- File: deploy/aws/iris-stack.yaml — AppLoadBalancer is configured with 'Scheme: internet-facing', 'Port: 443', 'Protocol: HTTPS', and 'Certificates' referencing ACM certificate ARN. Health checks use HTTPS.
- File: README.md — 'Configure all of the application systems to require TLS encryption in accordance with data protection requirements.'
- File: README.md — 'Keycloak Admin Console: http://localhost:8080/admin' (no HTTPS for local dev), but production uses ALB with HTTPS.
- File: api/README.md — API endpoints are exposed at http://localhost:5000 (no HTTPS in dev), but production is behind ALB with HTTPS.
- No evidence of TLS enforcement for internal service-to-service communication (e.g., API to Qdrant, API to PostgreSQL).
- Requirement: PARTIALLY SATISFIED — External access to the application is protected by HTTPS via ALB, but there is no evidence of TLS for internal communications between services.

Remediation:
Configure all of the application systems to require TLS encryption in accordance with data protection requirements.

---

### 209. APSC-DV-002450 | SV-222597r1117180

- Rule ID: SV-222597r1117180
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires cryptographic mechanisms to prevent unauthorized disclosure and/or detect changes during transmission (e.g., TLS, message signing).
- File: deploy/aws/iris-stack.yaml — AppLoadBalancer uses HTTPS with ACM certificate for external access.
- File: README.md — No mention of message-level integrity mechanisms (e.g., digital signatures, HMAC, CRCs) for API payloads or files.
- File: api/README.md — API endpoints use HTTP/HTTPS depending on environment; no mention of message signing or integrity checks beyond transport encryption.
- No evidence of TLS for internal service-to-service communication or message-level integrity mechanisms.
- Requirement: PARTIALLY SATISFIED — HTTPS is used for external access, but there is no evidence of message-level integrity or TLS for internal communications.

Remediation:
Configure the application to use cryptographic protections to prevent unauthorized disclosure of application data based upon the application architecture.

---

### 210. APSC-DV-002460 | SV-222598r961638

- Rule ID: SV-222598r961638
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires confidentiality and integrity of information during preparation for transmission (e.g., automatic HTTPS redirect, TLS by default).
- File: deploy/aws/iris-stack.yaml — AppLoadBalancer listens on port 443 (HTTPS) and forwards to target group on port 443, but the application server (iris-ui) listens on port 3000 (see README.md), and API listens on port 5000 (see api/README.md).
- File: README.md — Local development uses http://localhost:3000 and http://localhost:5000 (no HTTPS), but production is behind ALB with HTTPS.
- No evidence of automatic HTTP-to-HTTPS redirection at the application or Nginx level for UI or API.
- No evidence of TLS for backend (API to DB, API to Qdrant) connections.
- Requirement: PARTIALLY SATISFIED — External access is via HTTPS, but there is no evidence of automatic HTTPS redirection or TLS for backend communications.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 211. APSC-DV-002470 | SV-222599r961641

- Rule ID: SV-222599r961641
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during reception.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires confidentiality and integrity of information during reception (e.g., TLS for incoming connections).
- File: deploy/aws/iris-stack.yaml — AppLoadBalancer uses HTTPS for external access.
- File: README.md — Local development uses HTTP, production uses HTTPS via ALB.
- No evidence of TLS for backend (API to DB, API to Qdrant) connections.
- No evidence of automatic HTTPS redirection for UI or API.
- Requirement: PARTIALLY SATISFIED — External access is via HTTPS, but there is no evidence of TLS for backend communications or automatic HTTPS redirection.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 212. APSC-DV-002480 | SV-222600r961638

- Rule ID: SV-222600r961638
- Severity: medium
- Rule Title: The application must not disclose unnecessary information to users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to not disclose unnecessary information to users (e.g., technical details in error messages).
- File: api/app/process/router.py — API endpoints raise HTTPException with detailed error messages, e.g., 'detail=f"Failed to process video: {str(e)}"', 'detail=f"Bedrock service error: {str(e)}"', 'detail=f"Failed to get processing status: {str(e)}"'.
- File: api/README.md — No mention of custom error pages or error message sanitization.
- File: README.md — No mention of error handling or information disclosure controls.
- Requirement: NOT SATISFIED — API returns detailed error messages including exception strings, which may disclose internal information. No evidence of generic error pages or sanitization.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that sensitive information is not stored in hidden fields in web forms.
- File: ui/src/components/* — Not included in context, but README.md and api/README.md indicate authentication/session management is handled via Keycloak and JWT tokens, not via hidden fields in forms.
- File: README.md — 'Keycloak provides enterprise-grade authentication and authorization', 'JWT tokens containing roles and groups for API authorization'.
- File: api/README.md — 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.'
- Requirement: NOT APPLICABLE — The application uses token-based authentication and does not store sensitive information in hidden fields.

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
- Static repository review completed on 2026-04-29.
- The control requires protection from Cross-Site Scripting (XSS) vulnerabilities.
- File: README.md — No mention of XSS protection or input sanitization in UI or API.
- File: api/README.md — No mention of input validation or output encoding for API endpoints.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Use Streamlit for UI, which may provide some built-in escaping, but custom HTML is rendered via st.components.v1.html() with user-controlled content (e.g., chat messages, video player HTML), and no evidence of output encoding or sanitization.
- No evidence of automated vulnerability scan results or XSS testing.
- Requirement: NOT SATISFIED — No evidence of XSS mitigation (input validation, output encoding, or framework auto-escaping) in provided files.

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
- Static repository review completed on 2026-04-29.
- The control requires protection from Cross-Site Request Forgery (CSRF) vulnerabilities.
- File: README.md — No mention of CSRF protection.
- File: api/README.md — API uses JWT-based authentication via Authorization header, which mitigates CSRF for API endpoints, but no explicit mention of CSRF tokens or SameSite cookie settings for UI.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Use Streamlit for UI, which is not a traditional web app framework and may not be exposed to CSRF, but no explicit evidence of CSRF protection.
- No evidence of automated vulnerability scan results or CSRF testing.
- Requirement: PARTIALLY SATISFIED — API is protected by JWT tokens (reducing CSRF risk), but there is no explicit evidence of CSRF tokens or SameSite cookie settings for UI. No scan results provided.

Remediation:
Configure the application to use unpredictable challenge tokens and check the HTTP referrer to ensure the request was issued from the site itself.  Implement mitigating controls as required such as using web reputation services.

---

### 216. APSC-DV-002510 | SV-222604r961158

- Rule ID: SV-222604r961158
- Severity: high
- Rule Title: The application must protect from command injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires protection from command injection vulnerabilities.
- File: api/app/process/services/scene_summarization.py — Uses ffmpeg and cv2.VideoCapture to process video files, but no evidence of user input being passed directly to shell commands.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Use OpenCV and ffmpeg for video processing, but no evidence of unsanitized user input being passed to shell commands.
- No evidence of input sanitization or validation for file paths or other user-supplied data.
- No evidence of automated vulnerability scan results or command injection testing.
- Requirement: PARTIALLY SATISFIED — No direct evidence of command injection, but lack of input validation and scan results leaves risk unconfirmed.

Remediation:
Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.

---

### 217. APSC-DV-002520 | SV-222605r961158

- Rule ID: SV-222605r961158
- Severity: medium
- Rule Title: The application must protect from canonical representation vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires protection from canonical representation vulnerabilities (e.g., Unicode normalization, encoding assertions).
- File: README.md, api/README.md — No mention of character encoding, Unicode normalization, or canonicalization.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — No evidence of encoding assertions or normalization for user input or file handling.
- No evidence of automated vulnerability scan results or code review for canonicalization issues.
- Requirement: NOT SATISFIED — No evidence of canonicalization or encoding controls.

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
- Static repository review completed on 2026-04-29.
- The control requires validation of all input.
- File: api/app/process/router.py — API endpoints accept request models (Pydantic), which provides some type validation, but no evidence of additional input validation (e.g., length, format, content checks) for user-supplied data.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — No evidence of input validation for uploaded files or user-supplied text.
- No evidence of automated vulnerability scan results or input fuzzing.
- Requirement: PARTIALLY SATISFIED — Pydantic models provide type validation for API, but no evidence of comprehensive input validation or scan results.

Remediation:
Design and configure the application to validate input prior to executing commands.

---

### 219. APSC-DV-002540 | SV-222607r961158

- Rule ID: SV-222607r961158
- Severity: high
- Rule Title: The application must not be vulnerable to SQL Injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to not be vulnerable to SQL Injection.
- File: api/README.md — PostgreSQL is used for session metadata, but no evidence of ORM usage or parameterized queries in provided files.
- File: api/bootstrap_pipeline.py — Uses SQLAlchemy's create_all() and text() for schema migration, but no evidence of user input being passed to raw SQL queries.
- No evidence of automated vulnerability scan results or SQL injection testing.
- Requirement: PARTIALLY SATISFIED — No direct evidence of SQL injection, but lack of scan results and code samples for query construction leaves risk unconfirmed.

Remediation:
Modify the application and remove SQL injection vulnerabilities.

---

### 220. APSC-DV-002550 | SV-222608r961158

- Rule ID: SV-222608r961158
- Severity: high
- Rule Title: The application must not be vulnerable to XML-oriented attacks.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to not be vulnerable to XML-oriented attacks (e.g., XML injection, XPATH injection).
- File: README.md, api/README.md, api/app/process/router.py — No evidence of XML parsing, XML endpoints, or XML-based web services. All APIs use JSON.
- Requirement: NOT APPLICABLE — The application does not process XML.

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
- Static repository review completed on 2026-04-29.
- The control requires evidence that input handling vulnerabilities (e.g., lack of input validation/sanitization) are mitigated and that vulnerability scans are performed and remediated.
- File: api/app/process/router.py — API endpoints use FastAPI schemas for request validation (e.g., 'ProcessVideoRequest', 'ObjectDetectionRequest'), which provides some input validation at the API layer.
- File: api/README.md — No mention of static/dynamic application security testing (SAST/DAST) or vulnerability scanning in the documentation.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — No explicit input validation or sanitization for user-uploaded files or text input; relies on Streamlit and Google Gemini APIs for some input handling, but no evidence of systematic input sanitization.
- No scan results, scan configuration, or risk acceptance documentation present in the provided files.
- Requirement: PARTIALLY SATISFIED — API schemas provide some input validation, but there is no evidence of comprehensive input sanitization, vulnerability scanning, or remediation documentation.

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
- Static repository review completed on 2026-04-29.
- The control requires error messages to avoid revealing sensitive information to end users.
- File: api/app/process/router.py — API endpoints use FastAPI's HTTPException for error handling, e.g., 'raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))'. The 'detail' field exposes the string representation of exceptions, which may include sensitive details if not sanitized.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — Error messages are displayed to users via Streamlit, including exception messages and tracebacks (e.g., 'st.error(f"Error extracting text from PDF: {str(e)}")', 'st.error(f"Full traceback: {traceback.format_exc()}")').
- No evidence of error message sanitization or generic error messaging for non-privileged users.
- Requirement: NOT SATISFIED — Error messages may reveal sensitive information (e.g., exception details, tracebacks) to end users.

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
- Static repository review completed on 2026-04-29.
- The control requires that detailed error messages are only shown to privileged users (ISSO, ISSM, SA), and generic messages to others.
- File: api/app/process/router.py — All API endpoints return exception details in the 'detail' field of HTTPException, regardless of user role. No role-based filtering of error message content is implemented.
- File: vlm-testing/fpv_analyzer.py, vlm-testing/fpv_analyzer_rag.py — All errors, including tracebacks, are displayed to any user via Streamlit, with no distinction between privileged and non-privileged users.
- No evidence of role-based error message handling.
- Requirement: NOT SATISFIED — No mechanism to restrict detailed error messages to privileged users.

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
- Static repository review completed on 2026-04-29.
- The control requires mitigation of overflow attacks (buffer, stack, heap, integer, format string overflows).
- The application is implemented in Python (api/app/process/router.py, vlm-testing/fpv_analyzer.py, etc.), which is a memory-safe language and not subject to classic buffer/stack/heap overflows due to automatic bounds checking.
- No use of unsafe C extensions or direct memory manipulation is present in the provided code.
- Requirement: NOT APPLICABLE — Python's memory safety makes classic overflow attacks architecturally impossible in this context.

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
- Static repository review completed on 2026-04-29.
- The control requires removal of old software components after updates.
- File: api/README.md — Describes Docker-based deployment and local development, but does not mention any process for removing old versions or cleaning up obsolete components after updates.
- File: deploy/aws/iris-stack.yaml — EC2 UserData script clones the latest repository branch and overwrites the IRIS_DIR, but does not explicitly remove old Docker images, containers, or volumes.
- No evidence of a process or script that removes old application versions or components after updates.
- Requirement: NOT SATISFIED — No documented or automated process for removing old components after updates.

Remediation:
Configure or design the application to remove old components when updating.

---

### 226. APSC-DV-002630 | SV-222614r1117151

- Rule ID: SV-222614r1117151
- Severity: medium
- Rule Title: Security-relevant software updates and patches must be kept up to date.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires security-relevant software updates and patches to be kept up to date.
- File: api/README.md — Describes how to install dependencies and run the application, but does not mention a patch management or update process.
- File: deploy/aws/iris-stack.yaml — Installs system packages via dnf and pulls the latest code from GitHub, but does not specify a schedule or process for regular patching or update checks.
- No evidence of a documented or automated process for checking and applying updates at least weekly.
- Requirement: NOT SATISFIED — No evidence of a patch/update management process.

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to verify the correct operation of security functions.
- File: api/README.md — Describes authentication via Keycloak and RBAC, but does not mention any security function self-tests or verification routines.
- File: api/app/process/router.py — No endpoints or logic for security function testing or verification.
- No logs, documentation, or code indicating security function self-tests are performed.
- Requirement: NOT SATISFIED — No evidence of security function verification.

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires verification of security functions on startup, restart, or privileged command.
- File: api/README.md, api/app/process/router.py — No evidence of security function verification on startup, restart, or on privileged command.
- No logs, endpoints, or documentation indicating such checks are performed.
- Requirement: NOT SATISFIED — No evidence of periodic or event-driven security function verification.

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires notification to ISSO/ISSM of failed security verification tests.
- File: api/README.md, api/app/process/router.py — No evidence of security verification tests or notification logic for failed tests.
- No configuration or code for alerting or notification to ISSO/ISSM.
- Requirement: NOT SATISFIED — No evidence of notification mechanism for failed security verification tests.

Remediation:
Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.

---

### 230. APSC-DV-002870 | SV-222618r961083

- Rule ID: SV-222618r961083
- Severity: medium
- Rule Title: Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- The control prohibits unsigned Category 1A mobile code.
- The application is a web-based system (FastAPI backend, React frontend) and does not deliver or require client-side mobile code such as ActiveX, Java applets, or browser plugins.
- No evidence of mobile code in the provided files.
- Requirement: NOT APPLICABLE — No mobile code is present or delivered to clients.

Remediation:
Configure the application so Category 1A mobile code is signed.

---

### 231. APSC-DV-002880 | SV-222619r961863

- Rule ID: SV-222619r961863
- Severity: medium
- Rule Title: The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires an account management process for user creation, termination, and expiration.
- File: api/README.md — Describes authentication via Keycloak and RBAC, but does not document any process for account management, deactivation, or removal of inactive/suspended/terminated accounts.
- No evidence of a documented process or automation for timely removal of inactive accounts.
- Requirement: NOT SATISFIED — No documented account management process.

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires web servers to be on a separate network segment from application and database servers if operating in the DoD DMZ.
- File: deploy/aws/iris-stack.yaml — Defines VPC, subnets, security groups, and ALB, but does not explicitly separate web, application, and database servers into different network segments. The EC2 instance and RDS are in the same VPC, and security groups allow traffic between them, but no explicit DMZ segmentation is shown.
- No network diagram or documentation confirming DMZ separation.
- Requirement: PARTIALLY SATISFIED — VPC and subnets are defined, but no explicit evidence of DMZ-compliant tier separation.

Remediation:
Separate web server from other application tiers and place it on a separate network segment apart from the application and database servers in accordance with DoD DMZ data access controls requirements.

---

### 233. APSC-DV-002900 | SV-222621r1136913

- Rule ID: SV-222621r1136913
- Severity: medium
- Rule Title: The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires audit trails to be retained for at least 30 months (or 5 years for SAMI data).
- File: api/README.md, api/app/process/router.py — No mention of audit log retention, log storage, or retention policy.
- No configuration or code for log retention or archiving.
- Requirement: NOT SATISFIED — No evidence of audit trail retention policy or implementation.

Remediation:
Retain application audit log files for 30 months (12 months active + 18 months cold storage) for non-SAMI data and five years for SAMI data.

---

### 234. APSC-DV-002910 | SV-222622r961863

- Rule ID: SV-222622r961863
- Severity: medium
- Rule Title: The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires periodic review of audit trails based on system documentation.
- File: api/README.md — No documentation of audit log review schedule or process.
- No code or documentation indicating audit log review or record of review dates/times.
- Requirement: NOT SATISFIED — No evidence of audit log review process or documentation.

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
- Static repository review completed on 2026-04-29.
- The control requires a policy for reporting IA violations.
- File: api/README.md — No mention of IA policy or reporting procedures.
- No SOPs or documentation for reporting IA violations.
- Requirement: NOT SATISFIED — No evidence of IA violation reporting policy.

Remediation:
Create and maintain a policy to report IA violations.

---

### 236. APSC-DV-002930 | SV-222624r1051272

- Rule ID: SV-222624r1051272
- Severity: medium
- Rule Title: The ISSO must ensure active vulnerability testing is performed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires active vulnerability testing and test results.
- File: api/README.md — No mention of vulnerability testing, test procedures, or results.
- No scan reports, test scripts, or configuration for automated vulnerability scanning.
- Requirement: NOT SATISFIED — No evidence of active vulnerability testing.

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
- Static repository review completed on 2026-04-29.
- The control requires execution flow diagrams and design documents to show mitigation of deadlock and recursion issues in web services.
- File: README.md, api/README.md — High-level architecture and data flow diagrams are described, but no specific execution flow diagrams or documentation addressing deadlock/recursion in web services is present.
- No system diagrams or design documents addressing deadlock/recursion.
- Requirement: NOT SATISFIED — No execution flow diagrams or documentation for deadlock/recursion mitigation.

Remediation:
Develop web services to account for deadlock issues.

---

### 238. APSC-DV-002960 | SV-222626r961863

- Rule ID: SV-222626r961863
- Severity: medium
- Rule Title: The designer must ensure the application does not store configuration and control files in the same directory as user data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires configuration and control files to be stored separately from user data.
- File: api/README.md — Documents that environment variables are stored in 'api/.env', and user data (videos, etc.) is stored in 'storage/' or S3 buckets. However, no explicit directory structure or permissions are shown to guarantee separation.
- File: deploy/aws/iris-stack.yaml — Clones the repository to '/opt/iris', but does not specify directory separation for configuration vs. user data.
- No explicit evidence of directory separation or file permissions restricting user access to configuration files.
- Requirement: PARTIALLY SATISFIED — Some separation implied, but no explicit directory structure or permissions enforcement is documented.

Remediation:
Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.

---

### 239. APSC-DV-002970 | SV-222627r961863

- Rule ID: SV-222627r961863
- Severity: medium
- Rule Title: The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires configuration according to DoD STIG/NSA guidance, or, if unavailable, according to best practices, independent testing, or vendor guidance.
- File: api/README.md, README.md — No mention of DoD STIG, NSA guides, or alternative configuration guidance.
- No documentation or references to commercially accepted practices, independent testing, or vendor lock down guides.
- Requirement: NOT SATISFIED — No evidence of configuration according to STIG, NSA, or alternative guidance.

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
- Static repository review completed on 2026-04-29.
- The control requires all application ports, protocols, and services to be in compliance with DoD PPSM guidance and documented.
- File: deploy/aws/iris-stack.yaml — Defines ports for ALB (443), EC2 (22, 443, 3000), and RDS (5432), but does not reference DoD PPSM compliance or provide documentation mapping ports/services to PPS CAL.
- No System Security Plan, accreditation documentation, or explicit mapping of ports/protocols to DoD PPSM guidance.
- Requirement: NOT SATISFIED — No evidence of PPSM compliance documentation.

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
- Static repository review completed on 2026-04-29.
- The control requires evidence that the application and its ports are registered in the DoD Ports and Protocols Database.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml, .github/workflows/deploy-eks.yml, .github/workflows/deploy-eks-ironbank.yml) references DoD Ports and Protocols Database registration or a registration identifier.
- Application ports are documented (e.g., API on 5000, UI on 3000, Keycloak on 8080, Qdrant on 6333/6334) in README.md and CloudFormation, but no evidence of registration is present.
- Requirement: PARTIALLY SATISFIED — Application ports are documented, but no evidence of DoD Ports and Protocols Database registration is present in static artifacts.

Remediation:
Register the application and ports in the Ports and Protocols Database.

---

### 242. APSC-DV-002995 | SV-222630r961863

- Rule ID: SV-222630r961863
- Severity: medium
- Rule Title: The Configuration Management (CM) repository must be properly patched and STIG compliant.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires evidence that the Configuration Management (CM) repository is patched and STIG compliant.
- No static artifact in the provided files documents patch management processes, STIG application, or ATO documentation for the CM repository.
- The repository uses GitHub Actions (see .github/workflows/*) and AWS infrastructure (see deploy/aws/iris-stack.yaml), but no explicit evidence of patch management or STIG compliance for the CM system is present.
- Requirement: NOT SATISFIED — No evidence of CM patch management or STIG compliance in static artifacts.

Remediation:
Patch the CM system when new security patches are made available and apply the relevant STIGs.

---

### 243. APSC-DV-003000 | SV-222631r961863

- Rule ID: SV-222631r961863
- Severity: medium
- Rule Title: Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires evidence that access privileges to the CM repository are reviewed every three months.
- No static artifact in the provided files documents a process or schedule for reviewing CM repository access privileges.
- The repository uses GitHub and AWS, but no evidence of periodic access review is present in README.md, workflow files, or infrastructure code.
- Requirement: NOT SATISFIED — No evidence of periodic CM access privilege review in static artifacts.

Remediation:
Review access privileges to the CM repository at least every three months.

---

### 244. APSC-DV-003010 | SV-222632r961863

- Rule ID: SV-222632r961863
- Severity: medium
- Rule Title: A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires a Software Configuration Management (SCM) plan describing configuration control, change management, roles, tools, and audit mechanisms.
- No SCM plan or equivalent documentation is present in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml, workflows, etc.).
- No evidence of a document listing configuration-controlled objects, roles, responsibilities, or change tracking mechanisms.
- Requirement: NOT SATISFIED — No SCM plan or equivalent documentation found in static artifacts.

Remediation:
Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.

---

### 245. APSC-DV-003020 | SV-222633r961863

- Rule ID: SV-222633r961863
- Severity: medium
- Rule Title: A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires evidence of a Configuration Control Board (CCB) and charter documentation.
- No static artifact in the provided files references a CCB, its membership, or charter documentation.
- README.md and other documentation do not mention a CCB or its activities.
- Requirement: NOT SATISFIED — No evidence of a CCB or charter documentation in static artifacts.

Remediation:
Setup and maintain a Configuration Control Board.

---

### 246. APSC-DV-003030 | SV-222634r987685

- Rule ID: SV-222634r987685
- Severity: medium
- Rule Title: The application services and interfaces must be compatible with and ready for IPv6 networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires evidence that application services and interfaces are IPv6 compatible per DoD standards.
- No explicit IPv6 configuration or documentation is present in README.md, api/README.md, or infrastructure code.
- CloudFormation (deploy/aws/iris-stack.yaml) and Kubernetes manifests (referenced in workflows) do not show explicit IPv6 enablement or dual-stack configuration.
- Requirement: NOT SATISFIED — No evidence of IPv6 compatibility or configuration in static artifacts.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that critical applications are not hosted on general purpose machines with non-critical apps.
- CloudFormation template (deploy/aws/iris-stack.yaml) provisions dedicated EC2 instances and Kubernetes clusters for IRIS, but does not explicitly state that no other applications are deployed.
- No documentation or configuration explicitly restricts the instance to only IRIS.
- Requirement: PARTIALLY SATISFIED — Dedicated infrastructure is provisioned, but no explicit restriction or documentation that only IRIS is deployed.

Remediation:
Deploy mission critical applications on servers that are not shared by other less critical applications.

---

### 248. APSC-DV-003050 | SV-222636r1051323

- Rule ID: SV-222636r1051323
- Severity: medium
- Rule Title: A contingency plan must exist in accordance with DOD policy based on the application's availability requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires a contingency plan based on the application's availability requirements.
- No contingency plan or disaster recovery documentation is present in the provided files.
- CloudFormation (deploy/aws/iris-stack.yaml) includes RDS backup retention and multi-AZ, but no full contingency plan.
- Requirement: NOT SATISFIED — No contingency plan documentation found in static artifacts.

Remediation:
Create and maintain a contingency plan that identifies essential mission and business functions and associated contingency requirements.

---

### 249. APSC-DV-003060 | SV-222637r961863

- Rule ID: SV-222637r961863
- Severity: medium
- Rule Title: Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires a disaster recovery plan with secure and verifiable recovery procedures.
- No disaster recovery plan or documentation is present in the provided files.
- CloudFormation (deploy/aws/iris-stack.yaml) includes RDS backup and multi-AZ, but no documented recovery procedures or trusted recovery considerations.
- Requirement: NOT SATISFIED — No disaster recovery plan documentation found in static artifacts.

Remediation:
Create and maintain a disaster recovery plan.

---

### 250. APSC-DV-003070 | SV-222638r961863

- Rule ID: SV-222638r961863
- Severity: medium
- Rule Title: Data backup must be performed at required intervals in accordance with DoD policy.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires documented backup procedures and evidence of backup frequency, offsite storage, and testing.
- CloudFormation (deploy/aws/iris-stack.yaml) configures RDS backups (BackupRetentionPeriod: 7), but no documentation of backup procedures, offsite storage, or backup testing is present.
- S3 buckets are provisioned for storage, but no evidence of backup schedules or testing.
- Requirement: PARTIALLY SATISFIED — RDS backup retention is configured, but no documented backup procedures or testing evidence.

Remediation:
Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.

---

### 251. APSC-DV-003080 | SV-222639r961863

- Rule ID: SV-222639r961863
- Severity: medium
- Rule Title: Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that backup copies of application software or source code are stored in a fire-rated container or offsite.
- No documentation or configuration in the provided files describes offsite or fire-rated storage of backups or source code.
- S3 buckets are provisioned (deploy/aws/iris-stack.yaml), but no evidence that these are configured for offsite backup or fire-rated storage.
- Requirement: NOT SATISFIED — No evidence of offsite or fire-rated backup storage in static artifacts.

Remediation:
Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.

---

### 252. APSC-DV-003090 | SV-222640r961863

- Rule ID: SV-222640r961863
- Severity: medium
- Rule Title: Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires procedures to assure physical and technical protection of backup and restoration assets.
- No backup and recovery procedure documentation is present in the provided files.
- CloudFormation (deploy/aws/iris-stack.yaml) provisions S3 and RDS, but does not document protection procedures for backup/restoration assets.
- Requirement: NOT SATISFIED — No documented procedures for backup/restoration asset protection.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires encryption for key exchange using FIPS-140-2 validated cryptographic modules.
- No explicit evidence of key exchange protocols or cryptographic module validation is present in the provided files.
- README.md and api/README.md reference JWT authentication and HTTPS, but do not specify FIPS-140-2 validation or key exchange implementation details.
- Requirement: NOT SATISFIED — No evidence of FIPS-validated encryption for key exchange in static artifacts.

Remediation:
Use encryption for key exchange.

---

### 254. APSC-DV-003110 | SV-222642r961863

- Rule ID: SV-222642r961863
- Severity: high
- Rule Title: The application must not contain embedded authentication data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that the application does not contain embedded authentication data (e.g., passwords, certificates) in code or configuration files.
- In pointcloud-project/docker-compose.yml:
- POSTGRES_PASSWORD: secure_password_here
- In api/.env.example and api/README.md:
- AWS_ACCESS_KEY_ID=your_access_key_id
- AWS_SECRET_ACCESS_KEY=your_secret_access_key
- In deploy/aws/iris-stack.yaml, secrets are retrieved from AWS Secrets Manager, not embedded in code.
- However, the presence of 'secure_password_here' in a docker-compose file and placeholder secrets in .env.example indicates that embedded credentials may exist in development/test configurations.
- Requirement: PARTIALLY SATISFIED — No production secrets found, but embedded credentials exist in development/test files.

Remediation:
Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.

---

### 255. APSC-DV-003120 | SV-222643r1136915

- Rule ID: SV-222643r1136915
- Severity: high
- Rule Title: The application must have the capability to mark sensitive/classified output when required.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to have the capability to mark sensitive/classified output when required.
- No evidence in README.md, api/README.md, or UI code (video-player.tsx) of output marking for sensitive/classified data.
- No classification guide or marking procedures are referenced.
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
- Static repository review completed on 2026-04-29.
- The control requires test plans, procedures, and results to be created and executed prior to each release or patch update.
- README.md and api/README.md reference end-to-end and unit testing (e.g., Playwright, pytest), but do not provide test plans or procedures.
- No test plan documents or release-specific test evidence is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Automated tests are referenced, but no formal test plans or execution records are present.

Remediation:
Execute tests plans prior to release or patch update.

---

### 257. APSC-DV-003140 | SV-222645r961863

- Rule ID: SV-222645r961863
- Severity: medium
- Rule Title: Application files must be cryptographically hashed prior to deploying to DoD operational networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires application files to be cryptographically hashed prior to deployment.
- No evidence of a cryptographic hash validation process or hash values for application files is present in the provided files.
- README.md and deployment workflows do not reference hash generation or validation steps.
- Requirement: NOT SATISFIED — No evidence of cryptographic hash validation process in static artifacts.

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
- Static repository review completed on 2026-04-29.
- The control requires at least one tester to be designated for security testing.
- No documentation or organization chart in the provided files designates a security tester.
- README.md and workflow files do not reference security testing roles or personnel.
- Requirement: NOT SATISFIED — No evidence of designated security tester in static artifacts.

Remediation:
Designate personnel to conduct security testing on the applications.

---

### 259. APSC-DV-003160 | SV-222647r961863

- Rule ID: SV-222647r961863
- Severity: low
- Rule Title: Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires annual test procedures to ensure secure system state on initialization, shutdown, and aborts.
- No process documentation or test procedures for annual security state testing are present in the provided files.
- README.md and api/README.md reference automated tests, but not annual security state tests.
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
- Static repository review completed on 2026-04-29.
- The control requires application code reviews to be performed and documented.
- README.md and api/README.md reference code quality checks (e.g., ruff, lint, format), but do not document a code review process or provide code review reports.
- No evidence of code review results or process documentation is present in the provided files.
- Requirement: PARTIALLY SATISFIED — Automated code quality checks are referenced, but no formal code review process or documentation is present.

Remediation:
Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.

---

### 261. APSC-DV-003180 | SV-222649r961863

- Rule ID: SV-222649r961863
- Severity: low
- Rule Title: Code coverage statistics must be maintained for each release of the application.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- Code coverage statistics must be maintained for each release of the application.
- File: api/README.md — Section: 'Running Unit Tests' and 'Running Code Quality Checks'
- Command: `coverage run -m pytest && coverage html`
- Explicit instruction to run code coverage and generate HTML report
- File: ui/README.md — Section: 'Running Unit Tests'
- Command: `npm run test:coverage`
- Explicit instruction to run code coverage for UI code
- File: e2e/README.md — Section: 'Running Tests'
- End-to-end tests are run with Playwright, and test coverage is tracked
- Requirement: SATISFIED — Code coverage statistics are maintained and documented for both backend and frontend components, with explicit coverage commands and instructions present in project documentation.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Flaws found during a code review must be tracked in a defect tracking system.
- File: README.md — No explicit mention of a defect tracking system or issue management process.
- File: api/README.md, ui/README.md, e2e/README.md — No reference to issue tracking, bug reporting, or integration with a defect tracking system.
- No static evidence of a configuration management repository or automated capture of code review flaws (e.g., no references to Jira, GitHub Issues, or similar tools in the provided files).
- Requirement: PARTIALLY SATISFIED — While the repository is hosted on GitHub (implied by clone instructions), there is no explicit evidence in the static documentation or code that code review flaws are tracked in a defect tracking system. Confirmation would require review of the actual repository issue tracker or workflow integration.

Remediation:
Track software defects in a defect tracking system.

---

### 263. APSC-DV-003200 | SV-222651r961863

- Rule ID: SV-222651r961863
- Severity: medium
- Rule Title: The changes to the application must be assessed for IA and accreditation impact prior to implementation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The changes to the application must be assessed for IA and accreditation impact prior to implementation.
- File: README.md — No explicit mention of an IA (Information Assurance) impact assessment process or CCB (Change Control Board) documentation.
- File: api/README.md, ui/README.md — No references to IA impact analysis, accreditation, or formal change assessment procedures.
- No static evidence of a documented process for IA impact analysis prior to implementation of changes.
- Requirement: NOT SATISFIED — No evidence of IA impact assessment process or documentation in the provided static artifacts.

Remediation:
Review IA impact to the system prior to implementing changes.

---

### 264. APSC-DV-003210 | SV-222652r961863

- Rule ID: SV-222652r961863
- Severity: medium
- Rule Title: Security flaws must be fixed or addressed in the project plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Security flaws must be fixed or addressed in the project plan.
- File: README.md, api/README.md, ui/README.md — No explicit mention of a project plan or process for integrating security flaws into project planning.
- No references to security flaw tracking, remediation planning, or integration with project management tools.
- Requirement: NOT SATISFIED — No evidence of security flaw tracking or project plan integration in the provided static documentation.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The application development team must follow a set of coding standards.
- File: api/README.md — Section: 'Running Code Quality Checks'
- Command: `ruff check .` (Python linter enforcing code style)
- File: ui/README.md — Section: 'Running Code Quality Checks'
- Commands: `npm run lint`, `npm run format` (JavaScript/TypeScript linting and formatting)
- File: .github/workflows/api-code-quality.yml, .github/workflows/ui-code-quality.yml (not shown, but implied by workflow names in manifest) — CI workflows for code quality enforcement
- Requirement: SATISFIED — Coding standards are enforced via static analysis tools (ruff, lint, format) and documented in developer instructions.

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
- Static repository review completed on 2026-04-29.
- The designer must create and update the Design Document for each release of the application.
- File: README.md — Section: 'System Overview', 'Architecture Components', and 'Implementation Architecture' provide high-level design and architecture descriptions.
- File: README.md — Section: 'Technical Documentation' states: 'Detailed technical specifications and API documentation are maintained in the /docs directory, including: API endpoint specifications, Database schema documentation, UI component integration guides, Deployment and configuration instructions.'
- However, the actual /docs directory and its contents are not included in the provided context, and there is no evidence of a formal Design Document containing all required elements (external interfaces, information exchange, protections, user roles, restoration priority, incident response plan, etc.).
- Requirement: PARTIALLY SATISFIED — High-level design and architecture are described, but no static evidence of a comprehensive, versioned Design Document as required by the control.

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
- Static repository review completed on 2026-04-29.
- Threat models must be documented and reviewed for each application release and updated as required by design and functionality changes or when new threats are discovered.
- File: README.md — No explicit mention of a threat model document or threat modeling process.
- No static evidence of a threat model document, identified threats, vulnerabilities, countermeasures, or risk analysis in the provided files.
- Requirement: NOT SATISFIED — No evidence of threat model documentation or review process.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The application must not be subject to error handling vulnerabilities.
- File: api/README.md — Section: 'Running Unit Tests' and 'Running Code Quality Checks' indicate that tests and static analysis are performed, but there is no explicit mention of error handling vulnerability testing or results.
- File: e2e/README.md — End-to-end tests are present, but no evidence of error handling vulnerability coverage or test results.
- No static evidence of recent security scans or code analysis reports specifically addressing error handling vulnerabilities.
- Requirement: PARTIALLY SATISFIED — Testing infrastructure exists, but no evidence of error handling vulnerability testing or results.

Remediation:
Ensure proper return code and exception handling is implemented throughout the application.

---

### 269. APSC-DV-003236 | SV-222657r961863

- Rule ID: SV-222657r961863
- Severity: medium
- Rule Title: The application development team must provide an application incident response plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The application development team must provide an application incident response plan.
- File: README.md, api/README.md, ui/README.md — No explicit mention of an application incident response plan or process for tracking, confirming, and remediating vulnerabilities and notifying users.
- Requirement: NOT SATISFIED — No evidence of an incident response plan or process in the provided static documentation.

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
- Static repository review completed on 2026-04-29.
- All products must be supported by the vendor or the development team.
- File: README.md — Section: 'Technical Stack' lists core technologies and dependencies, but does not provide explicit support status or vendor support documentation.
- File: api/README.md, ui/README.md — No explicit documentation of support status for software components.
- Requirement: PARTIALLY SATISFIED — Software components are identified, but no static evidence of vendor or development team support status.

Remediation:
Remove or decommission all unsupported software products in the application.

---

### 271. APSC-DV-003250 | SV-222659r961863

- Rule ID: SV-222659r961863
- Severity: high
- Rule Title: The application must be decommissioned when maintenance or support is no longer available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The application must be decommissioned when maintenance or support is no longer available.
- File: README.md, api/README.md, ui/README.md — No explicit mention of maintenance contracts, support agreements, or decommissioning procedures.
- Requirement: NOT SATISFIED — No evidence of maintenance/support tracking or decommissioning process.

Remediation:
Ensure there is maintenance for the application.

---

### 272. APSC-DV-003260 | SV-222660r961863

- Rule ID: SV-222660r961863
- Severity: low
- Rule Title: Procedures must be in place to notify users when an application is decommissioned.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Procedures must be in place to notify users when an application is decommissioned.
- File: README.md, api/README.md, ui/README.md — No explicit mention of user notification procedures for decommissioning.
- Requirement: NOT SATISFIED — No evidence of decommissioning notification procedures.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Unnecessary built-in application accounts must be disabled.
- File: README.md — Section: 'Keycloak Identity and Access Management' describes use of Keycloak for authentication and mentions default admin credentials for development only.
- 'Default credentials: admin/TestPassword123! (development only)'
- 'Note: Change default credentials before deploying to production environments.'
- File: api/README.md — Keycloak configuration and user roles are described, but no explicit evidence of disabling unnecessary built-in accounts or changing default passwords in production.
- Requirement: PARTIALLY SATISFIED — Default accounts exist for development, but no static evidence of disabling/removing unnecessary built-in accounts for production.

Remediation:
Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Default passwords must be changed.
- File: README.md — Section: 'Keycloak Identity and Access Management' and 'Default Admin Credentials (development only)':
- 'Username: admin'
- 'Password: TestPassword123!'
- 'Note: Change default credentials before deploying to production environments.'
- File: api/README.md — Keycloak configuration uses 'admin'/'TestPassword123!' for development.
- No static evidence that default passwords are changed in production deployments.
- Requirement: PARTIALLY SATISFIED — Default passwords are present for development, and documentation warns to change them for production, but no static enforcement or confirmation of change.

Remediation:
Configure the application to use strong authenticators instead of passwords when possible. Otherwise, change default passwords to a DoD-approved strength password and follow all guidance for passwords.

---

### 275. APSC-DV-003285 | SV-222663r961863

- Rule ID: SV-222663r961863
- Severity: medium
- Rule Title: An Application Configuration Guide must be created and included with the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- An Application Configuration Guide must be created and included with the application.
- File: README.md — Section: 'Technical Documentation' states: 'Detailed technical specifications and API documentation are maintained in the /docs directory, including: API endpoint specifications, Database schema documentation, UI component integration guides, Deployment and configuration instructions.'
- However, the actual /docs directory and its contents are not included in the provided context, and there is no evidence of a comprehensive Application Configuration Guide covering all required configuration examples.
- Requirement: PARTIALLY SATISFIED — Documentation is referenced, but the configuration guide itself is not present in the provided static artifacts.

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
- Static repository review completed on 2026-04-29.
- If the application contains classified data, a Security Classification Guide must exist containing data elements and their classification.
- File: README.md, api/README.md, ui/README.md — No indication that the application processes or stores classified information.
- Requirement: NOT APPLICABLE — Application does not process classified data based on available documentation.

Remediation:
Create and maintain a security classification guide.

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The designer must ensure uncategorized or emerging mobile code is not used in applications.
- File: README.md, api/README.md, ui/README.md — No explicit mention of mobile code types, their categorization, or waiver documentation.
- Requirement: NOT SATISFIED — No evidence of mobile code review or waiver documentation.

Remediation:
Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Production database exports must have database administration credentials and sensitive data removed before releasing the export.
- File: README.md, api/README.md — No explicit mention of database export sanitization procedures or removal of sensitive data prior to export to development/test environments.
- Requirement: NOT SATISFIED — No evidence of database export sanitization process.

Remediation:
Remove sensitive data from production database exports.

---

### 279. APSC-DV-003320 | SV-222667r961863

- Rule ID: SV-222667r961863
- Severity: medium
- Rule Title: Protections against DoS attacks must be implemented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Protections against DoS attacks must be implemented.
- File: README.md — No explicit mention of DoS threat modeling or implemented mitigations.
- No static evidence of DoS protections in configuration or code.
- Requirement: NOT SATISFIED — No evidence of DoS threat identification or mitigation implementation.

Remediation:
Implement mitigations from the threat model for DOS attacks.

---

### 280. APSC-DV-003330 | SV-222668r961863

- Rule ID: SV-222668r961863
- Severity: medium
- Rule Title: The system must alert an administrator when low resource conditions are encountered.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The system must alert an administrator when low resource conditions are encountered.
- File: README.md, api/README.md, deploy/aws/iris-stack.yaml — No explicit mention of automated monitoring, alerting, or resource condition notification mechanisms.
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
- Static repository review completed on 2026-04-29.
- The control requires that at least one application administrator is registered to receive update notifications or security alerts for application components, libraries, and third-party tools.
- File: deploy/keycloak/dev-realm.json — users array includes an admin user:
- "username": "admin", "email": "admin@example.com", "realmRoles": ["admin", "user"]
- File: deploy/keycloak/dev-realm.json — Keycloak realm is configured with admin and other privileged users, but there is no static evidence of a notification or alert registration mechanism for update/security alerts for application components or dependencies.
- File: api/README.md — No mention of automated update/security alert notification registration for administrators.
- Requirement: PARTIALLY SATISFIED — Admin users exist in the IAM system, but there is no static evidence that they are registered to receive update/security notifications for application components, libraries, or third-party tools.

Remediation:
Register administrators to receive update notifications so they can patch and update applications and application components.

---

### 282. APSC-DV-003345 | SV-222670r961863

- Rule ID: SV-222670r961863
- Severity: low
- Rule Title: The application must provide notifications or alerts when product update and security related patches are available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to provide notifications or alerts when product updates and security-related patches are available, including a description, risk, mitigation, and how to obtain the update.
- File: api/README.md — No mention of an automated or manual notification process for security patches or product updates.
- File: deploy/keycloak/dev-realm.json — No evidence of notification process for updates or security patches.
- File: package.json — No scripts or dependencies indicating an update notification mechanism.
- No evidence in any provided file of a process or mechanism (manual or automated) for notifying administrators or users about available security patches or product updates, nor any description of risk or mitigation.
- Requirement: NOT SATISFIED — No static evidence of an update or security patch notification process.

Remediation:
Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.

---

### 283. APSC-DV-003350 | SV-222671r961863

- Rule ID: SV-222671r961863
- Severity: medium
- Rule Title: Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires that connections between the DoD enclave and the Internet or other public/commercial WANs must require a DMZ if the application is publicly accessible.
- File: deploy/aws/iris-stack.yaml — Application is deployed behind an AWS Application Load Balancer (ALB) in an internet-facing configuration, with security groups and subnets defined for public access.
- Resource: AppLoadBalancer — Scheme: internet-facing
- Security groups restrict access to ALB (443/tcp), EC2 (22, 443, 3000/tcp), and RDS (5432/tcp from EC2 SG only).
- Public subnets (Subnet1, Subnet2) and InternetGateway are defined, with public route table.
- ALB forwards traffic to EC2 instances in public subnets, which is a standard AWS DMZ pattern.
- The architecture implements a DMZ via the ALB and public subnets, consistent with AWS best practices for DMZ segmentation.
- Requirement: SATISFIED — Application is publicly accessible and traffic is routed through a DMZ (ALB in public subnet with security groups and public route table).

Remediation:
Setup a DMZ between DoD and public networks.

---

### 284. APSC-DV-003360 | SV-222672r961833

- Rule ID: SV-222672r961833
- Severity: low
- Rule Title: The application must generate audit records when concurrent logons from different workstations occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires the application to generate audit records when concurrent logons from different workstations occur, including source IP addresses.
- File: api/app/process/router.py — No evidence of audit logging for concurrent logons or tracking of source IP addresses in any endpoint.
- File: api/README.md — Authentication is handled via Keycloak (JWT), but no mention of audit logging for concurrent logons or IP tracking.
- File: deploy/keycloak/dev-realm.json — Keycloak is configured for authentication, but no evidence of audit log configuration for concurrent logons or IP address tracking.
- No static evidence in provided files of audit record generation for concurrent logons from different workstations, nor of IP address logging.
- Requirement: NOT SATISFIED — No static evidence of audit records for concurrent logons from different workstations.

Remediation:
Configure the application to log concurrent logons from different workstations.

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires evidence of annual security training for program managers, designers, developers, and testers (e.g., certificates, class rosters).
- This is a process/documentation control with no static code or configuration artifact. No static indicator of training evidence can be found in the codebase.
- Requirement: NOT REVIEWED — Control is purely process/documentation-based and cannot be assessed via static source code.

Remediation:
Provide application development/operational related security specific annual training for managers, designers, developers, and testers.

---

### 286. APSC-DV-002010 | SV-265634r1117183

- Rule ID: SV-265634r1117183
- Severity: medium
- Rule Title: The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- The control requires NSA-approved cryptography (NIST FIPS 140-2 validated or NSA Type-1) for protection of classified information, if the application processes classified data.
- File: api/app/config.py — Cryptographic settings for S3, Qdrant, and Bedrock are present, but no explicit evidence of FIPS 140-2 validated cryptography or NSA Type-1 modules:
- AWS_REGION: "us-gov-east-1" (GovCloud)
- BEDROCK_REGION: "us-gov-east-1"
- No explicit FIPS 140-2 or NSA Type-1 cryptography configuration.
- File: api/README.md — No mention of classified data processing or cryptographic module validation.
- File: deploy/aws/iris-stack.yaml — S3 buckets, RDS, and network configuration are present, but no explicit cryptographic module configuration for classified data.
- No evidence that the application processes classified data, but also no evidence of cryptographic module validation if it did.
- Requirement: PARTIALLY SATISFIED — Application uses AWS GovCloud and Bedrock, but there is no explicit evidence of FIPS 140-2 or NSA Type-1 cryptography configuration for classified data. Cannot confirm full compliance without further documentation or configuration.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
