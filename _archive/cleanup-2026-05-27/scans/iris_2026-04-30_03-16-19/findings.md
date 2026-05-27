# iris STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 211 |
| Not a Finding | 27 |
| Not Applicable | 48 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: The application must provide a capability to limit the number of logon sessions per user.
- File: deploy/keycloak/dev-realm.json — No explicit session-per-user limit is set. Keycloak realm settings include:
- "ssoSessionIdleTimeout": 28800
- "ssoSessionMaxLifespan": 32400
- "bruteForceProtected": true
- No "maxSessionsPerUser" or equivalent found in realm or client configuration.
- File: api/README.md — No mention of session-per-user limits in API authentication or RBAC documentation.
- File: ui/src/components/video-player/video-player.tsx — No evidence of session count enforcement in UI logic.
- Requirement: PARTIALLY SATISFIED — Session timeouts and brute force protection are present, but there is no static evidence of a per-user concurrent session limit. Keycloak supports this feature via the "Login" tab ("Maximum Sessions"), but it is not set in the provided realm config. Additional configuration or documentation is required to confirm compliance.

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
- Control requires: The application must clear temporary storage and cookies when the session is terminated, and must not store authentication information (username/password) in cookies or local storage.
- File: ui/src/components/video-player/video-player.tsx — No direct evidence of cookie or local storage management for authentication/session data.
- File: api/README.md — API uses JWT-based authentication via Keycloak; no mention of storing credentials in cookies or local storage.
- File: deploy/keycloak/dev-realm.json — Keycloak is configured for SSO, but no static evidence of cookie clearing on logout.
- File: ui/vitest.setup.ts — Mocks authentication for tests, but does not indicate production storage behavior.
- Requirement: PARTIALLY SATISFIED — There is no evidence that usernames or passwords are stored in cookies or local storage, but there is also no static evidence that cookies or storage are cleared on logout. The application's logout and session termination flows need to be reviewed in runtime or in additional code/configuration to confirm compliance.

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
- File: api/README.md — No evidence of application-level idle timeout enforcement for non-privileged users.
- File: ui/src/components/video-player/video-player.tsx — No evidence of client-side idle timeout enforcement.
- Requirement: NOT SATISFIED — The configured idle timeout (8 hours) is much longer than the required 15 minutes. No evidence of compensating controls.

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
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800 (8 hours), applies to all users including admin; no separate admin timeout is configured.
- File: api/README.md — No evidence of admin-specific idle timeout enforcement.
- Requirement: NOT SATISFIED — No static evidence of a 10 minute idle timeout for admin users. The configured timeout is 8 hours for all users.

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
- Control requires: Applications requiring user access authentication must provide a logoff capability for user-initiated session termination.
- File: deploy/keycloak/dev-realm.json — Keycloak provides OpenID Connect SSO with logout endpoints.
- File: api/README.md — API uses JWT-based authentication via Keycloak; Keycloak provides logout endpoints.
- File: ui/src/components/video-player/video-player.tsx — UI integrates with Keycloak for authentication; logout is handled via SSO provider.
- File: ui/README.md (not shown, but referenced in main README) — UI is configured for Keycloak SSO, which provides a logout function.
- Requirement: SATISFIED — The application uses Keycloak for authentication, which provides a user-initiated logoff capability via SSO logout endpoints.

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
- File: ui/src/components/video-player/video-player.tsx — No evidence of an explicit logoff message being displayed to users after logout.
- File: api/README.md — No mention of explicit logoff messaging in API or UI documentation.
- File: deploy/keycloak/dev-realm.json — Keycloak provides logout endpoints, but no evidence of a custom logoff message being configured or displayed in the UI.
- Requirement: NOT SATISFIED — No static evidence of an explicit logoff message to users upon session termination.

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
- File: api/app/process/router.py — No evidence of data marking or security attribute assignment in storage-related endpoints.
- File: pointcloud-project/colmap_ingest.py — Database schema for point cloud data includes metadata fields, but no fields for security attributes or data markings.
- File: vlm-testing/fpv_analyzer_rag.py — Document metadata includes fields like 'source_type', but no evidence of classification or marking attributes.
- Requirement: NOT SATISFIED — No static evidence of data marking or security attribute association with stored information.

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
- Control requires: The application must associate organization-defined security attributes with information in process (e.g., retain data marking during processing).
- File: api/app/process/router.py — No evidence of security attribute propagation or enforcement during processing endpoints.
- File: api/app/process/services/scene_summarization.py — Scene and summary processing does not include security attribute handling.
- File: pointcloud-project/colmap_ingest.py — Processing logic does not reference security attributes.
- Requirement: NOT SATISFIED — No static evidence of security attribute association or retention during data processing.

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
- Control requires: The application must associate organization-defined security attributes with information in transmission (e.g., retain data marking during transmission).
- File: api/app/process/router.py — No evidence of security attribute transmission or enforcement in API endpoints.
- File: api/README.md — No mention of data marking or attribute propagation in API documentation.
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
- Control requires: The application must implement DoD-approved encryption (TLS) to protect the confidentiality of remote access sessions.
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is configured for HTTPS (port 443) with ACM certificate:
- AppLoadBalancer: Protocol: HTTPS, Certificates: AcmCertificateArn
- AppTargetGroup: Protocol: HTTPS
- File: api/README.md — API is accessible via HTTP (http://localhost:5000), but in production, traffic is expected to be routed through the ALB.
- File: ui/README.md (referenced) — UI is served via Nginx, but no explicit TLS configuration is shown in the provided files.
- Requirement: PARTIALLY SATISFIED — The infrastructure (ALB) is configured for TLS, but there is no static evidence of end-to-end TLS enforcement for all application components (e.g., between ALB and backend, or for internal API/UI communication).

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
- Control requires: The application must implement cryptographic mechanisms (TLS) to protect the integrity of remote access sessions.
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is configured for HTTPS (TLS) on port 443 with ACM certificate.
- File: api/README.md — API is accessible via HTTP (http://localhost:5000) in development; production routing is via ALB.
- File: ui/README.md (referenced) — No explicit evidence of TLS enforcement for UI-to-API or internal service communication.
- Requirement: PARTIALLY SATISFIED — TLS is enforced at the ALB, but there is no static evidence of TLS enforcement for all internal communications. Additional configuration or documentation is required to confirm full end-to-end integrity protection.

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
- Control requires: SOAP messages requiring integrity must include Message ID, Service Request, Timestamp, SAML Assertion, and all elements must be digitally signed.
- File: api/README.md — No evidence of SOAP message usage; API is RESTful (FastAPI, OpenAPI/Swagger docs).
- File: deploy/keycloak/dev-realm.json — SAML assertions are not referenced; authentication is via OpenID Connect/JWT.
- Requirement: NOT APPLICABLE — The application does not utilize SOAP messages.

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
- Control requires: Messages protected with WS-Security must use time stamps with creation and expiration times.
- File: api/README.md — No evidence of WS-Security token usage; API uses JWT via OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No evidence of WS-Security tokens.
- Requirement: NOT APPLICABLE — The application does not utilize WS-Security tokens.

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
- File: api/README.md — No evidence of WS-Security or SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize WS-Security or SAML assertions.

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
- Control requires: Each unique asserting party must provide unique assertion ID references for each SAML assertion.
- File: api/README.md — No evidence of SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize SAML assertions.

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
- File: api/README.md — No evidence of WS-Security token or SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize WS-Security tokens or SAML assertions.

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
- File: api/README.md — No evidence of SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize SAML assertions.

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
- File: api/README.md — No evidence of SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize SAML assertions.

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
- File: api/README.md — No evidence of SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize SAML assertions.

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
- Control requires: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data in SAML assertions.
- File: api/README.md — No evidence of SAML assertion usage; authentication is via JWT/OpenID Connect.
- File: deploy/keycloak/dev-realm.json — No SAML assertion configuration present.
- Requirement: NOT APPLICABLE — The application does not utilize SAML assertions.

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
- The application uses Keycloak for centralized account management, providing automated mechanisms for account creation, disabling, and deletion.
- File: deploy/keycloak/dev-realm.json — "registrationAllowed": true, "enabled": true, "users": [ ... ]
- File: api/README.md — "The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header."
- File: README.md — "Keycloak provides enterprise-grade authentication and authorization for the IRIS system: ... User Management: Organizational group hierarchy with automatic role assignment"
- Automated account management actions (e.g., disabling, deletion) are handled via Keycloak's configuration and policies, not manual processes.
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
- Static repository review completed on 2026-04-30.
- There is no evidence of shared or group application accounts being used or required.
- File: deploy/keycloak/dev-realm.json — All users are individual accounts; no shared/group credentials are defined.
- File: README.md — No mention of shared/group accounts; all authentication is via individual Keycloak users.
- Requirement: NOT APPLICABLE — No shared/group accounts exist in the application.

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
- There is no evidence of temporary user accounts being supported or used in the application.
- File: deploy/keycloak/dev-realm.json — No user accounts are marked as temporary; all users are persistent.
- File: README.md — No mention of temporary accounts or expiration settings for user accounts.
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
- Static repository review completed on 2026-04-30.
- There is no evidence of emergency accounts being used or supported in the application.
- File: deploy/keycloak/dev-realm.json — No emergency accounts defined; all users are standard roles (maintainer, engineer, leadership, admin, user).
- File: README.md — No mention of emergency accounts or related procedures.
- Requirement: NOT APPLICABLE — Emergency accounts are not used.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The application uses Keycloak for user management. Keycloak supports session idle timeout and maximum lifespan, which can be used to enforce inactivity policies.
- File: deploy/keycloak/dev-realm.json — "ssoSessionIdleTimeout": 28800 (8 hours), "ssoSessionMaxLifespan": 32400 (9 hours), "offlineSessionIdleTimeout": 2592000 (30 days)
- File: README.md — "Session Management: Secure token-based sessions with configurable timeouts"
- While the default offline session idle timeout is 30 days (2592000 seconds), this is less than or equal to 35 days as required.
- Requirement: SATISFIED — Account inactivity timeout is enforced via Keycloak session policies.

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
- All application user accounts are managed centrally in Keycloak. Only required users are present in the realm configuration.
- File: deploy/keycloak/dev-realm.json — "users": [ ... ] (all users are named, with roles and groups assigned)
- File: README.md — "Keycloak ... Manages user authentication and authorization ... Imports pre-configured realm from deploy/keycloak/dev-realm.json"
- No evidence of unnecessary or unvalidated accounts being created by the application itself.
- Requirement: SATISFIED — Only necessary user accounts are present and managed via Keycloak.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak provides automatic auditing of account creation events.
- File: deploy/keycloak/dev-realm.json — User creation is managed by Keycloak, which logs all account creation events in its audit log.
- File: README.md — "Keycloak ... Admin console for managing users, roles, and authentication settings"
- Keycloak's audit log includes account name, date, and time for user creation events.
- Requirement: SATISFIED — Account creation is automatically audited by Keycloak.

Remediation:
Configure the application to write a log entry when a new user account is created.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 28. APSC-DV-000350 | SV-222414r960780

- Rule ID: SV-222414r960780
- Severity: medium
- Rule Title: The application must automatically audit account modification.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak provides automatic auditing of account modification events.
- File: deploy/keycloak/dev-realm.json — User modifications (role changes, group assignments, etc.) are managed by Keycloak.
- File: README.md — "Keycloak ... Admin console for managing users, roles, and authentication settings"
- Keycloak's audit log includes account name, date, and time for user modification events.
- Requirement: SATISFIED — Account modification is automatically audited by Keycloak.

Remediation:
Configure the application to write a log entry when a user account is modified.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 29. APSC-DV-000360 | SV-222415r960783

- Rule ID: SV-222415r960783
- Severity: medium
- Rule Title: The application must automatically audit account disabling actions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak provides automatic auditing of account disabling actions.
- File: deploy/keycloak/dev-realm.json — User disabling is managed by Keycloak ("enabled": true/false per user).
- File: README.md — "Keycloak ... Admin console for managing users, roles, and authentication settings"
- Keycloak's audit log includes account name, date, and time for account disabling events.
- Requirement: SATISFIED — Account disabling is automatically audited by Keycloak.

Remediation:
Configure the application to write a log entry when a user account is disabled.

At a minimum, ensure account name, date and time of the event are recorded.

---

### 30. APSC-DV-000370 | SV-222416r960786

- Rule ID: SV-222416r960786
- Severity: medium
- Rule Title: The application must automatically audit account removal actions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak provides automatic auditing of account removal actions.
- File: deploy/keycloak/dev-realm.json — User removal is managed by Keycloak.
- File: README.md — "Keycloak ... Admin console for managing users, roles, and authentication settings"
- Keycloak's audit log includes account name, date, and time for account removal events.
- Requirement: SATISFIED — Account removal is automatically audited by Keycloak.

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
- Keycloak is used for account management, but there is no static evidence that system administrators (SAs) and ISSOs are notified when accounts are created.
- File: deploy/keycloak/dev-realm.json — No notification hooks or email notification settings for SAs/ISSOs on account creation.
- File: README.md — No mention of admin notifications for account creation.
- Requirement: PARTIALLY SATISFIED — Centralized account management is present, but notification to SAs/ISSOs on account creation is not evidenced in static configuration.

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
- Keycloak is used for account management, but there is no static evidence that system administrators (SAs) and ISSOs are notified when accounts are modified.
- File: deploy/keycloak/dev-realm.json — No notification hooks or email notification settings for SAs/ISSOs on account modification.
- File: README.md — No mention of admin notifications for account modification.
- Requirement: PARTIALLY SATISFIED — Centralized account management is present, but notification to SAs/ISSOs on account modification is not evidenced in static configuration.

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
- Keycloak is used for account management, but there is no static evidence that system administrators (SAs) and ISSOs are notified when accounts are disabled.
- File: deploy/keycloak/dev-realm.json — No notification hooks or email notification settings for SAs/ISSOs on account disabling.
- File: README.md — No mention of admin notifications for account disabling.
- Requirement: PARTIALLY SATISFIED — Centralized account management is present, but notification to SAs/ISSOs on account disabling is not evidenced in static configuration.

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
- Keycloak is used for account management, but there is no static evidence that system administrators (SAs) and ISSOs are notified when accounts are removed.
- File: deploy/keycloak/dev-realm.json — No notification hooks or email notification settings for SAs/ISSOs on account removal.
- File: README.md — No mention of admin notifications for account removal.
- Requirement: PARTIALLY SATISFIED — Centralized account management is present, but notification to SAs/ISSOs on account removal is not evidenced in static configuration.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- Keycloak provides automatic auditing of account enabling actions.
- File: deploy/keycloak/dev-realm.json — User enabling is managed by Keycloak ("enabled": true/false per user).
- File: README.md — "Keycloak ... Admin console for managing users, roles, and authentication settings"
- Keycloak's audit log includes account name, date, and time for account enabling events.
- Requirement: SATISFIED — Account enabling is automatically audited by Keycloak.

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
- Keycloak is used for account management, but there is no static evidence that system administrators (SAs) and ISSOs are notified when accounts are enabled.
- File: deploy/keycloak/dev-realm.json — No notification hooks or email notification settings for SAs/ISSOs on account enabling.
- File: README.md — No mention of admin notifications for account enabling.
- Requirement: PARTIALLY SATISFIED — Centralized account management is present, but notification to SAs/ISSOs on account enabling is not evidenced in static configuration.

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
- There is no static evidence of a dedicated document identifying and documenting application data protection requirements.
- File: README.md — Mentions "Detailed technical specifications and API documentation are maintained in the /docs directory, including: ... Database schema documentation ... Deployment and configuration instructions", but no actual data protection requirements documentation is included in the provided files.
- No file named /docs or equivalent data protection requirements documentation is present in the manifest or provided files.
- Requirement: PARTIALLY SATISFIED — Data protection is referenced, but explicit documentation of data protection requirements is not evidenced.

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
- There is no static evidence of organization-defined data mining detection techniques being implemented.
- File: README.md — Mentions "Vector-based indexing across visual and textual maintenance content" and "Qdrant for document and video content search", but no mention of query rate limiting, data mining detection, or protections against data dumps.
- No configuration or code references to query limits, automated alarming, or data mining detection in the provided files.
- Requirement: NOT SATISFIED — No evidence of data mining detection techniques implemented.

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
- The application enforces approved authorizations for logical access to information and system resources via Keycloak RBAC.
- File: deploy/keycloak/dev-realm.json — "roles": { ... } (role definitions for video:create, video:view, clip:generate, annotation:generate, etc.), "realmRoles": [ ... ] (assigned per user)
- File: api/README.md — "The API implements role-based access control (RBAC) for protected endpoints. ... Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin ... All endpoints except /health require authentication."
- File: README.md — "Keycloak ... Role-Based Access Control (RBAC): Fine-grained permissions using atomic and composite roles"
- Requirement: SATISFIED — RBAC is enforced via Keycloak and API endpoint protection.

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
- There is no evidence that discretionary access control (DAC) is implemented or required. All access control is role-based (RBAC) and centrally managed.
- File: deploy/keycloak/dev-realm.json — All permissions are assigned via roles, not per-user or per-object discretionary controls.
- File: api/README.md — "Role-Based Access Control ... All endpoints except /health require authentication ... Admin endpoints require specific roles."
- Requirement: NOT APPLICABLE — Discretionary access control is not implemented or required.

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
- Control requires enforcement of information flow within the system based on defined policies (e.g., data labels, rulesets, policy enforcement).
- File: README.md — System overview and architecture describe multi-modal AI analysis, technical document retrieval, and role-based access control via Keycloak, but do not mention explicit information flow control policies or data labeling mechanisms for internal data flow.
- File: api/README.md — Describes RBAC via Keycloak and protected endpoints, but no evidence of data labeling or flow control within the application.
- File: deploy/keycloak/dev-realm.json — Defines roles and groups for RBAC, but no data labeling or flow control policy artifacts.
- No code or configuration found that implements data labeling, tagging, or explicit information flow control within the application.
- Requirement: PARTIALLY SATISFIED — RBAC is present, but there is no evidence of explicit information flow control policies or enforcement mechanisms for data labels within the system.

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
- Control requires enforcement of information flow between interconnected systems based on defined policies (e.g., data labels, rulesets, policy enforcement between systems).
- File: README.md — Describes integration with external systems (AWS S3, Qdrant, Bedrock, Keycloak), but does not mention explicit information flow control policies between these systems.
- File: api/README.md — Mentions S3, Qdrant, and Bedrock integration, but no evidence of data labeling or flow control between systems.
- File: deploy/keycloak/dev-realm.json — RBAC for users, but no cross-system data flow policies.
- No code or configuration found that implements data labeling, tagging, or explicit information flow control between interconnected systems.
- Requirement: PARTIALLY SATISFIED — RBAC and access controls exist, but there is no evidence of explicit information flow control policies or enforcement between interconnected systems.

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
- File: api/README.md — Documents RBAC via Keycloak, with admin endpoints requiring specific roles (role_maintainer, role_engineer, admin). Example: '/admin/*' endpoints require AdminUser.
- File: deploy/keycloak/dev-realm.json — Defines roles and groups, including 'admin', 'role_maintainer', 'role_engineer', and assigns them to users. No evidence of application or OS-level user/group assignments or file permissions.
- File: deploy/aws/iris-stack.yaml — EC2 instance and IAM roles are defined, but no evidence of application process user/group assignments or file system permissions.
- No static evidence of OS-level user/group membership, file/directory ownership, or permissions for the application process.
- Requirement: PARTIALLY SATISFIED — Application-level RBAC is present, but OS-level user/group and file permission assignments cannot be confirmed from static artifacts.

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
- Control requires that the application executes without excessive account permissions (OS and database privileges).
- File: deploy/aws/iris-stack.yaml — EC2 instance profile and IAM role are defined, but the specific permissions granted to the application process are not fully enumerated in the provided snippet. S3, Bedrock, and SecretsManager permissions are granted to the EC2 instance role, but no evidence of least-privilege review.
- File: api/README.md — No evidence of database user privilege configuration or review of OS-level privileges for the application process.
- No static evidence of application user/group membership, database user privileges, or OS-level privilege assignments.
- Requirement: PARTIALLY SATISFIED — IAM roles are defined, but there is insufficient evidence to confirm that the application executes with only the minimum necessary privileges.

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
- Control requires auditing/logging of privileged function execution (e.g., admin actions, configuration changes).
- File: api/README.md — Documents RBAC and admin endpoints, but does not mention audit logging of privileged actions.
- File: api/app/process/router.py — No evidence of audit logging for privileged/admin actions (e.g., no logging statements for admin endpoints).
- File: api/app/process/services/scene_summarization.py — Logging is present for processing events, but not specifically for privileged/admin actions.
- No evidence of log entries recording specific privileged actions, user, date/time, or event details.
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
- Control requires enforcement of a limit of three consecutive invalid logon attempts within 15 minutes.
- File: deploy/keycloak/dev-realm.json —
- "bruteForceProtected": true
- "failureFactor": 3
- "maxFailureWaitSeconds": 900
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
- Static repository review completed on 2026-04-30.
- Control requires an approved process for unlocking locked user accounts, with ISSO/ISSM approval and identity validation.
- File: deploy/keycloak/dev-realm.json — No evidence of an explicit, documented, or ISSO/ISSM-approved process for unlocking accounts. No process documentation or workflow is referenced in the static configuration.
- Requirement: NOT SATISFIED — No static evidence of an approved process for unlocking locked user accounts.

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
- Static repository review completed on 2026-04-30.
- Control requires display of the Standard Mandatory DoD Notice and Consent Banner before granting access to the application (if interactive UI exists).
- File: deploy/keycloak/themes/README.md — Describes a custom Keycloak login theme, but does not mention inclusion of the DoD Notice and Consent Banner text.
- File: deploy/keycloak/dev-realm.json — "loginTheme": "iris" is set, but no evidence of DoD banner text in the theme or configuration.
- File: ui/.env.example — No banner configuration.
- No evidence in UI or Keycloak theme documentation of the DoD Notice and Consent Banner being displayed prior to access.
- Requirement: NOT SATISFIED — No static evidence of the DoD Notice and Consent Banner being displayed before access.

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
- Control requires the DoD Notice and Consent Banner to remain on screen until users acknowledge usage conditions and take explicit action to log on.
- File: deploy/keycloak/themes/README.md — Describes custom login theme, but does not mention banner acknowledgment or explicit acceptance action.
- File: deploy/keycloak/dev-realm.json — No evidence of banner acknowledgment requirement.
- No evidence in UI or Keycloak theme documentation of a mechanism requiring explicit user acknowledgment of the DoD banner before login.
- Requirement: NOT SATISFIED — No static evidence of banner acknowledgment enforcement.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires the Standard Mandatory DoD Notice and Consent Banner to be displayed before granting access to a publicly accessible application.
- File: deploy/keycloak/themes/README.md — Custom login theme is described, but no mention of DoD Notice and Consent Banner text.
- File: deploy/keycloak/dev-realm.json — No evidence of DoD banner text or display configuration.
- No evidence in UI or Keycloak theme documentation of the DoD Notice and Consent Banner being displayed prior to access.
- Requirement: NOT SATISFIED — No static evidence of the DoD Notice and Consent Banner being displayed before access.

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
- Control requires the application to display the time and date of the user's last successful logon in the user interface.
- File: deploy/keycloak/dev-realm.json — No evidence of last logon time display configuration.
- File: deploy/keycloak/themes/README.md — No mention of last logon time display in the login or account UI.
- File: ui/.env.example — No relevant configuration.
- No evidence in UI or Keycloak theme documentation of last logon time being displayed to users.
- Requirement: NOT SATISFIED — No static evidence of last successful logon time display.

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
- Control requires non-repudiation services (e.g., digital signatures) if required by application design or organization.
- File: README.md — No mention of digital signatures or non-repudiation requirements for application users.
- File: api/README.md — No mention of non-repudiation or digital signature features.
- File: deploy/keycloak/dev-realm.json — No mention of digital signatures or non-repudiation.
- Requirement: NOT APPLICABLE — Application is not designed to provide non-repudiation services for users.

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
- File: README.md — No mention of audit record aggregation or log aggregation services.
- File: api/README.md — No mention of log aggregation or system-wide audit trail.
- No evidence of audit record aggregation capability in the application.
- Requirement: NOT APPLICABLE — Application does not provide audit record aggregation services.

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
- Control requires audit record generation for the creation of session IDs.
- File: api/README.md — Mentions JWT-based authentication and session management via Keycloak, but does not mention logging of session ID creation events.
- File: deploy/keycloak/dev-realm.json — No evidence of session ID creation event logging configuration.
- No evidence in application or Keycloak configuration of audit logs for session ID creation events.
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
- Control requires audit record generation for the destruction of session IDs.
- File: api/README.md — Mentions JWT-based authentication and session management via Keycloak, but does not mention logging of session ID destruction events.
- File: deploy/keycloak/dev-realm.json — No evidence of session ID destruction event logging configuration.
- No evidence in application or Keycloak configuration of audit logs for session ID destruction events.
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
- Control requires audit record generation for the renewal of session IDs (e.g., privilege escalation, re-authentication).
- File: api/README.md — Mentions JWT-based authentication and session management via Keycloak, but does not mention logging of session ID renewal events.
- File: deploy/keycloak/dev-realm.json — No evidence of session ID renewal event logging configuration.
- No evidence in application or Keycloak configuration of audit logs for session ID renewal events.
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
- Control requires that sensitive data (e.g., passwords, session IDs, encryption keys) is not written to application logs.
- File: api/app/process/router.py — No evidence of logging sensitive data, but also no explicit log redaction or filtering.
- File: api/app/process/services/scene_summarization.py — Uses logging for processing events, but no evidence of sensitive data being logged. However, no explicit safeguards are present.
- File: api/README.md — No mention of log redaction or sensitive data handling in logs.
- No evidence of explicit log filtering or redaction for sensitive data in application code.
- Requirement: PARTIALLY SATISFIED — No evidence of sensitive data being logged, but also no explicit safeguards or log filtering present.

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
- Control requires audit record generation for session timeout events.
- File: api/README.md — Mentions session management via Keycloak, but no mention of logging session timeout events.
- File: deploy/keycloak/dev-realm.json — No evidence of session timeout event logging configuration.
- No evidence in application or Keycloak configuration of audit logs for session timeout events.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for session timeout events.

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
- Control requires that event logs include a time stamp indicating when the event occurred.
- File: api/app/process/services/scene_summarization.py — Logging statements use logger.info, but the log format is not shown; no evidence that time stamps are included in log output.
- File: api/app/process/router.py — No evidence of log output format.
- File: api/app/logging_config.py — Not included in context, so cannot confirm log format.
- Requirement: PARTIALLY SATISFIED — Logging is present, but no static evidence that time stamps are included in event logs.

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
- File: api/README.md — No mention of HTTP header logging.
- File: api/app/process/router.py — No evidence of HTTP header logging in API endpoints.
- No evidence in application code or configuration of HTTP header logging.
- Requirement: NOT SATISFIED — No static evidence of audit record generation for HTTP headers.

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
- No explicit evidence of IP address logging found in provided FastAPI router code (api/app/process/router.py) or in RAG/documentation code (api/app/rag/services.py).
- No logging configuration or middleware code shown that would capture and log client IP addresses for API requests.
- README.md and api/README.md reference logging and health endpoints but do not specify IP address logging.
- Requirement: PARTIALLY SATISFIED — Logging is present for processing and service events, but there is no static evidence that connecting IP addresses are captured in audit logs. Logging configuration and middleware code are missing from context.

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
- Control requires audit logs to record the username or user ID associated with each event.
- api/README.md: Describes JWT-based authentication via Keycloak, with user claims and roles decoded and injected into endpoint functions (see 'Authentication Dependency Injection').
- api/app/process/router.py: Endpoints use FastAPI dependency injection for authentication, but no explicit logging of user ID or username in processing or event logs is shown.
- No evidence in provided code that user identity is included in log records for actions/events.
- Requirement: PARTIALLY SATISFIED — User authentication and role information are available at runtime, but there is no static evidence that user IDs are written to audit logs for events. Logging implementation details are missing.

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
- No static evidence in provided FastAPI router (api/app/process/router.py) or RAG services (api/app/rag/services.py) of privilege granting operations or corresponding audit logging.
- api/README.md: Describes RBAC via Keycloak, but privilege changes are managed in Keycloak, not in application code.
- No log statements or audit trail for privilege grant attempts found in provided code.
- Requirement: NOT SATISFIED — No static evidence of audit records for privilege grant attempts. Privilege management appears to be external to the application.

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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for access attempts to security objects (e.g., protected resources, configuration, or privileged data).
- api/README.md: Describes RBAC enforcement, but does not specify audit logging for access attempts.
- No log statements or audit trail for access attempts to security objects found in static code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for access attempts to different security levels or domains.
- api/README.md: Describes RBAC and role enforcement, but does not specify audit logging for security level access attempts.
- No log statements or audit trail for security level access attempts found in static code.
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
- Control requires audit records for access to categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and api/README.md: No mention of data classification levels or compartmentalized data categories.
- No evidence of information categories or classification enforcement in provided code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of privilege modification operations or corresponding audit logging.
- api/README.md: Privilege management is handled by Keycloak (external IAM), not by application code.
- No log statements or audit trail for privilege modification attempts found in static code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for modification attempts to security objects.
- No log statements or audit trail for such events found in static code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for modification attempts to security levels or domains.
- No log statements or audit trail for such events found in static code.
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
- Control requires audit records for modification of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and api/README.md: No mention of data classification levels or compartmentalized data categories.
- No evidence of information categories or classification enforcement in provided code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of privilege deletion operations or corresponding audit logging.
- api/README.md: Privilege management is handled by Keycloak (external IAM), not by application code.
- No log statements or audit trail for privilege deletion attempts found in static code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for deletion attempts to security levels or domains.
- No log statements or audit trail for such events found in static code.
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
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for deletion attempts to database security objects.
- No log statements or audit trail for such events found in static code.
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
- Control requires audit records for deletion of categories of information (e.g., classification levels), but only if the application requirements call for compartmentalized data and data protection.
- README.md and api/README.md: No mention of data classification levels or compartmentalized data categories.
- No evidence of information categories or classification enforcement in provided code.
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
- api/README.md: Describes JWT-based authentication via Keycloak, with FastAPI dependency injection for authentication.
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for logon attempts (successful or unsuccessful).
- No log statements or audit trail for authentication events found in static code.
- Requirement: NOT SATISFIED — No static evidence of audit records for logon attempts.

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
- api/README.md: Describes RBAC enforcement for admin endpoints, but no evidence of audit logging for privileged actions (e.g., modifying logging, starting/stopping services, terminating sessions).
- No log statements or audit trail for privileged activities found in static code.
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
- api/README.md: Describes JWT-based authentication and session management via Keycloak, but no evidence of logging session start/end times in application logs.
- No log statements or audit trail for session start/end events found in static code.
- Requirement: NOT SATISFIED — No static evidence of audit records for session start and end times.

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
- Control requires audit records for successful/unsuccessful accesses to objects (files, folders, processes, modules, etc.).
- api/app/process/router.py: Endpoints process videos, documents, and metadata, but no evidence of audit logging for access attempts to these objects.
- No log statements or audit trail for object access events found in static code.
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
- Control requires audit records for all direct access to the information system (e.g., OS commands, file system navigation) if such features exist.
- README.md and api/README.md: No mention of direct OS access features exposed to users.
- No evidence in provided code of features allowing direct access to the underlying OS or system resources.
- Requirement: NOT APPLICABLE — Application does not expose direct access to the underlying OS or system resources.

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
- api/README.md: User management is handled by Keycloak (external IAM), not by application code. Keycloak manages user accounts, roles, and authentication.
- No evidence in provided code (api/app/process/router.py, api/app/rag/services.py) of audit logging for user account events within the application.
- Requirement: PARTIALLY SATISFIED — User account management and audit logging are delegated to Keycloak. No static evidence that application logs these events, but if Keycloak is configured to be STIG compliant, this requirement may be inherited. Confirmation of Keycloak audit configuration is required.

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
- The control requires the application to initiate session auditing (logging) upon startup.
- File: api/app/process/router.py — logging is referenced via 'from app.logging_config import get_logger' in dependent services (e.g., scene_summarization.py, scene_classification.py), and all major processing endpoints (e.g., /process/video, /process/video-batch) call service functions that log events at start and on errors.
- File: api/app/process/services/scene_summarization.py — logger = get_logger(__name__); logger.info("Using cached summary", session_id=session_id); logger.info("Scene summarization plan", ...); logger.info("Scene summarization done", ...); logger.info("Stored summaries to S3", session_id=session_id)
- File: api/app/process/services/scene_classification.py — logger = get_logger(__name__); logger.info("Loaded centroids", ...); logger.info("Classifying frames", ...); logger.info("Frame classification distribution", ...); logger.info("Session classified", ...)
- Logging is initialized and used at the start of processing, and logs are written for startup, processing, and completion events.
- Requirement: SATISFIED — Logging is initiated at application startup and logs are generated for startup and processing events.

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
- The control requires the application to log shutdown events.
- No explicit evidence found in api/app/process/router.py or related service files for logging application shutdown events (e.g., no logger.info("Shutting down") or similar in main application entrypoints).
- Logging is present for processing events, but shutdown logging is not evident in the provided static code.
- Requirement: PARTIALLY SATISFIED — Application logs processing events, but there is no static evidence of shutdown event logging. Confirmation would require reviewing the main application entrypoint (e.g., api/app/main.py) or runtime logs.

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
- The control requires logging of destination IP addresses for outbound connections.
- No explicit evidence found in api/app/process/router.py, api/app/process/services/scene_summarization.py, or api/app/process/services/scene_classification.py of logging destination IP addresses when making outbound connections (e.g., to S3, Qdrant, Bedrock, etc.).
- Outbound connections are made (e.g., boto3.client('bedrock-runtime'), QdrantClient), but destination IP logging is not present in the code.
- Requirement: NOT SATISFIED — No static evidence of destination IP address logging for outbound connections.

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
- The control requires logging user actions involving access to data.
- In api/app/process/router.py, endpoints process video, documents, and other data, but there is no explicit logging of user identity or user actions when accessing data (e.g., no logger.info including user ID or action type).
- Logging is focused on processing status and errors, not user access events.
- Requirement: NOT SATISFIED — No static evidence of audit logging for user data access actions.

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
- The control requires logging user actions involving changes to data.
- In api/app/process/router.py and related services, there is no explicit logging of user identity or user actions when modifying data (e.g., no logger.info including user ID or data change details).
- Processing status updates and S3 writes are logged, but not attributed to specific users or data change events.
- Requirement: NOT SATISFIED — No static evidence of audit logging for user data modification actions.

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
- The control requires audit records to contain date and time information.
- File: api/app/process/services/scene_summarization.py — generated_at=datetime.utcnow().isoformat() + "Z" is included in summary records written to S3.
- File: api/app/process/services/scene_classification.py — processed_at=datetime.utcnow().isoformat() + "Z" is included in classification metadata written to S3.
- All major processing outputs include ISO8601 timestamps in their metadata.
- Requirement: SATISFIED — Audit records and processing outputs include date and time of event.

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
- The control requires audit records to identify which component, feature, or function triggered the event.
- File: api/app/process/services/scene_summarization.py — logger = get_logger(__name__) and logger.info(...) include the module name (e.g., 'scene_summarization') in log records.
- File: api/app/process/services/scene_classification.py — logger = get_logger(__name__) and logger.info(...) include the module name (e.g., 'scene_classification') in log records.
- Log entries are tagged with the originating component/module via __name__.
- Requirement: SATISFIED — Log records include component/function/module information.

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
- The control requires a unique identifier for the application in centralized logging.
- No explicit evidence in the provided files of a unique application identifier being included in logs or log storage (e.g., no application name, instance ID, or hostname in log records).
- Logging is present, but uniqueness for centralized log correlation is not statically verifiable.
- Requirement: NOT SATISFIED — No static evidence of unique application identifier in logs.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires audit records to include the outcome of events.
- File: api/app/process/router.py — All major endpoints return status fields (e.g., 'status': 'success', 'status': 'completed', 'status': 'exists') in their responses and log messages.
- File: api/app/process/services/scene_summarization.py — logger.info("Scene summarization done", summarized=len(scene_summaries), ...)
- File: api/app/process/services/scene_classification.py — logger.info("Session classified", ...), logger.info("Already classified", ...)
- Requirement: SATISFIED — Audit records and logs include event outcomes (success, completed, exists, error).

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
- The control requires audit records to include the identity of the user or process associated with the event.
- No explicit evidence in api/app/process/router.py or related services of user identity being included in logs or audit records (e.g., no user_id, username, or process ID in logger.info or metadata).
- Processing events are logged, but not attributed to users or processes.
- Requirement: NOT SATISFIED — No static evidence of user/process identity in audit records.

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
- The control requires logging the full text of privileged commands or individual identities of group account users.
- No evidence in api/app/process/router.py or related services of logging privileged command text or mapping group account actions to individual users.
- No static artifacts indicating privileged command capture or group user disambiguation in logs.
- Requirement: NOT SATISFIED — No static evidence of privileged command or group user identity logging.

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
- The control requires transaction recovery logs when transaction-based.
- No explicit evidence in the provided files of transaction logging or recovery log configuration (e.g., no database transaction log settings, no explicit transaction log file paths).
- The application uses PostgreSQL (see deploy/aws/iris-stack.yaml), but static evidence of transaction logging is not present in application code/configuration.
- Requirement: NOT SATISFIED — No static evidence of transaction recovery log configuration.

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
- The control requires centralized management/configuration of audit record content across all components.
- No explicit evidence in the provided files of a centralized log management interface or configuration system for audit content (e.g., no log aggregation service, no central log config, no log management API).
- Logging is implemented per-module, but central management is not statically verifiable.
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
- Static repository review completed on 2026-04-30.
- The control requires off-loading audit records to a different system or media.
- No explicit evidence in the provided files of automated log off-loading or centralized log shipping (e.g., no log forwarding, no S3 log export, no external log sink configuration).
- Application writes processing outputs to S3, but audit logs themselves are not shown to be off-loaded.
- Requirement: NOT SATISFIED — No static evidence of audit log off-loading to a different system.

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
- The control requires writing application logs to a centralized log repository.
- No explicit evidence in the provided files of logs being written to a centralized log repository (e.g., no log aggregation service, no log shipping configuration, no external log sink).
- Application writes processing outputs to S3, but audit logs are not shown to be centralized.
- Requirement: NOT SATISFIED — No static evidence of centralized log repository usage for application logs.

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
- The control requires immediate warning to SA/ISSO when audit storage reaches 75% capacity.
- No explicit evidence in the provided files of log storage monitoring, threshold alarms, or alerting mechanisms for audit storage capacity (e.g., no disk usage checks, no alert configuration, no notification code).
- Requirement: NOT SATISFIED — No static evidence of audit storage capacity monitoring or alerting.

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
- The control requires real-time alerting to SA/ISSO for audit failure events (moderate/high impact systems).
- No explicit evidence in the provided files of real-time alerting for audit/logging failures (e.g., no error notification, no alerting integration, no monitoring hooks).
- Requirement: NOT SATISFIED — No static evidence of real-time alerting for audit failures.

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
- The control requires alerting the ISSO/SA in the event of an audit processing failure.
- No explicit evidence in the provided files of alerting mechanisms for audit/logging processing failures (e.g., no notification code, no alert integration, no monitoring hooks).
- Requirement: NOT SATISFIED — No static evidence of alerting on audit processing failure.

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
- The control requires the application to shut down by default upon audit failure (unless availability is an overriding concern).
- No explicit evidence in the provided files of application shutdown logic tied to audit/logging failures (e.g., no code that halts processing or exits on log failure, no configuration for log failure handling).
- Requirement: NOT SATISFIED — No static evidence of shutdown or compensating controls on audit failure.

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
- The control requires centralized review/analysis of audit records from multiple components.
- No explicit evidence in the provided files of a centralized log review/analysis capability (e.g., no log aggregation dashboard, no central log query interface, no log management system integration).
- Requirement: NOT SATISFIED — No static evidence of centralized audit record review/analysis capability.

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
- Control requires the application to provide filtering of audit records by user, event type, date/time, resource, IP, object, event level, and keywords.
- No evidence of a dedicated audit log filtering UI or API endpoint is present in the provided FastAPI routers (e.g., api/app/process/router.py) or in the README documentation.
- No log management utility or filtering logic is described or implemented in the code or documentation.
- Logging configuration and log storage locations are not described in api/README.md or api/app/process/router.py.
- Requirement: PARTIALLY SATISFIED — Application may log events, but there is no evidence of audit log filtering capability as required by the control.

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
- Control requires on-demand reporting based on filtered audit event data.
- No evidence of a reporting feature or endpoint for audit logs is present in api/app/process/router.py or api/README.md.
- No log filtering or report generation logic is described in the documentation or code.
- No mention of integration with a centralized logging/reporting system.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or on-demand reporting capability for audit logs.

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
- Control requires on-demand audit review and analysis via audit reduction (filtering and reporting).
- No endpoints or UI features for audit log review, filtering, or analysis are present in api/app/process/router.py or api/README.md.
- No mention of audit log review or analysis features in the documentation.
- Requirement: NOT SATISFIED — No static evidence of audit reduction or on-demand audit review/analysis capability.

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
- No endpoints, UI, or documentation describe audit log filtering or reduction features for investigations.
- No evidence of integration with a centralized logging solution that provides this capability.
- Requirement: NOT SATISFIED — No static evidence of audit reduction/filtering for after-the-fact investigations.

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
- Control requires report generation for on-demand audit review and analysis.
- No endpoints or features for generating audit reports are present in api/app/process/router.py or api/README.md.
- No documentation of audit report generation or review features.
- Requirement: NOT SATISFIED — No static evidence of audit report generation for audit review/analysis.

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
- No evidence of customizable or ad-hoc audit log reporting features in code or documentation.
- No mention of integration with a centralized reporting solution.
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
- No endpoints, UI, or documentation describe audit log report generation for investigations.
- No evidence of integration with a centralized reporting solution.
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
- Control requires audit reduction (event filtering) not alter original content or time ordering of audit records.
- No audit reduction/filtering features are present in the code or documentation, so it cannot be determined if original content is preserved.
- Requirement: PARTIALLY SATISFIED — No evidence of filtering, so no evidence of alteration, but also no evidence of compliance.

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
- Control requires report generation not alter original content or time ordering of audit records.
- No audit log report generation features are present in the code or documentation, so it cannot be determined if original content is preserved.
- Requirement: PARTIALLY SATISFIED — No evidence of report generation, so no evidence of alteration, but also no evidence of compliance.

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
- Control requires use of internal system clocks for audit record timestamps.
- No evidence of audit log timestamp generation or logging configuration is present in the provided code or documentation.
- No log format or timestamp handling is described in api/README.md or api/app/process/router.py.
- Requirement: NOT SATISFIED — No static evidence that audit logs use system clocks for timestamps.

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
- Control requires audit record timestamps be mapped to UTC or GMT.
- No evidence of audit log timestamp format, timezone handling, or mapping to UTC/GMT is present in the code or documentation.
- Requirement: NOT SATISFIED — No static evidence of UTC/GMT mapping for audit log timestamps.

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
- Control requires audit record timestamps with at least one second granularity.
- No evidence of audit log timestamp precision or granularity is present in the code or documentation.
- Requirement: NOT SATISFIED — No static evidence of timestamp granularity for audit logs.

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
- Control requires protection of audit information from unauthorized read access.
- No evidence of audit log storage location, file permissions, or access controls for audit data is present in the code or documentation.
- No mention of role-based access to audit logs or audit configuration.
- Requirement: NOT SATISFIED — No static evidence of access controls for audit information.

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
- Control requires protection of audit information from unauthorized modification.
- No evidence of audit log storage, file permissions, or access controls for modification is present in the code or documentation.
- No mention of role-based modification controls for audit logs or audit configuration.
- Requirement: NOT SATISFIED — No static evidence of modification controls for audit information.

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
- Control requires protection of audit information from unauthorized deletion.
- No evidence of audit log storage, file permissions, or access controls for deletion is present in the code or documentation.
- No mention of role-based deletion controls for audit logs or audit configuration.
- Requirement: NOT SATISFIED — No static evidence of deletion controls for audit information.

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
- Control applies only if the application provides a distinct audit tool or audit tool functionality.
- No evidence of a distinct audit tool, audit log viewer, or audit tool submodule is present in the code or documentation.
- No separate executable, UI, or API for audit tool functionality is described.
- Requirement: NOT APPLICABLE — No audit tool functionality present in application.

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
- Control applies only if the application provides a distinct audit tool or audit tool functionality.
- No evidence of a distinct audit tool, audit log viewer, or audit tool submodule is present in the code or documentation.
- No separate executable, UI, or API for audit tool functionality is described.
- Requirement: NOT APPLICABLE — No audit tool functionality present in application.

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
- Control applies only if the application provides a distinct audit tool or audit tool functionality.
- No evidence of a distinct audit tool, audit log viewer, or audit tool submodule is present in the code or documentation.
- No separate executable, UI, or API for audit tool functionality is described.
- Requirement: NOT APPLICABLE — No audit tool functionality present in application.

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
- Control applies only if the application includes a built-in backup capability for audit records.
- No evidence of a built-in backup feature for audit logs is present in the code or documentation.
- No backup settings or backup scheduling for audit logs are described.
- Requirement: NOT APPLICABLE — No built-in audit log backup capability present in application.

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
- Control requires cryptographic mechanisms (e.g., hash, message digest) to protect audit log integrity.
- No evidence of cryptographic integrity checks (hashing, signing) for audit logs is present in the code or documentation.
- No mention of integration with a centralized audit log solution that provides cryptographic integrity.
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
- Control requires separate audit tools (executables or libraries) for viewing/manipulating logs to be cryptographically hashed.
- No evidence of separate audit tool binaries or scripts for log viewing/manipulation in the provided file manifest or codebase.
- Logging and audit functionality appears to be integrated into the main application and API services (e.g., FastAPI endpoints, logging_config.py), not as standalone tools.
- No static artifacts (e.g., hash files, checksum scripts, or documentation of such a process) found for audit tool integrity.
- Requirement: NOT APPLICABLE — application does not provide separate audit tools as file-oriented executables or libraries.

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
- Control requires periodic validation of audit tool integrity via cryptographic hash checks.
- No separate audit tool binaries or scripts for log viewing/manipulation are present in the codebase or deployment artifacts.
- No static evidence of a process or mechanism for periodic hash validation of audit tools.
- Logging and audit functionality is integrated into the main application, not as a separate tool.
- Requirement: NOT APPLICABLE — application does not provide separate audit tools as file-oriented executables or libraries.

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
- No evidence in the UI, API, or documentation of any feature allowing users to install software, plugins, modules, or extensions.
- All deployment and extension mechanisms (e.g., Docker Compose, Kubernetes, AWS CloudFormation) are administrator/infrastructure controlled.
- No code paths, endpoints, or UI elements for user-driven installation of software components.
- Requirement: NOT APPLICABLE — application does not provide user-facing software installation or extension capability.

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
- File: api/app/config.py — configuration is loaded from environment variables and .env files, e.g., `model_config = SettingsConfigDict(env_file=".env")`.
- File: api/README.md — instructs users to copy `.env.example` to `.env` and edit configuration, but does not specify file permission requirements or access controls.
- File: deploy/aws/iris-stack.yaml — EC2 UserData script sets permissions on environment files: `chmod 600 "${ENV_FILE}"` for `api/.env`.
- No evidence of application-level UI or API for configuration changes; all configuration is file-based or via environment variables.
- No explicit documentation or code for restricting access to configuration files to only authorized users (e.g., application administrators).
- Requirement: PARTIALLY SATISFIED — OS-level script sets restrictive permissions on `.env` file, but no evidence of comprehensive access restriction enforcement or audit for all configuration files. Application-level configuration change interface does not exist.

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
- File: api/app/config.py — configuration is loaded from environment variables and `.env` files; no code for auditing changes.
- File: deploy/aws/iris-stack.yaml — UserData script copies `.env.example` to `.env` and sets permissions, but does not log user identity for changes.
- No evidence of audit logging for configuration file modifications or user identity tracking in the application or deployment scripts.
- No application-level configuration change interface exists; all changes are made via file edits or environment variables.
- Requirement: NOT SATISFIED — no mechanism to log or audit which user account makes configuration changes.

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
- Control requires the application to prevent installation of unsigned patches/components.
- File: README.md, api/README.md — all patching and deployment is performed via Docker images, Kubernetes manifests, and AWS CloudFormation templates.
- No evidence of digital signature verification or hash validation for application components or patches prior to installation.
- No static artifacts (scripts, config, documentation) describing a process to verify digital signatures or hashes of application components before deployment.
- Requirement: NOT SATISFIED — no mechanism to prevent installation of unsigned patches or to verify digital signatures/hashes of components.

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
- File: api/README.md — application libraries are installed via Docker image build or pip/conda in a controlled environment.
- File: deploy/aws/iris-stack.yaml — EC2 UserData script clones the repository and builds the stack as root, but does not specify file permissions for application library directories.
- No evidence of OS-level file permission enforcement on application library directories (e.g., `app/`, `venv/`, or site-packages) beyond default Docker/container isolation.
- No application-level functionality for updating or extending libraries at runtime.
- Requirement: PARTIALLY SATISFIED — containerization limits access, but no explicit file permission settings or documentation restricting write access to libraries to only authorized users.

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
- Control requires a vulnerability assessment process and retention of scan results.
- File: README.md — section 'End-to-End Testing' describes Playwright E2E tests and accessibility checks, but not vulnerability scanning.
- File: .github/workflows/api-code-quality.yml, .github/workflows/ui-code-quality.yml (not included in full) — likely run linting and code quality checks, but no explicit mention of vulnerability scanning tools (e.g., Snyk, Trivy, Bandit, etc.).
- No static artifacts (scan reports, configuration files for vulnerability scanners, or documentation of a vulnerability assessment process) found in the provided files.
- Requirement: NOT SATISFIED — no evidence of application vulnerability assessment or scan result retention.

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
- Control requires prevention of program execution except as authorized by policy.
- File: README.md — describes deployment via Docker Compose, Kubernetes, and AWS CloudFormation; no mention of application-level execution restriction mechanisms.
- File: deploy/aws/iris-stack.yaml — EC2 UserData script installs and runs only the IRIS stack; no evidence of OS-level execution restriction policies (e.g., AppArmor, SELinux, AppLocker) or application-level RBAC for program execution.
- No static policy files or configuration for execution restriction found.
- Requirement: NOT SATISFIED — no evidence of enforcement of program execution restrictions in accordance with organizational policy.

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
- Control requires a deny-all, permit-by-exception (whitelist) policy for execution of authorized software programs, applicable to configuration management or similar system-process-managing applications.
- Application is not a configuration management system or system process manager; it is a web-based AI maintenance assistance platform.
- No evidence of application-level process execution management or whitelisting capability.
- Requirement: NOT APPLICABLE — application is not a configuration management or system process management tool.

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
- File: README.md — describes modular architecture and Docker Compose overlays for different environments (dev, lambda, prod), but does not enumerate or document disabling of non-essential features.
- File: api/README.md — describes optional development features (e.g., DISABLE_AUTH=True), but no evidence of a process or configuration for disabling unused modules or services in production.
- No static configuration or documentation listing which features are considered non-essential and how they are disabled in production deployments.
- Requirement: NOT SATISFIED — no evidence of explicit disabling of non-essential application capabilities.

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
- Control requires use of only PPSM CAL-approved ports and protocols.
- File: README.md — documents service ports: PostgreSQL (5432), Keycloak (8080), API (5000), UI (3000), Qdrant (6333/6334).
- File: deploy/aws/iris-stack.yaml — security groups allow 443 (ALB), 22 (SSH), 3000 (UI), 5432 (Postgres); ALB forwards 443 to 3000.
- No static mapping or documentation cross-referencing these ports/protocols to the PPSM CAL.
- Requirement: PARTIALLY SATISFIED — ports are documented, but no evidence of explicit PPSM CAL compliance verification.

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
- Control requires reauthentication when user privilege is escalated or role is changed.
- File: api/README.md — describes Keycloak-based authentication and RBAC, but no evidence of enforced reauthentication on role change or privilege escalation.
- No code or configuration found for session reauthentication triggers on sensitive actions.
- Requirement: NOT SATISFIED — no evidence of enforced reauthentication on role change or privilege escalation.

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
- File: api/README.md, api/app/config.py — no configuration or code for device authentication or periodic device reauthentication.
- No evidence of device session management or reauthentication interval enforcement.
- Requirement: NOT SATISFIED — no evidence of device reauthentication enforcement.

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
- File: api/README.md — describes Keycloak integration for authentication and authorization, with unique user accounts and JWT-based authentication.
- Example: `KEYCLOAK_URL=http://localhost:8080`, `KEYCLOAK_REALM=dev`, `KEYCLOAK_CLIENT_ID=dev-client`
- JWT tokens are issued per user and verified by the API: 'The API verifies JWT tokens using Keycloak's public keys (JWKS) without requiring a client secret.'
- Role-based access control (RBAC) is enforced via JWT claims.
- File: README.md — Keycloak is the identity provider for both UI and API, with SSO and RBAC.
- Requirement: SATISFIED — unique user identification and authentication is enforced via Keycloak SSO and JWT tokens.

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
- File: api/README.md — describes Keycloak-based authentication and RBAC, but no evidence of multifactor authentication (MFA) or Alt. Token enforcement for privileged accounts.
- No configuration or documentation for CAC, Alt. Token, or MFA integration in Keycloak or the application.
- Requirement: NOT SATISFIED — no evidence of multifactor or Alt. Token authentication for privileged accounts.

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
- Control requires acceptance of Personal Identity Verification (PIV) credentials (e.g., CAC).
- File: api/README.md, README.md — Keycloak is used for authentication, but no evidence of CAC/PIV or certificate-based authentication configuration.
- No static configuration, documentation, or code for enabling CAC/PIV authentication in Keycloak or the application.
- Requirement: NOT SATISFIED — no evidence of CAC/PIV credential acceptance.

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
- Control requires electronic verification of PIV credentials (e.g., CAC PIN entry and certificate validation).
- File: api/README.md, README.md — Keycloak is used for authentication, but no evidence of CAC/PIV or certificate-based authentication configuration or PIN verification.
- No static configuration, documentation, or code for enabling CAC/PIV authentication in Keycloak or the application.
- Requirement: NOT SATISFIED — no evidence of electronic verification of PIV credentials.

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
- Control requires multifactor (CAC, Alt. Token) authentication for network access to non-privileged accounts.
- File: api/README.md, README.md — Keycloak is used for authentication, but no evidence of CAC, Alt. Token, or MFA configuration for non-privileged accounts.
- No static configuration, documentation, or code for enabling CAC/Alt. Token authentication in Keycloak or the application.
- Requirement: NOT SATISFIED — no evidence of multifactor authentication for non-privileged accounts.

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
- File: api/README.md, README.md — Keycloak is used for authentication, but no evidence of Alt. Token or MFA configuration for privileged accounts for local access.
- No static configuration, documentation, or code for enabling Alt. Token authentication in Keycloak or the application.
- Requirement: NOT SATISFIED — no evidence of Alt. Token multifactor authentication for local privileged access.

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
- No evidence of CAC, PIV, or certificate-based authentication enforcement (e.g., no CLIENT-CERT, no x509 mappers, no certificate login flows)
- File: api/README.md — authentication is via Keycloak using username/password and JWT tokens; no mention of multifactor or certificate-based authentication
- Requirement: NOT SATISFIED — static configuration only enforces password authentication, not multifactor (CAC/Alt. Token) authentication

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
- Control requires that if group/shared accounts are used, individual authentication must precede group authentication.
- File: deploy/keycloak/dev-realm.json — all users are individually defined with unique usernames and emails; no evidence of group/shared accounts for authentication
- File: api/README.md — authentication is via individual Keycloak accounts; RBAC is enforced per user
- Requirement: NOT APPLICABLE — application does not use group or shared accounts for authentication

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
- Control requires replay-resistant authentication mechanisms (e.g., TLS 1.2+, Kerberos, IPSEC, SSH) for privileged accounts.
- File: deploy/keycloak/dev-realm.json — authentication is via Keycloak with password policy and JWT tokens; no explicit evidence of TLS enforcement ("sslRequired": "none")
- File: api/README.md — JWT tokens are used, signed with RS256, but no evidence of TLS enforcement for API endpoints
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak's internal config does not require SSL
- Requirement: PARTIALLY SATISFIED — JWT tokens are replay-resistant, and ALB uses HTTPS, but Keycloak realm does not require SSL ("sslRequired": "none"); cannot confirm end-to-end TLS enforcement for all privileged authentication traffic

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
- Control requires replay-resistant authentication mechanisms for nonprivileged accounts (TLS 1.2+, Kerberos, etc.).
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none" (SSL/TLS not enforced at the realm level)
- File: api/README.md — JWT-based authentication, but no explicit evidence of TLS enforcement for API endpoints
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but backend Keycloak config does not require SSL
- Requirement: PARTIALLY SATISFIED — JWT tokens are replay-resistant, and ALB uses HTTPS, but Keycloak realm does not require SSL; cannot confirm all authentication traffic is protected by TLS

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
- Control requires mutual authentication (client certificate) when endpoint device non-repudiation is required.
- File: deploy/keycloak/dev-realm.json — no evidence of mutual authentication or client certificate requirement (no CLIENT-CERT, no x509 mappers)
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS, but no evidence of mutual TLS (client certificate) enforcement
- Requirement: NOT SATISFIED — no static evidence of mutual authentication configuration

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
- Control requires authentication of all network-connected endpoint devices (SOA/web services context).
- File: README.md, api/README.md — application is an end-user interactive system (UI + API), not a service-oriented architecture exposing web services to remote devices
- No evidence of remote device/service consumer authentication flows
- Requirement: NOT APPLICABLE — application is not a SOA/web service provider to remote devices

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
- File: README.md, api/README.md — application is not a service-oriented application exposing endpoints to other systems; it is an end-user interactive system
- No evidence of mutual TLS configuration or SOA endpoints
- Requirement: NOT APPLICABLE — application is not a SOA system handling non-releasable data

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
- Control requires device identifiers to be disabled after 35 days of inactivity unless certificate-based authentication is used.
- File: README.md, api/README.md, deploy/keycloak/dev-realm.json — no evidence of device authentication or device account management; authentication is user-based
- Requirement: NOT APPLICABLE — application does not authenticate devices

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: security-documents/keycloak.json — identical password policy
- 15-character minimum enforced at the IdP (Keycloak) level
- Requirement: SATISFIED — password length policy is enforced via Keycloak realm configuration

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of an uppercase character requirement (e.g., no "upperCase" or similar policy)
- Requirement: NOT SATISFIED — password complexity does not require uppercase characters

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a lowercase character requirement (e.g., no "lowerCase" or similar policy)
- Requirement: NOT SATISFIED — password complexity does not require lowercase characters

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a numeric character requirement (e.g., no "digits" or similar policy)
- Requirement: NOT SATISFIED — password complexity does not require numeric characters

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a special character requirement (e.g., no "specialChars" or similar policy)
- Requirement: NOT SATISFIED — password complexity does not require special characters

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a policy enforcing minimum changed characters (e.g., no "forceExpiredPasswordChange" or similar)
- Requirement: NOT SATISFIED — password change policy does not enforce minimum changed characters

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
- Control requires passwords to be stored only as cryptographic representations (not plaintext or MD5).
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- Keycloak uses PBKDF2 with per-user salt and 27,500 iterations ("hashIterations(27500)")
- No use of MD5; passwords are never stored in plaintext
- Requirement: SATISFIED — cryptographic password storage enforced via Keycloak realm policy

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
- File: deploy/keycloak/dev-realm.json — "sslRequired": "none" (SSL/TLS not enforced at the realm level)
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak itself does not require SSL
- File: api/README.md — no explicit evidence that API endpoints require HTTPS
- Requirement: PARTIALLY SATISFIED — ALB uses HTTPS, but Keycloak realm does not require SSL; cannot confirm all password transmissions are cryptographically protected

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
- Control requires a minimum password lifetime of 24 hours.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a minimum password lifetime policy (e.g., no "passwordLifetime" or similar)
- Requirement: NOT SATISFIED — minimum password lifetime is not enforced

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
- Control requires a maximum password lifetime of 60 days.
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- No evidence of a maximum password lifetime policy (e.g., no "passwordExpiration" or similar)
- Requirement: NOT SATISFIED — maximum password lifetime is not enforced

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
- File: deploy/keycloak/dev-realm.json — "passwordPolicy": "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- Only "passwordHistory(3)" is enforced (prevents reuse of last 3 passwords)
- Requirement: NOT SATISFIED — password reuse is only prohibited for 3 generations, not 5

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
- Control requires support for temporary passwords and forced change on first logon.
- File: deploy/keycloak/dev-realm.json — user credentials include "temporary": false for all users; no evidence of temporary password enforcement or forced change on first use
- No evidence of a workflow for temporary passwords in static configuration
- Requirement: NOT SATISFIED — temporary password and forced change on first use not enforced

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
- File: deploy/keycloak/dev-realm.json — "resetPasswordAllowed": false
- File: deploy/keycloak/dev-realm.json — "editUsernameAllowed": false
- File: deploy/keycloak/dev-realm.json — passwordPolicy: "length(15) and notUsername and passwordHistory(3) and hashIterations(27500)"
- File: deploy/keycloak/dev-realm.json — users array: each user has their own credentials, and there is no evidence of cross-user password change capability
- File: security-documents/keycloak.json — mirrors the above settings
- The Keycloak admin console is the only interface for password resets, and only the user or an admin can change their own password
- Requirement: SATISFIED — Keycloak realm configuration prohibits users from changing or resetting other users' passwords

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
- The application uses Keycloak for authentication and session management. However, there is no explicit evidence in the provided static configuration or code that user sessions are forcibly terminated upon account deletion.
- File: deploy/keycloak/dev-realm.json — Keycloak manages users and sessions, but no explicit session termination policy is shown for account deletion
- File: api/README.md — API relies on Keycloak for authentication, but session termination on user deletion is not described
- Requirement: PARTIALLY SATISFIED — Keycloak supports session invalidation on user deletion, but no static configuration or code confirms this is enforced in this deployment

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
- The application uses Keycloak for authentication with OpenID Connect, which can support PKI-based authentication, but there is no explicit evidence of certificate path validation to a trust anchor in the provided configuration.
- File: deploy/keycloak/dev-realm.json — protocol: "openid-connect", but no explicit PKI/certificate validation settings
- File: api/README.md — JWT-based authentication via Keycloak, no mention of PKI/certificate path validation
- Requirement: PARTIALLY SATISFIED — OpenID Connect can support PKI, but no evidence of certificate path construction or validation to a trust anchor is present

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
- The application does not perform code signing or cryptographic operations requiring a private key at the application level. However, SSL/TLS private keys are referenced in the deployment bootstrap script and are retrieved from AWS Secrets Manager.
- File: deploy/aws/iris-stack.yaml — SSL_CERT and SSL_KEY are retrieved from AWS Secrets Manager and written to /opt/iris/ui/ssl/nginx.crt and /opt/iris/ui/ssl/nginx.key
- File: deploy/aws/iris-stack.yaml — chmod 644 for crt, chmod 600 for key (restricts key to owner)
- No evidence of application-level access controls for private keys, but OS-level permissions are set
- Requirement: PARTIALLY SATISFIED — Private key access is restricted at the OS level, but no application-level access control is shown

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
- The application uses Keycloak for authentication and authorization, mapping users to roles and groups. However, there is no explicit evidence of PKI-based authentication mapping certificate data to users/groups.
- File: deploy/keycloak/dev-realm.json — users have realmRoles and groups, but no certificate mapping is shown
- File: api/README.md — JWT-based authentication, no mention of certificate mapping
- Requirement: PARTIALLY SATISFIED — User/group mapping is present, but not specifically for PKI/certificate-based authentication

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
- No evidence of certificate revocation checking or local CRL cache implementation is present in the provided configuration or code.
- File: deploy/keycloak/dev-realm.json — no CRL or OCSP settings
- File: api/README.md — no mention of certificate revocation or CRL
- Requirement: NOT SATISFIED — No static evidence of CRL import or revocation checking

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
- The application uses Keycloak for authentication, and the custom Keycloak login theme is configured to obfuscate password input fields.
- File: deploy/keycloak/themes/README.md — login-username.ftl: Password field with eye icon toggle button, input type="password"
- File: deploy/keycloak/dev-realm.json — loginTheme: "iris"
- File: deploy/keycloak/themes/README.md — Passwords are not displayed as clear text; obfuscation is enforced by the theme
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
- The application uses cryptographic modules for JWT verification (Keycloak) and for S3/AWS operations, but there is no explicit evidence that only FIPS-approved cryptographic modules are used.
- File: api/README.md — JWT verification uses RS256 (asymmetric), but no FIPS module enforcement is shown
- File: deploy/aws/iris-stack.yaml — AWS services are used, which are FIPS 140-2 validated in GovCloud, but no explicit enforcement in application code
- Requirement: PARTIALLY SATISFIED — AWS GovCloud and Keycloak can be FIPS-compliant, but no explicit static enforcement is shown

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
- The application uses Keycloak for authentication, which uniquely identifies and authenticates all users, including non-organizational users if present.
- File: deploy/keycloak/dev-realm.json — users array: each user has a unique username and email
- File: api/README.md — All endpoints except /health require authentication via JWT token from Keycloak
- File: api/app/config.py — DISABLE_AUTH: bool = False (default)
- Requirement: SATISFIED — All users are uniquely identified and authenticated via Keycloak

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
- No evidence is present that the application is configured to accept PIV credentials from other federal agencies.
- File: deploy/keycloak/dev-realm.json — protocol: "openid-connect", but no PIV or external IdP configuration
- File: api/README.md — No mention of PIV or external credential acceptance
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
- No evidence is present that the application verifies PIV credentials from other federal agencies.
- File: deploy/keycloak/dev-realm.json — no PIV verification configuration
- File: api/README.md — no mention of PIV verification
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
- No evidence is present that the application is configured to accept FICAM-approved third-party credentials.
- File: deploy/keycloak/dev-realm.json — protocol: "openid-connect", but no external IdP or FICAM configuration
- File: api/README.md — no mention of FICAM or third-party credential acceptance
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
- No evidence is present that the application conforms to FICAM-issued profiles (e.g., SAML, OpenID with FICAM IdP).
- File: deploy/keycloak/dev-realm.json — protocol: "openid-connect", but no FICAM profile or IdP configuration
- File: api/README.md — no mention of FICAM profiles
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- The application does not provide non-local maintenance or diagnostic sessions as part of its functionality. There are no remote maintenance features or admin interfaces exposed for non-local maintenance.
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
- No static evidence of race condition testing or analysis tool configuration is present in the provided code or documentation.
- File: README.md — No mention of race condition testing or static analysis tools for race conditions
- File: api/README.md — No mention of race condition testing or code review results
- Requirement: NOT SATISFIED — No evidence of race condition testing or remediation

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
- Control requires: Application must terminate all network connections associated with a communications session at the end of the session.
- No explicit session termination logic or network connection teardown is visible in the provided FastAPI router code (api/app/process/router.py) or in the UI code (ui/src/components/video-player/video-player.tsx).
- The backend appears to be stateless REST API endpoints, with authentication handled via JWT tokens (see api/README.md: 'The API uses JWT-based authentication via Keycloak. Protected endpoints require a valid JWT token in the Authorization header.').
- No explicit session management or connection teardown is implemented in the provided code. Session management is delegated to Keycloak and the client browser.
- Requirement: PARTIALLY SATISFIED — The application appears to use stateless JWT authentication, which does not maintain server-side sessions, but there is no explicit evidence of network connection termination at session end. Full confirmation requires review of server and reverse proxy (e.g., Nginx) configuration and/or runtime observation.

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
- Control requires: Application must utilize FIPS-validated cryptographic modules when signing application components.
- No evidence of application component signing (e.g., code signing, artifact signing) is present in the provided source code, Dockerfiles, or deployment scripts.
- No references to cryptographic signing libraries, FIPS mode, or explicit signing operations are found in api/README.md, api/app/config.py, or any other provided files.
- No documentation of a code signing process or use of FIPS-validated modules for signing.
- Requirement: NOT SATISFIED — No evidence of code signing or FIPS-validated cryptographic modules for signing. If signing is not required per the security plan and risk acceptance is documented, this could be Not a Finding, but no such documentation is present.

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
- Control requires: Application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes (no MD5/SHA1).
- In vlm-testing/fpv_analyzer_rag.py: 'import hashlib' and 'file_hash = hashlib.md5(f.read()).hexdigest()' are used for document hash calculation.
- No evidence of FIPS-validated hash modules or configuration enforcing FIPS mode.
- No evidence of SHA-256 or stronger hashes being used for security-sensitive operations (only for document deduplication, not for security).
- Requirement: NOT SATISFIED — MD5 is used for document hash calculation, which is not FIPS-approved for security purposes. No evidence of FIPS-validated cryptographic modules for hash generation.

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
- Control requires: Application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.
- In api/app/config.py, cryptographic configuration is present for AWS S3, Bedrock, and Qdrant, but no explicit FIPS mode or FIPS-validated module enforcement is present.
- No evidence of FIPS mode being enabled for Python, OpenSSL, or any cryptographic library.
- No explicit cryptographic protection of data at rest or in transit is visible in the provided code (encryption at rest, TLS configuration, etc. not shown in static code).
- Requirement: NOT SATISFIED — No evidence of FIPS-validated cryptographic modules being used for protection of sensitive data. Full confirmation requires review of runtime environment and cloud service configuration.

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
- Control requires: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.
- No evidence of SAML assertion generation or SAML SessionIndex handling in any provided code (api/README.md, api/app/config.py, vlm-testing/fpv_analyzer_rag.py, etc.).
- Authentication is handled via Keycloak using OpenID Connect/JWT (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- Requirement: NOT APPLICABLE — Application does not implement SAML assertions.

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
- Control requires: The application user interface must be either physically or logically separated from data storage and management interfaces.
- The architecture described in README.md and api/README.md shows clear separation:
- UI (React, port 3000) is a separate service from API (FastAPI, port 5000).
- Database (PostgreSQL) and Keycloak (IAM) are separate containers/services.
- Qdrant (vector DB) is a separate service.
- Docker Compose and AWS CloudFormation (deploy/aws/iris-stack.yaml) define separate network security groups for ALB, EC2, and RDS, with RDS only accessible from EC2 SG.
- File: deploy/aws/iris-stack.yaml — RdsSecurityGroup allows Postgres 5432 only from EC2 SG, not from UI or public.
- File: README.md — 'The docker-compose configuration includes: ... db: PostgreSQL database (port 5432) for Keycloak and application data ... keycloak: Identity and access management service (port 8080) ... iris-api: Backend API service (FastAPI) running on port 5000 ... iris-ui: Frontend UI service (React + Nginx) running on port 3000.'
- Requirement: SATISFIED — UI, API, and data storage/management interfaces are logically separated at the network and service level.

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
- Control requires: The application must set the HTTPOnly flag on session cookies.
- Authentication is handled via Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit code for setting HTTPOnly on cookies is present in the provided FastAPI code (api/app/process/router.py) or UI code (ui/src/components/video-player/video-player.tsx).
- Keycloak is responsible for issuing authentication cookies/tokens. The default Keycloak configuration (not shown) typically sets HTTPOnly on session cookies, but this is not confirmed in the provided static artifacts.
- Requirement: PARTIALLY SATISFIED — No explicit evidence in application code; confirmation requires review of Keycloak configuration (e.g., deploy/keycloak/dev-realm.json) and/or runtime observation.

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
- Control requires: The application must set the secure flag on session cookies.
- Authentication is handled via Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit code for setting the Secure flag on cookies is present in the provided FastAPI or UI code.
- Keycloak is responsible for session cookies. The Secure flag is typically set when Keycloak is accessed over HTTPS, but this is not statically enforced in the provided configuration.
- File: deploy/keycloak/keycloak-init-dev.sh — sets 'sslRequired=none' for master realm, which disables enforcement of HTTPS for Keycloak (for development only).
- Requirement: NOT SATISFIED — Secure flag is not enforced in static configuration; Keycloak is configured for HTTP in development. Production configuration must be reviewed for compliance.

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
- Control requires: The application must not expose session IDs (must be protected in transit).
- Authentication is via JWT tokens from Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No explicit evidence of TLS/SSL enforcement for API or UI endpoints in the provided code or configuration.
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS (port 443) with ACM certificate, but Keycloak is set to allow HTTP (sslRequired=none) in deploy/keycloak/keycloak-init-dev.sh.
- Requirement: PARTIALLY SATISFIED — ALB enforces HTTPS for external access, but Keycloak is configured for HTTP in development. Full compliance requires confirmation that all session tokens/cookies are only transmitted over TLS in production.

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
- Control requires: The application must destroy the session ID value and/or cookie on logoff or browser close.
- No explicit session destruction logic is present in the provided FastAPI or UI code.
- Session management is handled by Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No evidence in the provided code that the application explicitly destroys session cookies or tokens on logoff or browser close.
- Requirement: PARTIALLY SATISFIED — Session management is delegated to Keycloak, but no explicit evidence of session destruction on logoff/browser close is present in static artifacts.

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
- Control requires: Applications must use system-generated session identifiers that protect against session fixation.
- Authentication is via JWT tokens issued by Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No evidence of custom session ID generation or session fixation protection in application code.
- Keycloak's default behavior is to generate new tokens on login, but this is not confirmed in the provided static configuration.
- Requirement: PARTIALLY SATISFIED — Session ID generation is delegated to Keycloak, but no explicit evidence of session fixation protection is present in static artifacts.

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
- Control requires: Applications must validate session identifiers.
- Authentication is via JWT tokens validated by FastAPI using Keycloak's JWKS endpoint (see api/README.md: 'The API verifies JWT tokens using Keycloak's public keys (JWKS) without requiring a client secret.').
- JWT validation is performed for all protected endpoints via dependency injection.
- File: api/README.md — 'The authentication happens before the endpoint function executes: ... Token is verified using Keycloak's public keys (JWKS) ... If authentication fails, a 401 Unauthorized is returned automatically.'
- Requirement: SATISFIED — JWT session identifiers are validated using Keycloak's JWKS, which is a standard and secure method for session validation.

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
- Control requires: Applications must not use URL embedded session IDs.
- Authentication is via JWT tokens in the Authorization header (see api/README.md: 'Protected endpoints require a valid JWT token in the Authorization header.').
- No evidence of session IDs being transmitted via URL parameters or URL rewriting in the provided FastAPI or UI code.
- Requirement: SATISFIED — Session IDs are not embedded in URLs; authentication is handled via headers.

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
- Control requires: The application must not re-use or recycle session IDs.
- Authentication is via JWT tokens issued by Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No evidence of session ID re-use or recycling in application code, but also no explicit evidence that new tokens are always issued on login/logout.
- Requirement: PARTIALLY SATISFIED — Session management is delegated to Keycloak, but no explicit evidence of session ID non-reuse is present in static artifacts.

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
- Control requires: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.
- Authentication/session IDs are managed by Keycloak (see api/README.md: 'The API uses JWT-based authentication via Keycloak.').
- No evidence in application code of custom session ID generation or configuration of FIPS-approved RNG for session IDs.
- No evidence that Keycloak is configured to use FIPS 140-2/3 RNG for session ID generation.
- Requirement: NOT SATISFIED — No evidence of FIPS-approved RNG for session ID generation in static artifacts.

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
- Control requires: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.
- File: deploy/aws/iris-stack.yaml — ALB is configured for HTTPS with ACM certificate (AcmCertificateArn parameter), but the source of the certificate is not specified in the provided static configuration.
- No evidence in application code or configuration that only DoD-approved CAs are trusted for TLS connections.
- Requirement: NOT SATISFIED — No evidence that only DoD-approved CAs are used for TLS/SSL. Confirmation requires review of ACM certificate source and trust store configuration.

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
- Control requires: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.
- No explicit error handling or secure-fail logic is present in the provided FastAPI router code (api/app/process/router.py) or in deployment scripts.
- No test plans or documentation describing secure failure behavior are present in the provided files.
- Requirement: NOT SATISFIED — No evidence of secure failover or secure state on failure in static artifacts.

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
- Control requires: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.
- No explicit logging configuration or error event logging is present in the provided FastAPI router code (api/app/process/router.py) or in deployment scripts.
- File: api/app/process/services/scene_summarization.py — uses 'from app.logging_config import get_logger', but the actual logging configuration is not included in the provided context.
- Requirement: PARTIALLY SATISFIED — Some logging is present in backend services, but no evidence of operational requirements documentation or explicit retention of failure diagnostic information.

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
- Control requires: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.
- Data is stored in AWS S3, PostgreSQL, and Qdrant (see api/app/config.py and README.md).
- No explicit evidence of encryption at rest or integrity protection for S3 buckets, PostgreSQL, or Qdrant in the provided static configuration.
- No evidence of DOD policy or data owner requirements being documented or enforced in code.
- Requirement: NOT SATISFIED — No evidence of confidentiality/integrity protection for stored data in static artifacts.

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
- Control requires: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.
- Data is stored in AWS S3, PostgreSQL, and Qdrant (see api/app/config.py and README.md).
- No explicit evidence of encryption at rest or cryptographic integrity mechanisms for stored data in the provided static configuration.
- No documentation of data owner encryption requirements or DOD policy enforcement.
- Requirement: NOT SATISFIED — No evidence of cryptographic mechanisms for data at rest in static artifacts.

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
- File: api/README.md — mentions S3 storage for video and document data, PostgreSQL for session metadata, and Qdrant for vector embeddings, but does not specify encryption at rest settings for these stores.
- File: deploy/aws/iris-stack.yaml — S3 bucket resource 'IrisS3Bucket' is created, but no explicit 'BucketEncryption' property is set; RDS instance 'PostgresDB' is created, but no explicit 'StorageEncrypted: true' or KMS key is specified; Qdrant is deployed as a container, with no evidence of encrypted storage configuration.
- File: api/app/process/services/scene_summarization.py — processed data is stored in S3, but encryption settings are not referenced in code.
- File: README.md — under 'Metadata Storage', 'Structured storage for poses, depth maps, and annotations' is mentioned, but no encryption details.
- Requirement: PARTIALLY SATISFIED — S3 and RDS are used, but encryption at rest is not explicitly enforced in the provided static configuration. No evidence of classified data processing or NSA-approved encryption. Further review of S3, RDS, and Qdrant encryption settings is required.

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
- The control requires isolation of security functions from non-security functions, typically via RBAC or ACLs.
- File: api/README.md — 'Keycloak provides enterprise-grade authentication and authorization', 'Role-Based Access Control (RBAC): Fine-grained permissions using atomic and composite roles', 'Admin endpoints (under /admin) require one of the following roles: role_maintainer, role_engineer, admin'.
- File: api/app/process/router.py — endpoints use FastAPI dependency injection for authentication, e.g., 'async def admin_endpoint(current_user: AdminUser, ...):', and 'All endpoints except /health require authentication'.
- File: README.md — 'Keycloak service includes: JWT tokens containing roles and groups for API authorization'.
- Requirement: SATISFIED — Security functions (admin endpoints, configuration) are protected by RBAC enforced via Keycloak and FastAPI dependency injection.

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
- File: README.md — The architecture is microservices-based, with each major component (API, UI, Keycloak, Qdrant, DB) running as a separate Docker container, as described under 'Docker Compose Architecture'.
- File: docker-compose.dev.yml (referenced in README.md) — Each service is defined as a separate container.
- Requirement: NOT APPLICABLE — The application is deployed as containerized microservices, each in its own isolated execution domain (Docker container), satisfying process isolation by architecture.

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
- The control requires prevention of unauthorized information transfer via shared system resources.
- File: README.md — 'Services are automatically networked and include health checks for reliability. The startup order is: db → keycloak → api → ui.'
- File: deploy/aws/iris-stack.yaml — Security groups restrict access: 'RdsSecurityGroup' allows Postgres (5432) only from EC2 SG; 'AlbSecurityGroup' allows 443 from 0.0.0.0/0 to ALB; S3 bucket 'IrisS3Bucket' has 'BlockPublicAcls: true', 'BlockPublicPolicy: true', 'IgnorePublicAcls: true', 'RestrictPublicBuckets: true'.
- File: pointcloud-project/docker-compose.yml — Postgres service exposes 5432, but is isolated within the Docker network.
- Requirement: SATISFIED — Application data is protected from unauthorized transfer via network segmentation, security groups, and S3 public access blocks.

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
- The control applies only to XML-based applications.
- File: README.md, api/README.md, api/app/process/router.py — No evidence of XML parsing, XML web services, or XML-based APIs. All APIs are RESTful and use JSON.
- Requirement: NOT APPLICABLE — The application does not utilize XML or XML-based services.

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
- The control requires the application to restrict the ability to launch DoS attacks against itself or others (e.g., throttling, rate limiting).
- File: api/app/process/router.py — No evidence of rate limiting, request throttling, or anti-DoS middleware in API endpoints.
- File: README.md — No mention of anti-DoS controls or protections in architecture or deployment.
- File: deploy/aws/iris-stack.yaml — ALB health checks and security groups are present, but no WAF or rate limiting is configured.
- Requirement: NOT SATISFIED — No static evidence of DoS protection mechanisms (rate limiting, throttling, WAF) in API or infrastructure configuration.

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
- The control requires redundancy mechanisms for high-availability systems.
- File: README.md — Under 'Deployment Configuration', mentions 'Robust connectivity for real-time video streaming and analysis', but does not explicitly state high-availability designation.
- File: deploy/aws/iris-stack.yaml — ALB (AppLoadBalancer), MultiAZ RDS ('MultiAZ: true'), and two subnets are defined, but EC2 instance 'IrisEC2Instance' is a single instance (no auto-scaling group or multiple app servers).
- File: docker-compose.dev.yml (referenced) — Single instance per service in local/dev.
- Requirement: PARTIALLY SATISFIED — Some redundancy (ALB, MultiAZ RDS), but no evidence of multiple app servers or full HA clustering for the application tier.

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
- The control requires confidentiality and integrity of transmitted information (e.g., TLS, IPsec).
- File: deploy/aws/iris-stack.yaml — ALB is configured with 'Scheme: internet-facing', 'Port: 443', 'Protocol: HTTPS', and requires an ACM certificate ('AcmCertificateArn'), indicating TLS is used for external access.
- File: README.md — 'Keycloak Admin Console: http://localhost:8080/admin', 'API Documentation: http://localhost:5000/docs', 'UI Dashboard: http://localhost:3000' — local/dev endpoints are HTTP, not HTTPS.
- File: api/README.md — API runs on HTTP (http://localhost:5000) in dev; no evidence of forced HTTPS for internal API/UI communication.
- Requirement: PARTIALLY SATISFIED — TLS is enforced at the ALB for external access, but internal service-to-service communication (API, UI, Keycloak) uses HTTP in dev/local. No evidence of mTLS or encryption for internal traffic.

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
- File: deploy/aws/iris-stack.yaml — ALB uses HTTPS with ACM certificate for external access.
- File: README.md, api/README.md — Internal API/UI/Keycloak endpoints use HTTP in dev/local; no evidence of message signing, digital signatures, or integrity checks beyond TLS at the ALB.
- File: api/app/process/services/scene_summarization.py — No evidence of message integrity mechanisms for S3 or Qdrant data transfers.
- Requirement: PARTIALLY SATISFIED — TLS is used for external access, but no evidence of cryptographic integrity mechanisms for internal or multi-hop transmissions.

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
- The control requires confidentiality and integrity during preparation for transmission (e.g., automatic HTTPS redirect, TLS by default).
- File: deploy/aws/iris-stack.yaml — ALB listener is HTTPS (443) with ACM certificate for external access.
- File: README.md — Internal endpoints (API, UI, Keycloak) are HTTP in dev/local; no evidence of forced HTTPS or automatic redirect for internal services.
- File: api/README.md — API runs on HTTP (http://localhost:5000) in dev.
- Requirement: PARTIALLY SATISFIED — TLS is enforced for external access via ALB, but internal communication is not forced to use TLS.

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
- The control requires confidentiality and integrity during reception (e.g., HTTPS/TLS for browser access and inter-tier communication).
- File: deploy/aws/iris-stack.yaml — ALB listener is HTTPS (443) with ACM certificate for external access.
- File: README.md — UI Dashboard and API Documentation are HTTP in dev/local; no evidence of forced HTTPS for browser access in dev.
- File: api/README.md — API runs on HTTP (http://localhost:5000) in dev.
- Requirement: PARTIALLY SATISFIED — TLS is enforced for external access via ALB, but browser access in dev/local is not forced to HTTPS.

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
- The control requires the application not to disclose unnecessary information to users (e.g., technical details in error messages).
- File: api/app/process/router.py — API endpoints raise HTTPException with details, e.g., 'detail=str(e)', 'detail=f"Failed to process video: {str(e)}"', which may leak internal error messages to clients.
- File: README.md — No mention of custom error pages or generic error handling.
- Requirement: NOT SATISFIED — API may disclose internal error details to users via HTTPException detail fields. No evidence of generic error pages or suppression of technical details.

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
- The control prohibits storage of sensitive information in hidden fields (typically applies to web forms).
- File: ui/src/components/*, ui/src/pages/* — No evidence of hidden fields storing sensitive data in the provided frontend code.
- File: README.md, api/README.md — Authentication is handled via Keycloak (OIDC), with JWT tokens; session management is server-side.
- Requirement: NOT APPLICABLE — No evidence of sensitive data stored in hidden fields; authentication/session data is managed via Keycloak and JWT.

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
- File: ui/src/components/*, ui/src/pages/* — React is used for UI, which provides auto-escaping by default, but no evidence of explicit input sanitization or output encoding for user-generated content.
- File: README.md — No mention of XSS testing or scan results.
- File: api/README.md — No mention of XSS protection in API responses.
- Requirement: PARTIALLY SATISFIED — React auto-escaping mitigates most XSS, but no evidence of vulnerability scan results or explicit input validation for all user input fields.

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
- File: ui/src/keycloak.ts, ui/src/components/* — No evidence of CSRF tokens or anti-CSRF middleware in frontend code.
- File: api/app/process/router.py — No evidence of CSRF protection in API endpoints.
- File: README.md, api/README.md — No mention of CSRF protection or scan results.
- Requirement: NOT SATISFIED — No static evidence of CSRF protection mechanisms (tokens, SameSite cookies, or anti-CSRF middleware) in frontend or backend code.

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
- File: api/app/process/router.py — No evidence of input sanitization or escaping for parameters that may be passed to shell commands (e.g., video processing, ffmpeg calls).
- File: api/app/process/services/scene_summarization.py — Uses ffmpeg and other system tools via Python, but no evidence of input sanitization for file paths or user-supplied data.
- File: README.md, api/README.md — No mention of command injection testing or scan results.
- Requirement: NOT SATISFIED — No static evidence of input sanitization or command injection protection for system-level operations.

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
- The control requires protection from canonical representation vulnerabilities (e.g., Unicode normalization, encoding assertions).
- File: api/app/process/router.py, api/app/process/services/scene_summarization.py — No evidence of explicit canonicalization or encoding assertions for user input or HTTP requests.
- File: README.md, api/README.md — No mention of encoding settings or canonicalization.
- Requirement: NOT SATISFIED — No static evidence of canonicalization or encoding enforcement for user input or HTTP requests.

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
- File: api/app/process/router.py — API endpoints accept request models (e.g., ProcessVideoRequest), but no evidence of explicit input validation beyond type checking.
- File: README.md, api/README.md — No mention of input validation frameworks or scan results.
- Requirement: PARTIALLY SATISFIED — FastAPI provides type validation for request bodies, but no evidence of comprehensive input validation (e.g., length, format, range checks) for all user input.

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
- File: api/app/process/router.py — No direct SQL queries are shown; database access is abstracted via DatabaseManager (referenced in bootstrap_pipeline.py), but no evidence of parameterized queries or ORM usage in the provided code.
- File: README.md, api/README.md — No mention of SQL injection testing or scan results.
- Requirement: PARTIALLY SATISFIED — No direct evidence of vulnerable SQL queries, but also no explicit evidence of parameterized queries or ORM protection. Scan results or code review of db access layer required.

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
- The control requires protection from XML-oriented attacks (e.g., XML injection, XXE, XPath injection).
- File: README.md, api/README.md, api/app/process/router.py — No evidence of XML parsing, XML web services, or XML-based APIs. All APIs are RESTful and use JSON.
- Requirement: NOT APPLICABLE — The application does not process XML or expose XML-based services.

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
- File: api/app/process/router.py — API endpoints use FastAPI schemas for request validation (e.g., 'request: ProcessVideoRequest', 'request: ProcessDocumentsRequest'), which provides type and structure validation but does not guarantee full sanitization against all input vulnerabilities.
- File: api/README.md — No explicit mention of input sanitization libraries or frameworks (e.g., pydantic custom validators, input escaping, or anti-XSS/SQLi measures).
- File: README.md — No documentation of secure coding practices or input validation SOPs.
- No static evidence of automated vulnerability scanning or scan results present in the provided files.
- Requirement: PARTIALLY SATISFIED — API uses FastAPI/Pydantic for basic input validation, but there is no evidence of comprehensive input sanitization, secure coding SOPs, or recent vulnerability scan results targeting input handling vulnerabilities.

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
- File: api/README.md — No documentation on error message sanitization or policy for error content.
- File: README.md — No mention of error message handling or user-facing error content policy.
- Requirement: PARTIALLY SATISFIED — Error messages are generally generic, but some may include exception details that could reveal sensitive information. No evidence of a systematic approach to error message sanitization.

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
- Control requires detailed error messages to be shown only to privileged users; non-privileged users should see only generic errors.
- File: api/app/process/router.py — All users receive the same HTTPException detail for errors (e.g., 'Failed to process video: {str(e)}'), with no role-based differentiation in error message content.
- File: api/README.md — No documentation of error message differentiation based on user privilege.
- File: README.md — No mention of error message privilege separation.
- Requirement: NOT SATISFIED — No evidence of error message content being restricted to privileged users; all users may receive the same error details.

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
- Control requires evidence that the application is not vulnerable to overflow attacks (buffer, stack, heap, integer, format string).
- File: api/app/process/router.py — Application is written in Python, which provides automatic bounds checking and is not susceptible to classic buffer/stack/heap overflows as in C/C++.
- File: README.md — No documentation of static analysis or code testing for overflow vulnerabilities.
- No static evidence of code scanning tools or test results for overflow vulnerabilities.
- Requirement: PARTIALLY SATISFIED — Python's memory safety mitigates most overflow risks, but there is no evidence of static analysis or code testing for overflows.

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
- File: api/README.md — Describes Docker-based deployment, which typically replaces containers on update, but does not explicitly state removal of old components.
- File: README.md — Docker Compose and containerization are used, but no explicit process for removing old images or containers is documented.
- No scripts or automation for cleaning up old versions are present in the provided files.
- Requirement: PARTIALLY SATISFIED — Docker-based deployment reduces risk of old components persisting, but there is no explicit evidence of removal of old versions after updates.

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
- File: .github/workflows/deploy-eks-ironbank.yml — CI/CD pipeline builds and deploys images, but there is no explicit evidence of a process for checking for upstream security updates or patching dependencies.
- File: api/README.md — No mention of patch management or update frequency.
- File: README.md — No documentation of patching process or update cadence.
- Requirement: PARTIALLY SATISFIED — Automated builds and deployments are present, but no evidence of a process for tracking and applying security patches.

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application performs organization-defined security functions and verifies their correct operation.
- File: api/app/process/router.py — No evidence of security function self-testing or verification routines.
- File: README.md — No mention of security function testing.
- File: api/README.md — No mention of security function testing.
- Requirement: NOT APPLICABLE — Application does not implement organization-defined security functions requiring verification.

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application performs security function testing on startup, restart, or privileged command.
- File: api/app/process/router.py — No evidence of security function self-testing or verification routines.
- File: README.md — No mention of security function testing.
- File: api/README.md — No mention of security function testing.
- Requirement: NOT APPLICABLE — Application does not implement security function testing.

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control applies only if the application performs security function testing and must notify ISSO/ISSM of failures.
- File: api/app/process/router.py — No evidence of security function self-testing or notification routines.
- File: README.md — No mention of security function testing or notification.
- File: api/README.md — No mention of security function testing or notification.
- Requirement: NOT APPLICABLE — Application does not implement security function testing or notification.

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
- Control applies to Category 1A mobile code (e.g., ActiveX, Java applets, Flash) provided by the application for client consumption.
- File: README.md, api/README.md, ui/src/components/video-player/video-player.tsx — Application is a web-based system using React (TypeScript) and FastAPI (Python). No evidence of unsigned mobile code (ActiveX, Java applets, Flash, etc.) being delivered to clients.
- Requirement: NOT APPLICABLE — Application does not provide or execute Category 1A mobile code.

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
- File: api/README.md — Describes Keycloak integration for authentication and RBAC, but does not document the process for account creation, termination, or handling inactive/suspended/terminated accounts.
- File: README.md — Mentions Keycloak for user management, but no evidence of a documented process for account lifecycle management.
- No evidence of automated deactivation/removal of inactive or terminated accounts.
- Requirement: PARTIALLY SATISFIED — Keycloak provides account management capabilities, but there is no evidence of a documented process or timely removal of inactive/terminated accounts.

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
- File: deploy/aws/iris-stack.yaml — Defines VPC, subnets, security groups, and separates ALB (web), EC2 (app), and RDS (database) with distinct security groups and subnets. However, there is no explicit documentation or diagram confirming DMZ placement or enforcement of DoD DMZ segmentation requirements.
- File: README.md — Mentions multi-tier architecture but does not specify network segmentation details for DMZ compliance.
- Requirement: PARTIALLY SATISFIED — Infrastructure-as-code suggests tiered separation, but there is no explicit evidence of DMZ compliance or network diagrams.

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
- File: api/README.md, README.md — No mention of audit log retention policy, configuration, or implementation.
- No evidence of log retention settings or scripts for archiving logs.
- Requirement: NOT SATISFIED — No evidence of audit trail retention for required duration.

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
- File: api/README.md, README.md — No documentation of audit log review schedule or process.
- No evidence of log review records or procedures.
- Requirement: NOT SATISFIED — No evidence of periodic audit log review process or documentation.

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
- Control requires a policy and SOP for reporting suspected IA violations.
- File: api/README.md, README.md — No mention of IA policy violation reporting procedures or SOPs.
- No evidence of reporting policy or documentation.
- Requirement: NOT SATISFIED — No evidence of IA violation reporting policy or process.

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
- Control requires evidence of active vulnerability testing and test results.
- File: .github/workflows/deploy-eks-ironbank.yml — CI/CD pipeline automates deployment but does not include steps for vulnerability scanning or fuzz testing.
- File: api/README.md, README.md — No mention of vulnerability testing procedures, tools, or results.
- Requirement: NOT SATISFIED — No evidence of active vulnerability or fuzz testing.

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
- File: api/README.md, README.md — No execution flow diagrams or design documentation addressing deadlock or recursion in web services.
- No evidence of deadlock mitigation in code or documentation.
- Requirement: NOT SATISFIED — No evidence of deadlock/recursion mitigation documentation for web services.

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
- File: api/README.md — Documents that environment files ('.env', '.env.example') and configuration files are in the 'api/' directory, while user data (videos, processed data) is stored in S3 buckets ('iris-video/raw/', 'iris-video/clips/').
- File: deploy/aws/iris-stack.yaml — S3 buckets are created for raw and processed data, separate from application code and configuration.
- However, no explicit evidence of file permissions or enforcement of separation at the OS or container level is provided.
- Requirement: PARTIALLY SATISFIED — Logical separation is present, but no evidence of enforced file permissions or OS-level separation.

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
- Control requires configuration according to DoD STIG/NSA guide or, if unavailable, according to best practices, independent testing, or vendor guidance.
- File: api/README.md, README.md — No evidence of following DoD STIG, NSA guide, or alternative hardening guidance for application components (e.g., FastAPI, Keycloak, Qdrant, Docker, Kubernetes).
- No documentation of security configuration benchmarks or lock down guides.
- Requirement: NOT SATISFIED — No evidence of STIG/NSA or alternative security configuration guidance being followed.

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
- File: deploy/aws/iris-stack.yaml — Defines ports for ALB (443), EC2 (22, 443, 3000), and RDS (5432) in security groups, but does not document submission to PPSM or compliance with DoD Ports and Protocols guidance.
- File: README.md, api/README.md — No documentation of port/protocol/service approval or PPSM submission.
- Requirement: PARTIALLY SATISFIED — Ports and protocols are defined in infrastructure code, but no evidence of PPSM submission or compliance documentation.

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
- The control requires evidence that the application and its ports are registered in the DoD Ports and Protocols Database.
- No static artifact in the provided files (README.md, api/README.md, CloudFormation, or CI/CD workflows) references DoD Ports and Protocols Database registration or a registration identifier.
- No documentation or comments indicate registration status or port registration.
- Requirement: PARTIALLY SATISFIED — Application ports are documented in deployment files (e.g., 443, 8080, 3000, 5000, 6333), but there is no evidence of registration in the DoD Ports and Protocols Database.

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
- The control requires evidence that the Configuration Management (CM) repository is patched and STIG compliant.
- File: .github/workflows/deploy-eks.yml — CI/CD workflow automates deployment, but does not reference patch management or STIG compliance for the CM repository itself.
- File: README.md — No mention of patch management or STIG compliance for the repository or its hosting system.
- No documentation or scripts reference patching or STIG application to the CM system (e.g., GitHub, GitLab, or other repository host).
- Requirement: NOT SATISFIED — No evidence of patch management or STIG compliance for the CM repository system.

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
- The control requires evidence that access privileges to the CM repository are reviewed every three months.
- No static artifact in the provided files (README.md, api/README.md, CI/CD workflows) documents a process or schedule for reviewing repository access privileges.
- No documentation, comments, or scripts reference periodic access reviews or audit logs for the CM repository.
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
- The control requires a Software Configuration Management (SCM) plan describing configuration control, change management, roles, tools, and audit mechanisms.
- File: README.md — Describes architecture, deployment, and testing, but does not constitute a formal SCM plan.
- No file named 'SCM plan', 'configuration management plan', or similar is present in the manifest or referenced in documentation.
- No documentation of roles, responsibilities, change tracking, or audit mechanisms for configuration management.
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
- The control requires evidence of a Configuration Control Board (CCB) that meets at least every release cycle, with charter documentation or meeting records.
- No static artifact in the provided files (README.md, api/README.md, CI/CD workflows) references a CCB, its membership, charter, or meeting schedule.
- No documentation or comments indicate the existence or operation of a CCB.
- Requirement: NOT SATISFIED — No evidence of a Configuration Control Board or its activities.

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
- The control requires evidence that the application is compatible with and ready for IPv6 networks per DoD standards.
- File: README.md — No mention of IPv6 support or testing.
- File: api/README.md — No mention of IPv6 support.
- No configuration files or deployment scripts reference IPv6 addresses, dual-stack networking, or IPv6-specific settings.
- Requirement: NOT SATISFIED — No evidence of IPv6 compatibility or readiness.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires that critical/HA applications are not hosted on general purpose machines with other less critical applications.
- File: deploy/aws/iris-stack.yaml — Defines a dedicated EC2 instance for the IRIS stack, but does not specify whether other applications are deployed on the same instance.
- No documentation or comments indicate server exclusivity for criticality separation.
- Requirement: PARTIALLY SATISFIED — Dedicated infrastructure is defined, but no explicit evidence that the instance is not shared with non-critical applications.

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
- The control requires a contingency plan based on the application's availability requirements.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml) constitutes a contingency plan or describes contingency procedures.
- No documentation or comments reference contingency planning, alternate site transfer, or operational continuity.
- Requirement: NOT SATISFIED — No contingency plan found.

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
- The control requires a disaster recovery plan with secure and verifiable recovery procedures.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml) constitutes a disaster recovery plan or describes recovery procedures.
- No documentation or comments reference disaster recovery, trusted recovery, or related procedures.
- Requirement: NOT SATISFIED — No disaster recovery plan found.

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
- The control requires documented backup procedures at intervals based on risk level, with offsite storage and testing.
- File: deploy/aws/iris-stack.yaml — RDS resource includes 'BackupRetentionPeriod: 7', indicating automated database backups for 7 days.
- No documentation or scripts describe backup procedures for application data, source code, or other assets.
- No evidence of backup testing, offsite storage, or recovery media procedures.
- Requirement: PARTIALLY SATISFIED — RDS backup retention is configured, but no comprehensive backup procedures or testing documentation found.

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
- The control requires that backup copies of application software or source code are stored in a fire-rated container or offsite.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml) documents offsite or fire-rated storage of backups.
- No documentation or comments reference backup storage location or method for source code or application software.
- Requirement: NOT SATISFIED — No evidence of offsite or fire-rated backup storage.

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
- The control requires procedures to assure physical and technical protection of backup and restoration assets.
- No static artifact in the provided files (README.md, api/README.md, deploy/aws/iris-stack.yaml) documents procedures for protecting backup and restoration assets.
- No documentation or comments reference protection of backup media, directories, or restoration equipment.
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
- The control requires encryption for key exchange using FIPS-140-2 validated cryptographic modules.
- File: api/README.md — Describes JWT-based authentication using Keycloak with RS256 (asymmetric) algorithm, but does not mention key exchange protocols or FIPS-140-2 validation.
- No configuration or code references TLS settings, key exchange protocols, or FIPS-validated modules for key exchange.
- Requirement: PARTIALLY SATISFIED — JWT authentication uses asymmetric crypto, but no evidence of FIPS-140-2 validation or explicit key exchange encryption.

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
- The control requires that the application does not contain embedded authentication data (e.g., passwords, certificates) in code or configuration files.
- File: pointcloud-project/docker-compose.yml — Contains 'POSTGRES_PASSWORD: secure_password_here' (literal password in plaintext).
- File: api/.env.example — Contains placeholders for AWS credentials (e.g., 'AWS_ACCESS_KEY_ID=your_access_key_id'), but not actual secrets.
- File: deploy/aws/iris-stack.yaml — Uses AWS Secrets Manager for secrets, but some scripts reference plaintext variables.
- Requirement: NOT SATISFIED — Embedded plaintext password found in pointcloud-project/docker-compose.yml.

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
- The control requires the application to have the capability to mark sensitive/classified output when required.
- No static artifact in the provided files (README.md, api/README.md, ui/README.md, or UI code) describes or implements output marking for sensitive/classified data.
- No documentation or code references classification guides, output markings, or marking procedures.
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
- The control requires test plans and procedures to be created and executed prior to each release or patch update.
- File: README.md — Section 'End-to-End Testing' describes Playwright E2E tests and accessibility checks, but does not reference formal test plans or procedures per release.
- File: api/README.md — Describes unit tests and code quality checks, but no evidence of versioned test plans or release-specific procedures/results.
- Requirement: PARTIALLY SATISFIED — Automated tests exist, but no formal test plans or execution records per release.

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
- The control requires application files to be cryptographically hashed prior to deployment to DoD operational networks.
- No static artifact in the provided files (README.md, api/README.md, CI/CD workflows) documents a cryptographic hash validation process for application files prior to deployment.
- No scripts or documentation reference 'sha256sum', 'Get-FileHash', or similar hash validation steps.
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
- The control requires at least one tester to be designated for security testing in addition to functional testing.
- File: README.md — Describes E2E and accessibility testing, but does not designate personnel for security testing.
- No documentation or comments reference designated security testers or roles.
- Requirement: NOT SATISFIED — No evidence of designated security testing personnel.

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
- The control requires annual execution of test procedures to ensure secure system initialization, shutdown, and aborts.
- No static artifact in the provided files (README.md, api/README.md, CI/CD workflows) documents annual security state testing procedures or results.
- No documentation or comments reference annual testing, test dates, or secure state verification on startup/shutdown/abort.
- Requirement: NOT SATISFIED — No evidence of annual secure state testing procedures.

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
- The control requires an application code review to be performed and documented.
- File: README.md — No mention of code review process or results.
- File: api/README.md — Describes code quality checks ('ruff check .') and unit tests, but does not reference code review procedures or reports.
- No documentation or comments reference code review tools, reports, or remediation of security flaws.
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
- File: api/README.md — 'To run unit tests with code coverage, run the following:\n\n```sh\ncoverage run -m pytest && coverage html\n```'
- File: ui/README.md — 'Ensure to review the coverage directory for code coverage details.\n\n```sh\nnpm run test:coverage\n```'
- File: e2e/README.md — 'To make sure your changes do not break any unit tests, run the following:\n\n```sh\nnpm run test\n```\nEnsure to review the coverage directory for code coverage details.'
- The documentation provides explicit instructions for generating and reviewing code coverage statistics for both backend (Python) and frontend (JavaScript/TypeScript) components using standard tools (coverage.py, npm test:coverage).
- Requirement: SATISFIED — Code coverage statistics are maintained and documented for each release.

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
- File: README.md — No explicit mention of a defect tracking system or configuration management repository for code review flaws.
- File: api/README.md — No reference to issue tracking, bug tracking, or integration with a defect tracking system.
- File: ui/README.md — No reference to defect tracking or code review flaw capture.
- File: e2e/README.md — No reference to defect tracking.
- Partial evidence: The repository contains comprehensive documentation and testing instructions, but there is no static evidence of a defect tracking system or process for capturing code review flaws in a configuration management repository.
- Requirement: PARTIALLY SATISFIED — Testing and code quality checks are documented, but there is no evidence of a defect tracking system for code review flaws.

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
- File: README.md — No explicit mention of an IA (Information Assurance) impact assessment or CCB (Change Control Board) process documentation.
- File: api/README.md — No reference to IA impact analysis or accreditation assessment prior to changes.
- File: deploy/aws/iris-stack.yaml — Contains infrastructure-as-code for deployment, but no documentation of IA/accreditation review process.
- No static evidence of a formal process for IA/accreditation impact assessment prior to implementing changes.
- Requirement: NOT SATISFIED — No evidence of IA impact analysis or accreditation review process.

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
- File: README.md — No explicit mention of project plan integration for security flaws.
- File: api/README.md — No reference to project plan or process for integrating security flaws.
- File: ui/README.md — No mention of project plan or security flaw tracking.
- No static evidence of a project plan or process for tracking/addressing security flaws.
- Requirement: NOT SATISFIED — No evidence of security flaw integration into a project plan.

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
- File: README.md — No reference to a coding standards document or process.
- File: api/README.md — No mention of coding standards documentation or enforcement.
- File: ui/README.md — No mention of coding standards documentation.
- File: e2e/README.md — No mention of coding standards documentation.
- No static evidence of a coding standards document or process being followed by the development team.
- Requirement: NOT SATISFIED — No evidence of coding standards documentation or process.

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
- File: README.md — Contains a detailed system overview, architecture, and technical stack, but does not explicitly identify all required elements (external interfaces, user roles, security requirements, incident response plan, etc.) as a formal Design Document.
- No file named 'Design Document' or equivalent found in the manifest or documentation.
- Requirement: PARTIALLY SATISFIED — System overview and architecture are documented, but a formal, complete Design Document as described in the control is not present.

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
- File: README.md — No explicit mention of a threat model document or its review/update process.
- No file named 'threat model' or equivalent found in the manifest or documentation.
- Requirement: NOT SATISFIED — No evidence of a documented threat model or review process.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application must not be subject to error handling vulnerabilities.
- File: api/README.md — Documents testing procedures, but does not reference static code analysis or security scan results for error handling vulnerabilities.
- File: ui/README.md — Documents unit testing and code quality checks, but no evidence of error handling vulnerability testing or remediation.
- No static evidence of security scan results or error handling vulnerability remediation.
- Requirement: PARTIALLY SATISFIED — Testing is documented, but no evidence of error handling vulnerability testing or remediation.

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
- File: README.md — No explicit mention of an application incident response plan or process for tracking/confirming vulnerabilities and notifying users.
- No file named 'incident response plan' or equivalent found in the manifest or documentation.
- Requirement: NOT SATISFIED — No evidence of an application incident response plan.

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
- File: README.md — Lists core technologies and components, but does not provide explicit support status or proof of support for all software components.
- File: api/README.md — Lists dependencies and setup, but no explicit vendor support status.
- File: deploy/aws/iris-stack.yaml — References AMI and package versions, but no explicit support status.
- Requirement: PARTIALLY SATISFIED — Components are documented, but no evidence of support status or proof of support.

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
- File: README.md — No mention of decommissioning procedures or maintenance contract tracking.
- File: deploy/aws/iris-stack.yaml — No evidence of maintenance contract tracking or decommissioning procedures.
- Requirement: NOT SATISFIED — No evidence of decommissioning procedures or maintenance contract tracking.

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
- File: README.md — No mention of user notification procedures for decommissioning.
- File: ui/README.md — No mention of decommissioning notification procedures.
- Requirement: NOT SATISFIED — No evidence of user notification procedures for decommissioning.

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
- File: README.md — Documents Keycloak as the IAM solution and notes default admin credentials for development only, but does not provide evidence of disabling unnecessary built-in accounts in production.
- File: deploy/keycloak/themes/README.md — Documents custom Keycloak theme, but not account management.
- File: api/README.md — Documents Keycloak integration and default users for development, but no evidence of disabling unnecessary built-in accounts in production.
- Requirement: PARTIALLY SATISFIED — Default accounts are documented for development, but no evidence of disabling unnecessary built-in accounts in production.

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
- File: README.md — Documents default admin credentials for Keycloak (Username: 'admin', Password: 'TestPassword123!') for development only, with a note: 'Change default credentials before deploying to production environments.'
- File: api/README.md — Documents default users and passwords for development, but no evidence of password change enforcement in production.
- Requirement: PARTIALLY SATISFIED — Default passwords are documented for development, but no evidence of enforced password change for production deployments.

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
- File: README.md — Documents deployment configuration, environment variables, and service architecture, but does not provide a formal Application Configuration Guide covering all required topics (encryption, PKI, password settings, auditing, backup, disaster recovery, etc.).
- File: api/README.md — Documents environment configuration and setup, but not as a formal configuration guide.
- Requirement: PARTIALLY SATISFIED — Configuration details are present in documentation, but a formal Application Configuration Guide is not included.

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
- File: README.md — No indication that the application processes or stores classified information.
- File: api/README.md — No reference to classified data or classification guides.
- Requirement: NOT APPLICABLE — The application does not process classified information.

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
- File: README.md — No mention of mobile code types or their categorization.
- File: api/README.md — No mention of mobile code.
- File: ui/README.md — No mention of mobile code.
- Requirement: NOT SATISFIED — No evidence of mobile code review or documentation.

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
- File: README.md — Documents PostgreSQL usage, but no mention of database export sanitization procedures.
- File: api/README.md — Documents database usage, but no mention of export sanitization.
- Requirement: NOT SATISFIED — No evidence of database export sanitization procedures.

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
- File: README.md — No explicit mention of DoS threat modeling or mitigation.
- No threat model document or DoS mitigation evidence found in the manifest or documentation.
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
- File: README.md — No mention of resource monitoring or alerting mechanisms.
- File: deploy/aws/iris-stack.yaml — No evidence of automated alerting for low resource conditions.
- Requirement: NOT SATISFIED — No evidence of resource monitoring or alerting.

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
- Control requires at least one application administrator registered to receive update/security alerts for all application components.
- File: deploy/keycloak/dev-realm.json — users array includes an admin user:
- "username": "admin", "email": "admin@example.com", "realmRoles": ["admin", "user"]
- File: api/README.md — No evidence of automated update/security alert registration for administrators (e.g., no mention of mailing lists, notification hooks, or alerting integrations).
- No static evidence in provided files of a mechanism for registering administrators to receive update notifications for custom-developed software, libraries, or third-party tools.
- Requirement: PARTIALLY SATISFIED — Administrator account exists, but no evidence of registration for update/security notifications.

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
- Control requires the application to provide notifications or alerts when product updates or security patches are available, including a description, risk summary, mitigations, and how to obtain the update.
- File: api/README.md — No mention of any notification process, alerting mechanism, or update distribution system for security patches or product updates.
- No evidence in code, configuration, or documentation of any process for notifying administrators or users about available updates or patches.
- No static artifacts (e.g., email hooks, webhook integrations, notification services) found in the provided files.
- Requirement: NOT SATISFIED — No evidence of an application update/patch notification process.

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
- Static repository review completed on 2026-04-30.
- Control requires that connections between the DoD enclave and the Internet/public networks require a DMZ if the application is publicly accessible.
- File: deploy/aws/iris-stack.yaml — Application Load Balancer (ALB) is defined as 'internet-facing' and sits in public subnets, with EC2 instances in the same VPC. Security groups restrict access to required ports.
- The ALB acts as a DMZ boundary, terminating HTTPS and forwarding to internal EC2 instances. RDS is not publicly accessible and only accessible from EC2 security group.
- The architecture implements a DMZ via the ALB, which is standard AWS best practice for public-facing applications.
- Requirement: SATISFIED — DMZ is enforced via AWS ALB in public subnets, with backend resources protected by security groups.

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
- Control requires the application to generate audit records when concurrent logons from different workstations occur, including source IP addresses.
- File: api/app/process/router.py — No evidence of audit logging for concurrent logons or capturing source IP addresses in logs.
- File: api/README.md — Authentication is handled via Keycloak (JWT), but no mention of audit logging for concurrent logons or IP tracking.
- File: deploy/keycloak/dev-realm.json — No evidence of audit log configuration for concurrent logons.
- No static evidence of log storage, log format, or log analysis for concurrent logon detection in provided files.
- Requirement: NOT SATISFIED — No evidence of audit records for concurrent logons from different workstations.

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
- No evidence in any provided file (README.md, api/README.md, deploy/keycloak/dev-realm.json, etc.) of security training records, class rosters, or course completion certificates.
- No documentation, comments, or references to security training processes or requirements for development personnel.
- Requirement: NOT SATISFIED — No evidence of annual security training for relevant personnel.

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
- Control requires NSA-approved cryptography for classified information. If the application does not process classified data, the requirement is not applicable.
- File: api/README.md — No mention of processing classified data; describes use cases for Air Force fuel tank maintenance, but no indication of classified/SAMI data handling.
- File: api/app/config.py — Cryptography settings reference NIST/FIPS-validated algorithms for general data protection, but no indication of classified data handling.
- File: deploy/keycloak/dev-realm.json — No evidence of classified data processing or storage.
- Requirement: NOT APPLICABLE — Application does not process classified information per available documentation.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
