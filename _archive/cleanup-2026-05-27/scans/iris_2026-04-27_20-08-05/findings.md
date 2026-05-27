# iris STIG Findings Assessment

Total STIGs Assessed: 286

| Status | Count |
|---|---|
| Open | 262 |
| Not a Finding | 3 |
| Not Applicable | 21 |

### 1. APSC-DV-000010 | SV-222387r960735

- Rule ID: SV-222387r960735
- Severity: medium
- Rule Title: The application must provide a capability to limit the number of logon sessions per user.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to specify the number of logon sessions that are allowed per user.

---

### 2. APSC-DV-000060 | SV-222388r1043182

- Rule ID: SV-222388r1043182
- Severity: medium
- Rule Title: The application must clear temporary storage and cookies when the session is terminated.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to clear sensitive data from cookies and local storage when the user logs out of the application.

---

### 3. APSC-DV-000070 | SV-222389r1043182

- Rule ID: SV-222389r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the non-privileged user session and log off non-privileged users after a 15 minute idle time period has elapsed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to terminate the non-privileged users session after 15 minutes of inactivity.

---

### 4. APSC-DV-000080 | SV-222390r1043182

- Rule ID: SV-222390r1043182
- Severity: medium
- Rule Title: The application must automatically terminate the admin user session and log off admin users after a 10 minute idle time period is exceeded.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to terminate the admin users session after 10 minutes of inactivity.

---

### 5. APSC-DV-000090 | SV-222391r961224

- Rule ID: SV-222391r961224
- Severity: medium
- Rule Title: Applications requiring user access authentication must provide a logoff capability for user initiated communication session.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to provide all users with the capability to manually terminate their application session.

---

### 6. APSC-DV-000100 | SV-222392r961227

- Rule ID: SV-222392r961227
- Severity: low
- Rule Title: The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.

---

### 7. APSC-DV-000110 | SV-222393r1136904

- Rule ID: SV-222393r1136904
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of data marking or security attribute association with stored information was found in the provided codebase.
- No schema or code references to classified, CUI, or other data marking fields.

Remediation:
Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.

---

### 8. APSC-DV-000120 | SV-222394r1136906

- Rule ID: SV-222394r1136906
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of data marking or security attribute association with information in process was found in the provided codebase.
- No code references to marking propagation during data processing.

Remediation:
Design and configure the application to retain the data marking when processing data.

---

### 9. APSC-DV-000130 | SV-222395r1136908

- Rule ID: SV-222395r1136908
- Severity: medium
- Rule Title: The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of data marking or security attribute association with information in transmission was found in the provided codebase.
- No code references to marking propagation during data transmission.

Remediation:
Design and configure the application to retain the data marking when transmitting data.

---

### 10. APSC-DV-000160 | SV-222396r960759

- Rule ID: SV-222396r960759
- Severity: medium
- Rule Title: The application must implement DoD-approved encryption to protect the confidentiality of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses AWS S3 and Bedrock clients, but repository artifacts do not confirm enforcement of DoD-approved encryption (e.g., TLS) for all remote access sessions.
- No explicit TLS enforcement or certificate validation code is present; requires runtime and infrastructure validation.

Remediation:
Design and configure applications to use TLS encryption to protect the confidentiality of remote access sessions.

---

### 11. APSC-DV-000170 | SV-222397r960762

- Rule ID: SV-222397r960762
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to protect the integrity of remote access sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses AWS S3 and Bedrock clients, but repository artifacts do not confirm cryptographic integrity protection (e.g., TLS) for all remote access sessions.
- No explicit TLS enforcement or certificate validation code is present; requires runtime and infrastructure validation.

Remediation:
Design and configure applications to use TLS encryption to protect the integrity of remote access sessions.

---

### 12. APSC-DV-000180 | SV-222398r960762

- Rule ID: SV-222398r960762
- Severity: medium
- Rule Title: Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SOAP message generation or WS-Security/SAML assertion handling is present in the codebase.
- Application does not utilize SOAP or WS-Security protocols.

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
- Static repository review completed on 2026-04-27.
- No WS-Security token or SOAP message handling is present in the codebase.
- Application does not utilize WS-Security protocols.

Remediation:
Design and configure applications using WS-Security messages to use time stamps with creation and expiration times and sequence numbers.

---

### 14. APSC-DV-000200 | SV-222400r960759

- Rule ID: SV-222400r960759
- Severity: high
- Rule Title: Validity periods must be verified on all application messages using WS-Security or SAML assertions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No WS-Security or SAML assertion handling is present in the codebase.
- Application does not utilize WS-Security or SAML assertions.

Remediation:
Design and configure the application to use validity periods, ensure validity periods are verified on all WS-Security token profiles and SAML Assertions.

---

### 15. APSC-DV-000210 | SV-222401r960759

- Rule ID: SV-222401r960759
- Severity: medium
- Rule Title: The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion handling is present in the codebase.
- Application does not utilize SAML assertions.

Remediation:
Design and configure each SAML assertion authority to use unique assertion identifiers.

---

### 16. APSC-DV-000220 | SV-222402r960759

- Rule ID: SV-222402r960759
- Severity: medium
- Rule Title: The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No WS-Security token or SAML assertion handling is present in the codebase.
- Application does not utilize WS-Security tokens.

Remediation:
Encrypt assertions or use equivalent confidentiality when sensitive assertion data is passed through an intermediary.

---

### 17. APSC-DV-000230 | SV-222403r960759

- Rule ID: SV-222403r960759
- Severity: high
- Rule Title: The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion or SOAP message handling is present in the codebase.
- Application does not utilize SAML assertions.

Remediation:
Design and configure the application to use the <NotOnOrAfter> condition when using the <SubjectConfirmation> element in a SAML assertion.

---

### 18. APSC-DV-000240 | SV-222404r960759

- Rule ID: SV-222404r960759
- Severity: high
- Rule Title: The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion or SOAP message handling is present in the codebase.
- Application does not utilize SAML assertions.

Remediation:
Design and configure the application to implement the use of the <NotBefore> and <NotOnOrAfter> or <OneTimeUse> when using the <Conditions> element in a SAML assertion.

---

### 19. APSC-DV-000250 | SV-222405r960759

- Rule ID: SV-222405r960759
- Severity: medium
- Rule Title: The application must ensure if a OneTimeUse element is used in an assertion, there is only one of the same used in the Conditions element portion of an assertion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion or SOAP message handling is present in the codebase.
- Application does not utilize SAML assertions.

Remediation:
When using OneTimeUse elements in a SAML assertion only allow one, OneTimeUse element to be used in the conditions element of a SAML assertion.

---

### 20. APSC-DV-000260 | SV-222406r960759

- Rule ID: SV-222406r960759
- Severity: medium
- Rule Title: The application must ensure messages are encrypted when the SessionIndex is tied to privacy data.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion or SOAP message handling is present in the codebase.
- Application does not utilize SAML assertions.

Remediation:
Encrypt messages when the SessionIndex is tied to privacy data.

---

### 21. APSC-DV-000280 | SV-222407r1043176

- Rule ID: SV-222407r1043176
- Severity: medium
- Rule Title: The application must provide automated mechanisms for supporting account management functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Use automated processes and mechanisms for account management functions.

---

### 22. APSC-DV-000290 | SV-222408r1015683

- Rule ID: SV-222408r1015683
- Severity: medium
- Rule Title: Shared/group account credentials must be terminated when members leave the group.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create a procedure for deleting either member accounts or the entire group account when members leave the group.

---

### 23. APSC-DV-000300 | SV-222409r960771

- Rule ID: SV-222409r960771
- Severity: medium
- Rule Title: The application must automatically remove or disable temporary user accounts 72 hours after account creation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure temporary accounts to be automatically removed or disabled after 72 hours after account creation.

---

### 24. APSC-DV-000310 | SV-222410r961863

- Rule ID: SV-222410r961863
- Severity: low
- Rule Title: The application must have a process, feature or function that prevents removal or disabling of emergency accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Identify accounts that are created in an emergency situation and ensure procedures or processes are in place to prevent disabling or deleting the account while the emergency is underway.

---

### 25. APSC-DV-000320 | SV-222411r960774

- Rule ID: SV-222411r960774
- Severity: low
- Rule Title: The application must automatically disable accounts after a 35 day period of account inactivity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to expire user accounts after 35 days of inactivity.

---

### 26. APSC-DV-000330 | SV-222412r960774

- Rule ID: SV-222412r960774
- Severity: medium
- Rule Title: Unnecessary application accounts must be disabled, or deleted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design the application so unessential user accounts are not created during installation. Disable or delete all unnecessary application user accounts.

---

### 27. APSC-DV-000340 | SV-222413r960777

- Rule ID: SV-222413r960777
- Severity: medium
- Rule Title: The application must automatically audit account creation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are created.

---

### 32. APSC-DV-000390 | SV-222418r1015685

- Rule ID: SV-222418r1015685
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) when accounts are modified.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are modified.

---

### 33. APSC-DV-000400 | SV-222419r1015686

- Rule ID: SV-222419r1015686
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account disabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are disabled.

---

### 34. APSC-DV-000410 | SV-222420r1015687

- Rule ID: SV-222420r1015687
- Severity: low
- Rule Title: The application must notify system administrators (SAs) and information system security officers (ISSOs) of account removal actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are removed.

---

### 35. APSC-DV-000420 | SV-222421r961290

- Rule ID: SV-222421r961290
- Severity: medium
- Rule Title: The application must automatically audit account enabling actions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to notify the SA and the ISSO when application accounts are enabled.

---

### 37. APSC-DV-000440 | SV-222423r961302

- Rule ID: SV-222423r961302
- Severity: medium
- Rule Title: Application data protection requirements must be identified and documented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Identify and document the application data elements and the data protection requirements.

---

### 38. APSC-DV-000450 | SV-222424r961305

- Rule ID: SV-222424r961305
- Severity: medium
- Rule Title: The application must utilize organization-defined data mining detection techniques for organization-defined data storage objects to adequately detect data mining attempts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Utilize and implement data mining protections when requirements specify it.

---

### 39. APSC-DV-000460 | SV-222425r1117167

- Rule ID: SV-222425r1117167
- Severity: high
- Rule Title: The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or configure the application to enforce access to application resources.

---

### 40. APSC-DV-000470 | SV-222426r961317

- Rule ID: SV-222426r961317
- Severity: medium
- Rule Title: The application must enforce organization-defined discretionary access control policies over defined subjects and objects.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to enforce discretionary access control policies.

---

### 41. APSC-DV-000480 | SV-222427r1117168

- Rule ID: SV-222427r1117168
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 42. APSC-DV-000490 | SV-222428r1117169

- Rule ID: SV-222428r1117169
- Severity: medium
- Rule Title: The application must enforce approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to enforce data flow control in accordance with data flow control policies.

---

### 43. APSC-DV-000500 | SV-222429r961353

- Rule ID: SV-222429r961353
- Severity: medium
- Rule Title: The application must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Modify the application to limit access and prevent the disabling or circumvention of security safeguards.

---

### 44. APSC-DV-000510 | SV-222430r961359

- Rule ID: SV-222430r961359
- Severity: high
- Rule Title: The application must execute without excessive account permissions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.

---

### 45. APSC-DV-000520 | SV-222431r961362

- Rule ID: SV-222431r961362
- Severity: medium
- Rule Title: The application must audit the execution of privileged functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to write log entries when privileged functions are executed. At a minimum, ensure the specific action taken, date and time of event are recorded.

---

### 46. APSC-DV-000530 | SV-222432r960840

- Rule ID: SV-222432r960840
- Severity: high
- Rule Title: The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to enforce an account lock after 3 failed logon attempts occurring within a 15-minute window.

---

### 47. APSC-DV-000540 | SV-222433r961368

- Rule ID: SV-222433r961368
- Severity: medium
- Rule Title: The application administrator must follow an approved process to unlock locked user accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 49. APSC-DV-000560 | SV-222435r960846

- Rule ID: SV-222435r960846
- Severity: low
- Rule Title: The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.

---

### 50. APSC-DV-000570 | SV-222436r960849

- Rule ID: SV-222436r960849
- Severity: low
- Rule Title: The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to present the standard DoD-approved banner prior to granting access to the application.

---

### 51. APSC-DV-000580 | SV-222437r987626

- Rule ID: SV-222437r987626
- Severity: low
- Rule Title: The application must display the time and date of the users last successful logon.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to display the date and time when the user was last successfully granted access to the application.

---

### 52. APSC-DV-000590 | SV-222438r960864

- Rule ID: SV-222438r960864
- Severity: medium
- Rule Title: The application must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to provide users with a non-repudiation function in the form of digital signatures when it is required by the organization or by the application design and architecture.

---

### 53. APSC-DV-000600 | SV-222439r960873

- Rule ID: SV-222439r960873
- Severity: medium
- Rule Title: For applications providing audit record aggregation, the application must compile audit records from organization-defined information system components into a system-wide audit trail that is time-correlated with an organization-defined level of tolerance for the relationship between time stamps of individual records in the audit trail.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- Application source code and documentation do not indicate any audit record aggregation or log aggregation functionality; requirement is not applicable.

Remediation:
Configure the application to correlate time stamps when aggregating audit records.

---

### 54. APSC-DV-000620 | SV-222441r960879

- Rule ID: SV-222441r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the creation of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Enable session ID creation event auditing.

---

### 55. APSC-DV-000630 | SV-222442r960879

- Rule ID: SV-222442r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the destruction of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Enable session ID destruction event auditing.

---

### 56. APSC-DV-000640 | SV-222443r960879

- Rule ID: SV-222443r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for the renewal of session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or reconfigure the application to log session renewal events on those application events that provide changes in the users privileges or permissions to the application.

---

### 57. APSC-DV-000650 | SV-222444r960879

- Rule ID: SV-222444r960879
- Severity: medium
- Rule Title: The application must not write sensitive data into the application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or reconfigure the application to not write sensitive data to the logs.

---

### 58. APSC-DV-000660 | SV-222445r960879

- Rule ID: SV-222445r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for session timeouts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to record session timeout events in the logs.

---

### 59. APSC-DV-000670 | SV-222446r960879

- Rule ID: SV-222446r960879
- Severity: medium
- Rule Title: The application must record a time stamp indicating when the event occurred.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to record the time the event occurred when recording the event.

---

### 60. APSC-DV-000680 | SV-222447r960879

- Rule ID: SV-222447r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for HTTP headers including User-Agent, Referer, GET, and POST.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the web application and/or the web server to log HTTP headers.

---

### 61. APSC-DV-000690 | SV-222448r960879

- Rule ID: SV-222448r960879
- Severity: medium
- Rule Title: The application must provide audit record generation capability for connecting system IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application or application server to log all connecting IP address information

---

### 62. APSC-DV-000700 | SV-222449r960879

- Rule ID: SV-222449r960879
- Severity: medium
- Rule Title: The application must record the username or user ID of the user associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to record the user ID of the user responsible for the log event entry.

---

### 63. APSC-DV-000710 | SV-222450r960885

- Rule ID: SV-222450r960885
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to grant privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to grant privileges.

---

### 64. APSC-DV-000720 | SV-222451r961791

- Rule ID: SV-222451r961791
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security objects.

---

### 65. APSC-DV-000730 | SV-222452r961794

- Rule ID: SV-222452r961794
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access security levels.

---

### 66. APSC-DV-000740 | SV-222453r961797

- Rule ID: SV-222453r961797
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to access categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of information category or classification level enforcement or audit logic in reviewed code or documentation.
- README.md and code do not indicate compartmentalized data or category-based access controls.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to access protected categories of information.

---

### 67. APSC-DV-000750 | SV-222454r961800

- Rule ID: SV-222454r961800
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to modify privileges.

---

### 68. APSC-DV-000760 | SV-222455r961803

- Rule ID: SV-222455r961803
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security objects.

---

### 69. APSC-DV-000770 | SV-222456r961806

- Rule ID: SV-222456r961806
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify security levels.

---

### 70. APSC-DV-000780 | SV-222457r961809

- Rule ID: SV-222457r961809
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to modify categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of information category or classification level enforcement or audit logic in reviewed code or documentation.
- README.md and code do not indicate compartmentalized data or category-based access controls.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to modify protected categories of information.

---

### 71. APSC-DV-000790 | SV-222458r961812

- Rule ID: SV-222458r961812
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete privileges occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to audit successful and unsuccessful attempts to delete privileges.

---

### 72. APSC-DV-000800 | SV-222459r961815

- Rule ID: SV-222459r961815
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete security levels occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete security levels.

---

### 73. APSC-DV-000810 | SV-222460r961818

- Rule ID: SV-222460r961818
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete application database security objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete database security objects.

---

### 74. APSC-DV-000820 | SV-222461r961821

- Rule ID: SV-222461r961821
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of information category or classification level enforcement or audit logic in reviewed code or documentation.
- README.md and code do not indicate compartmentalized data or category-based access controls.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to create an audit record for both successful and unsuccessful attempts to delete protected categories of information.

---

### 75. APSC-DV-000830 | SV-222462r961824

- Rule ID: SV-222462r961824
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful logon attempts occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Authentication is implemented via Keycloak JWT (api/app/auth.py), but no evidence of audit record/log generation for logon attempts.
- No log writing or audit event emission for successful or failed logins is present in the codebase.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application or application server to write a log entry when successful and unsuccessful logon events occur.

---

### 76. APSC-DV-000840 | SV-222463r961827

- Rule ID: SV-222463r961827
- Severity: medium
- Rule Title: The application must generate audit records for privileged activities or other system-level access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Role-based access control is enforced (api/app/auth.py), but no evidence of privileged activity audit logging.
- No code found that generates audit records for privileged actions or system-level access.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to write a log entry when privileged activities or other system-level events occur.

---

### 77. APSC-DV-000850 | SV-222464r961830

- Rule ID: SV-222464r961830
- Severity: medium
- Rule Title: The application must generate audit records showing starting and ending time for user access to the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of session start/end time audit logging in reviewed code.
- Authentication logic (api/app/auth.py) does not emit session timing events to logs or audit records.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application or application server to record the start and end time of user session activity.

---

### 78. APSC-DV-000860 | SV-222465r961836

- Rule ID: SV-222465r961836
- Severity: medium
- Rule Title: The application must generate audit records when successful/unsuccessful accesses to objects occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of audit record generation for successful/unsuccessful object access in reviewed code.
- Logging in process/services modules is limited to operational events, not access control or audit events.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log successful and unsuccessful access to application objects.

---

### 79. APSC-DV-000870 | SV-222466r961839

- Rule ID: SV-222466r961839
- Severity: medium
- Rule Title: The application must generate audit records for all direct access to the information system.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No direct access to the underlying OS, file system, or system resources is provided by the application per reviewed code and documentation.
- Application is a web API and UI stack with no user-facing direct system access features.

Remediation:
Configure the application to log all direct access to the system.

---

### 80. APSC-DV-000880 | SV-222467r961842

- Rule ID: SV-222467r961842
- Severity: medium
- Rule Title: The application must generate audit records for all account creations, modifications, disabling, and termination events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- User authentication and authorization are handled via Keycloak (api/app/auth.py, deploy/keycloak/themes/README.md).
- No evidence of application-level audit record generation for account creation, modification, disabling, or termination events in the repository.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log user account creation, modification, disabling, and termination events.

---

### 81. APSC-DV-000910 | SV-222468r960888

- Rule ID: SV-222468r960888
- Severity: medium
- Rule Title: The application must initiate session auditing upon startup.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to begin logging application events as soon as the application starts up.

---

### 82. APSC-DV-000940 | SV-222469r960891

- Rule ID: SV-222469r960891
- Severity: medium
- Rule Title: The application must log application shutdown events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application or application server to record application shutdown events in the event logs.

---

### 83. APSC-DV-000950 | SV-222470r960891

- Rule ID: SV-222470r960891
- Severity: medium
- Rule Title: The application must log destination IP addresses.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to record the destination IP address of the remote system.

---

### 84. APSC-DV-000960 | SV-222471r960891

- Rule ID: SV-222471r960891
- Severity: medium
- Rule Title: The application must log user actions involving access to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Identify the specific data elements requiring protection and audit access to the data.

---

### 85. APSC-DV-000970 | SV-222472r960891

- Rule ID: SV-222472r960891
- Severity: medium
- Rule Title: The application must log user actions involving changes to data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log all changes to application data.

---

### 86. APSC-DV-000980 | SV-222473r960894

- Rule ID: SV-222473r960894
- Severity: medium
- Rule Title: The application must produce audit records containing information to establish when (date and time) the events occurred.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-27.
- All logging and summary generation code (e.g., api/app/process/services/summarization.py, api/app/process/services/thumbnail.py) includes 'generated_at' fields and uses datetime.utcnow().isoformat() for event timestamps, ensuring date and time are present in audit records.

Remediation:
Configure the application or application server to include the date and the time of the event in the audit logs.

---

### 87. APSC-DV-000990 | SV-222474r960897

- Rule ID: SV-222474r960897
- Severity: medium
- Rule Title: The application must produce audit records containing enough information to establish which component, feature or function of the application triggered the audit event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log which component, feature or functionality of the application triggered the event.

---

### 88. APSC-DV-001000 | SV-222475r960900

- Rule ID: SV-222475r960900
- Severity: medium
- Rule Title: When using centralized logging; the application must include a unique identifier in order to distinguish itself from other application logs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application logs or the centralized log storage facility so the application name and the hosts hosting the application are uniquely identified in the logs.

---

### 89. APSC-DV-001010 | SV-222476r960903

- Rule ID: SV-222476r960903
- Severity: medium
- Rule Title: The application must produce audit records that contain information to establish the outcome of the events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to include the outcome of application functions or events.

---

### 90. APSC-DV-001020 | SV-222477r960906

- Rule ID: SV-222477r960906
- Severity: medium
- Rule Title: The application must generate audit records containing information that establishes the identity of any individual or process associated with the event.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log the identity of the user and/or the process associated with the event.

---

### 91. APSC-DV-001030 | SV-222478r960909

- Rule ID: SV-222478r960909
- Severity: medium
- Rule Title: The application must generate audit records containing the full-text recording of privileged commands or the individual identities of group account users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log the full text recording of privileged commands or the individual identities of group users.

---

### 92. APSC-DV-001040 | SV-222479r960909

- Rule ID: SV-222479r960909
- Severity: medium
- Rule Title: The application must implement transaction recovery logs when transaction based.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application database to utilize transactional logging.

---

### 93. APSC-DV-001050 | SV-222480r985972

- Rule ID: SV-222480r985972
- Severity: medium
- Rule Title: The application must provide centralized management and configuration of the content to be captured in audit records generated by all application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to utilize a centralized log management system that provides the capability to configure the content of audit records.

---

### 94. APSC-DV-001070 | SV-222481r961395

- Rule ID: SV-222481r961395
- Severity: medium
- Rule Title: The application must off-load audit records onto a different system or media than the system being audited.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to off-load audit records onto a different system as per approved schedule.

---

### 95. APSC-DV-001080 | SV-222482r961860

- Rule ID: SV-222482r961860
- Severity: medium
- Rule Title: The application must be configured to write application logs to a centralized log repository.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to utilize a centralized log repository and ensure the logs are off-loaded from the application system as quickly as possible.

---

### 96. APSC-DV-001090 | SV-222483r961398

- Rule ID: SV-222483r961398
- Severity: medium
- Rule Title: The application must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to send an immediate alarm to the application admin/SA and the ISSO when the allocated log storage capacity exceeds 75% of usage or exceeds the capacity value the SA and ISSO have determined will provide adequate time to plan for capacity expansion.

---

### 97. APSC-DV-001100 | SV-222484r961401

- Rule ID: SV-222484r961401
- Severity: medium
- Rule Title: Applications categorized as having a moderate or high impact must provide an immediate real-time alert to the SA and ISSO (at a minimum) for all audit failure events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to send an alarm in the event the audit system has failed or is failing.

---

### 99. APSC-DV-001120 | SV-222486r1043188

- Rule ID: SV-222486r1043188
- Severity: medium
- Rule Title: The application must shut down by default upon audit failure (unless availability is an overriding concern).

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to cease processing if the audit system fails or configure the application to continue logging in a manner that compensates for the audit failure.

---

### 100. APSC-DV-001130 | SV-222487r960918

- Rule ID: SV-222487r960918
- Severity: medium
- Rule Title: The application must provide the capability to centrally review and analyze audit records from multiple components within the system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application so all of the applications logs are available for review from one centralized location.

---

### 101. APSC-DV-001140 | SV-222488r960924

- Rule ID: SV-222488r960924
- Severity: medium
- Rule Title: The application must provide the capability to filter audit records for events of interest based upon organization-defined criteria.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application filters to search event logs based on defined criteria.

---

### 102. APSC-DV-001150 | SV-222489r961056

- Rule ID: SV-222489r961056
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to generate soft copy, hard copy and/or screen-based reports based on the selected filtered event data.

---

### 103. APSC-DV-001160 | SV-222490r961413

- Rule ID: SV-222490r961413
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to log to a centralized auditing capability that provides on-demand reports based on the filtered audit event data or design or configure the application to meet the requirement.

---

### 104. APSC-DV-001170 | SV-222491r961416

- Rule ID: SV-222491r961416
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to provide an audit reduction capability that supports forensic investigations.

---

### 105. APSC-DV-001180 | SV-222492r961419

- Rule ID: SV-222492r961419
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand audit review and analysis.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or configure the application to provide an immediate audit review capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 106. APSC-DV-001190 | SV-222493r961422

- Rule ID: SV-222493r961422
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports on-demand reporting requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or configure the application to provide an on-demand report generation capability or utilize a centralized utility designed for the purpose of on-demand log management and reporting.

---

### 107. APSC-DV-001200 | SV-222494r961425

- Rule ID: SV-222494r961425
- Severity: medium
- Rule Title: The application must provide a report generation capability that supports after-the-fact investigations of security incidents.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design or configure the application to provide after-the-fact report generation capability or utilize a centralized utility designed for the purpose of log management and reporting.

---

### 108. APSC-DV-001210 | SV-222495r961428

- Rule ID: SV-222495r961428
- Severity: medium
- Rule Title: The application must provide an audit reduction capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to not alter original log content or time ordering of audit records.

---

### 109. APSC-DV-001220 | SV-222496r961431

- Rule ID: SV-222496r961431
- Severity: medium
- Rule Title: The application must provide a report generation capability that does not alter original content or time ordering of audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure and design the application to not modify source logs when filtering events.

---

### 110. APSC-DV-001250 | SV-222497r960927

- Rule ID: SV-222497r960927
- Severity: medium
- Rule Title: The applications must use internal system clocks to generate time stamps for audit records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Logging and summary generation in api/app/process/services/summarization.py and api/app/process/services/thumbnail.py use datetime.utcnow() for timestamps, which is system clock-based.
- However, full confirmation that all audit records use the internal system clock for all log events cannot be established from code alone; requires runtime and deployment validation.

Remediation:
Configure the application to use the hosting systems internal clock for audit record generation.

---

### 111. APSC-DV-001260 | SV-222498r961443

- Rule ID: SV-222498r961443
- Severity: medium
- Rule Title: The application must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Timestamps for summary and thumbnail generation use datetime.utcnow(), which is UTC-based in Python.
- No explicit evidence that all audit records are mapped to UTC/GMT or that system clock is configured as such; requires deployment and configuration validation.

Remediation:
Configure the application to use the underlying system clock that maps to relevant UTC or GMT timezone.

---

### 112. APSC-DV-001270 | SV-222499r961446

- Rule ID: SV-222499r961446
- Severity: medium
- Rule Title: The application must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Timestamps are generated using datetime.utcnow().isoformat() + 'Z', which provides at least second-level granularity.
- Cannot confirm that all audit records meet one-second precision or that all log sources use this format; requires review of all logging/audit implementations.

Remediation:
Configure the application to leverage the underlying operating system as the time source when recording time stamps or design the application to ensure granularity of 1 second as the minimum degree of precision.

---

### 113. APSC-DV-001280 | SV-222500r960930

- Rule ID: SV-222500r960930
- Severity: medium
- Rule Title: The application must protect audit information from any type of unauthorized read access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- S3 is used for storing summary and thumbnail artifacts (see api/app/process/services/summarization.py and thumbnail.py).
- No static evidence of S3 bucket/object ACLs, IAM policies, or application-level access controls for audit information; requires review of deployment configuration and runtime access controls.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish permissions that control access to the audit logs and audit configuration settings.

---

### 114. APSC-DV-001290 | SV-222501r960933

- Rule ID: SV-222501r960933
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized modification.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Audit-related artifacts (summaries, thumbnails) are written to S3 via boto3 (see summarization.py, thumbnail.py).
- No static evidence of write/modify restrictions or enforcement of least privilege for audit information; requires review of S3/IAM policies and application access controls.

Remediation:
Configure the application to protect audit data from unauthorized modification and changes. Limit users to roles that are assigned the rights to edit audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 115. APSC-DV-001300 | SV-222502r960936

- Rule ID: SV-222502r960936
- Severity: medium
- Rule Title: The application must protect audit information from unauthorized deletion.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Deletion of audit artifacts (summaries, thumbnails) is not implemented in the reviewed code, nor are controls for deletion rights evident.
- Cannot confirm from static code whether unauthorized deletion is prevented; requires review of S3/IAM policies and application-level controls.

Remediation:
Configure the application to protect audit data from unauthorized deletion. Limit users to roles that are assigned the rights to delete audit data and establish permissions that control access to the audit logs and audit configuration settings.

---

### 116. APSC-DV-001310 | SV-222503r960939

- Rule ID: SV-222503r960939
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No distinct audit tool functionality is present in the reviewed application code; audit-related actions are performed via service classes and S3/database access.
- Cannot confirm from static code whether audit tool access is restricted; requires review of deployment, file system, and application-level controls.

Remediation:
Configure the application to protect audit data from unauthorized access. Limit users to roles that are assigned the rights to view, edit or copy audit data, and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 117. APSC-DV-001320 | SV-222504r960942

- Rule ID: SV-222504r960942
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized modification.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No distinct audit tool binaries or separate executables are present in the repository; audit logic is implemented as service classes.
- Cannot confirm from static code whether modification of audit tools is restricted; requires review of deployment and file system permissions.

Remediation:
Configure the application to protect audit tools from unauthorized modifications. Limit users to roles that are assigned the rights to edit or update audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 118. APSC-DV-001330 | SV-222505r960945

- Rule ID: SV-222505r960945
- Severity: medium
- Rule Title: The application must protect audit tools from unauthorized deletion.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No distinct audit tool binaries or separate executables are present in the repository; audit logic is implemented as service classes.
- Cannot confirm from static code whether deletion of audit tools is restricted; requires review of deployment and file system permissions.

Remediation:
Configure the application to protect audit tools from unauthorized deletions. Limit users to roles that are assigned the rights to edit or delete audit tools and establish file permissions that control access to the audit tools and audit tool capabilities and configuration settings.

---

### 119. APSC-DV-001340 | SV-222506r960948

- Rule ID: SV-222506r960948
- Severity: medium
- Rule Title: The application must back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No built-in backup capability for audit records is present in the application code; audit artifacts are stored in S3, which is typically managed externally.
- Per control guidance, this requirement is not applicable if backup is not implemented by the application.

Remediation:
Configure application backup settings to backup application audit logs every 7 days.

---

### 120. APSC-DV-001350 | SV-222507r960951

- Rule ID: SV-222507r960951
- Severity: medium
- Rule Title: The application must use cryptographic mechanisms to protect the integrity of audit information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of cryptographic integrity protection (e.g., checksums, hashes, signatures) for audit information in S3 is present in the reviewed code.
- Requires review of S3 bucket configuration, server-side encryption, or external integrity validation mechanisms.

Remediation:
Configure the application to create an integrity check consisting of a cryptographic hash or one-way digest that can be used to establish the integrity when storing log files.

---

### 121. APSC-DV-001360 | SV-222508r961206

- Rule ID: SV-222508r961206
- Severity: medium
- Rule Title: Application audit tools must be cryptographically hashed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.

---

### 122. APSC-DV-001370 | SV-222509r961206

- Rule ID: SV-222509r961206
- Severity: medium
- Rule Title: The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.

---

### 123. APSC-DV-001390 | SV-222510r1015689

- Rule ID: SV-222510r1015689
- Severity: medium
- Rule Title: The application must prohibit user installation of software without explicit privileged status.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration was found that would allow non-privileged users to install software, plugins, or extensions via the application UI or API.
- The application appears to use Keycloak for authentication and does not expose user-driven installation features in the reviewed code.
- Full confirmation requires dynamic review of the deployed application UI and user roles.

Remediation:
Configure the application to prohibit user installation of software without explicit permission.

---

### 124. APSC-DV-001410 | SV-222511r961461

- Rule ID: SV-222511r961461
- Severity: medium
- Rule Title: The application must enforce access restrictions associated with changes to application configuration.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication (see api/app/config.py and Keycloak theme), but no explicit code restricting configuration changes to privileged users was found in the static code.
- File and directory permissions for configuration files are not defined in the repository.
- Full assessment requires review of deployment file permissions and application role enforcement.

Remediation:
Configure the application to limit access to configuration settings to only authorized users.

---

### 125. APSC-DV-001420 | SV-222512r1015690

- Rule ID: SV-222512r1015690
- Severity: medium
- Rule Title: The application must audit who makes configuration changes to the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of audit logging for configuration changes was found in the static codebase.
- No code was found that logs the user identity when configuration changes are made.
- Requires dynamic review of application logging and audit mechanisms.

Remediation:
Configure the application to create log entries that can be used to identify the user accounts that make application configuration changes.

---

### 126. APSC-DV-001430 | SV-222513r1015691

- Rule ID: SV-222513r1015691
- Severity: medium
- Rule Title: The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence was found in the codebase that verifies digital signatures or cryptographic hashes of patches, service packs, or application components prior to installation.
- Patch management appears to be handled externally (e.g., via AWS CloudFormation or deployment scripts), but signature enforcement is not shown.
- Requires review of deployment and patching procedures.

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
- Static repository review completed on 2026-04-27.
- No explicit file permission settings or access controls for software libraries were found in the repository.
- Application library directories and update mechanisms are not defined in the static code.
- Requires review of deployment environment and runtime file permissions.

Remediation:
Configure the application OS file permissions to restrict access to software libraries and configure the application to restrict user access regarding software library update functionality to only authorized users or processes.

---

### 128. APSC-DV-001460 | SV-222515r961863

- Rule ID: SV-222515r961863
- Severity: medium
- Rule Title: An application vulnerability assessment must be conducted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application vulnerability scanners to test all components of the application, conduct vulnerability scans on a regular basis and remediate identified issues.  Retain scan results for compliance verification.

---

### 129. APSC-DV-001480 | SV-222516r961473

- Rule ID: SV-222516r961473
- Severity: medium
- Rule Title: The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration was found that enforces organizational policies regarding software program usage or execution restrictions.
- Enforcement of such policies may be handled at the infrastructure or OS level, not within the application codebase.
- Requires review of organizational policy and deployment environment.

Remediation:
Restrict application execution in accordance with the policy, terms, and conditions specified.

---

### 130. APSC-DV-001490 | SV-222517r961479

- Rule ID: SV-222517r961479
- Severity: medium
- Rule Title: The application must employ a deny-all, permit-by-exception (whitelist) policy to allow the execution of authorized software programs.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- The application is not a configuration management or system process management tool; it does not manage execution of other software programs.
- No whitelisting or deny-all execution policy functionality is present in the application code.

Remediation:
Configure the application to utilize a deny-all, permit-by-exception policy when allowing the execution of authorized software.

---

### 131. APSC-DV-001500 | SV-222518r960963

- Rule ID: SV-222518r960963
- Severity: medium
- Rule Title: The application must be configured to disable non-essential capabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence was found in the codebase of configuration or controls to disable non-essential capabilities or services.
- Application features and enabled modules are not enumerated in the static code.
- Requires review of deployment configuration and enabled services.

Remediation:
Disable application extraneous application functionality that is not required in order to fulfill the application's mission.

---

### 132. APSC-DV-001510 | SV-222519r1043177

- Rule ID: SV-222519r1043177
- Severity: medium
- Rule Title: The application must be configured to use only functions, ports, and protocols permitted to it in the PPSM CAL.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application defines network ports for PostgreSQL and Qdrant in api/app/config.py, but there is no evidence of enforcement against the PPSM CAL.
- No code was found that restricts or validates allowed ports/protocols against the PPSM CAL.
- Requires review of deployment configuration and network policy enforcement.

Remediation:
Configure the application to utilize application ports approved by the PPSM CAL.

---

### 133. APSC-DV-001520 | SV-222520r1050664

- Rule ID: SV-222520r1050664
- Severity: medium
- Rule Title: The application must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication (see config.py and Keycloak theme), but no code was found that enforces reauthentication on privilege escalation or role change.
- Requires dynamic review of authentication flows and session management.

Remediation:
Configure the application to require reauthentication before user privilege is escalated and user roles are changed.

---

### 134. APSC-DV-001530 | SV-222521r985974

- Rule ID: SV-222521r985974
- Severity: medium
- Rule Title: The application must require devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration was found that enforces device reauthentication under defined circumstances.
- Device authentication and reauthentication intervals are not addressed in the static codebase.
- Requires review of device integration and authentication configuration.

Remediation:
Configure the application to require reauthentication periodically.

---

### 135. APSC-DV-001540 | SV-222522r1051115

- Rule ID: SV-222522r1051115
- Severity: high
- Rule Title: The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for user authentication (see api/app/config.py: KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID and deploy/keycloak/themes/README.md).
- The UI authentication hook (ui/src/hooks/use-auth.test.ts) verifies that users are uniquely identified and authenticated via OIDC tokens.

Remediation:
Configure the application to uniquely identify and authenticate users and user processes.

---

### 136. APSC-DV-001550 | SV-222523r960972

- Rule ID: SV-222523r960972
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application integrates with Keycloak for authentication, but there is no evidence in the codebase of enforcing multifactor (Alt. Token) authentication for privileged accounts.
- MFA enforcement must be validated in Keycloak realm and client configuration.

Remediation:
Configure the application to use an Alt. Token when providing network access to privileged application accounts.

---

### 137. APSC-DV-001560 | SV-222524r961494

- Rule ID: SV-222524r961494
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication, but there is no evidence in the codebase of explicit PIV/CAC credential acceptance.
- Requires review of Keycloak realm configuration and authentication flows.

Remediation:
Configure the application to require CAC authentication.

---

### 138. APSC-DV-001570 | SV-222525r961497

- Rule ID: SV-222525r961497
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication, but there is no evidence in the codebase of electronic verification of PIV credentials.
- Requires review of Keycloak configuration and certificate validation settings.

Remediation:
Configure the application to require CAC authentication.

---

### 139. APSC-DV-001580 | SV-222526r960975

- Rule ID: SV-222526r960975
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication, but there is no evidence in the codebase of enforcing multifactor (CAC/Alt. Token) authentication for non-privileged accounts.
- Requires review of Keycloak realm and client configuration for MFA enforcement.

Remediation:
Configure the application to require CAC or Alt. Token authentication for non-privileged network access to non-privileged accounts.

---

### 140. APSC-DV-001590 | SV-222527r1015693

- Rule ID: SV-222527r1015693
- Severity: medium
- Rule Title: The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- The application uses Keycloak for authentication, but there is no evidence in the codebase of enforcing multifactor (Alt. Token) authentication for local privileged access.
- Requires review of Keycloak configuration and local access policies.

Remediation:
Configure the application to only use Alt. Tokens when locally accessing privileged application accounts.

---

### 141. APSC-DV-001600 | SV-222528r1015694

- Rule ID: SV-222528r1015694
- Severity: medium
- Rule Title: The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to require CAC or Alt. Token authentication for nonprivileged network access.

---

### 142. APSC-DV-001610 | SV-222529r1015695

- Rule ID: SV-222529r1015695
- Severity: medium
- Rule Title: The application must ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure the application to individually authenticate group account members prior to allowing access.

---

### 143. APSC-DV-001620 | SV-222530r960993

- Rule ID: SV-222530r960993
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to privileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- JWT authentication is implemented in api/app/auth.py using Keycloak and RS256, but evidence of TLS enforcement or replay-resistant transport (e.g., TLS 1.2+) is not present in the repository; requires deployment and infrastructure validation.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating privileged accounts.

---

### 144. APSC-DV-001630 | SV-222531r1015696

- Rule ID: SV-222531r1015696
- Severity: medium
- Rule Title: The application must implement replay-resistant authentication mechanisms for network access to nonprivileged accounts.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- JWT authentication is implemented in api/app/auth.py using Keycloak and RS256, but evidence of TLS enforcement or replay-resistant transport (e.g., TLS 1.2+) is not present in the repository; requires deployment and infrastructure validation.

Remediation:
Design and configure the application to utilize replay-resistant mechanisms when authenticating nonprivileged accounts.

---

### 145. APSC-DV-001640 | SV-222532r960999

- Rule ID: SV-222532r960999
- Severity: medium
- Rule Title: The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No static evidence of mutual authentication (e.g., client certificate validation or two-way SSL/TLS) is present in the repository; requires infrastructure and deployment configuration review.

Remediation:
Configure the application to utilize mutual authentication when specified by data protection requirements.

---

### 146. APSC-DV-001650 | SV-222533r961503

- Rule ID: SV-222533r961503
- Severity: medium
- Rule Title: The application must authenticate all network connected endpoint devices before establishing any connection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No static evidence of endpoint device authentication (e.g., device certificates or device-specific authentication logic) is present in the repository; requires system-level and infrastructure validation.

Remediation:
Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.

---

### 147. APSC-DV-001660 | SV-222534r961506

- Rule ID: SV-222534r961506
- Severity: medium
- Rule Title: Service-Oriented Applications handling non-releasable data must authenticate endpoint devices via mutual SSL/TLS.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of Service-Oriented Architecture (SOA) or web service endpoints handling non-releasable data in the provided source code; application appears to be end-user and API focused.

Remediation:
Configure the application to utilize mutual authentication when the application is processing non-releasable data.

---

### 148. APSC-DV-001670 | SV-222535r1015697

- Rule ID: SV-222535r1015697
- Severity: medium
- Rule Title: The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No static evidence of device identifier/account inactivity tracking or disabling after 35 days is present; requires review of user/device management logic and/or external IdP configuration.

Remediation:
Configure the application to disable device accounts after 35 days of inactivity or to utilize DOD PKI certificates that provide an expiration date.

---

### 149. APSC-DV-001680 | SV-222536r1015698

- Rule ID: SV-222536r1015698
- Severity: high
- Rule Title: The application must enforce a minimum 15-character password length.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password policy enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require 15 characters in the password.

---

### 150. APSC-DV-001690 | SV-222537r1015699

- Rule ID: SV-222537r1015699
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one uppercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password complexity enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require at least one uppercase character in the password.

---

### 151. APSC-DV-001700 | SV-222538r1015700

- Rule ID: SV-222538r1015700
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one lowercase character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password complexity enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require at least one lowercase character in the password.

---

### 152. APSC-DV-001710 | SV-222539r1015701

- Rule ID: SV-222539r1015701
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one numeric character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password complexity enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require at least one numeric character in the password.

---

### 153. APSC-DV-001720 | SV-222540r1015702

- Rule ID: SV-222540r1015702
- Severity: medium
- Rule Title: The application must enforce password complexity by requiring that at least one special character be used.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password complexity enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require at least one special character in the password.

---

### 154. APSC-DV-001730 | SV-222541r1043189

- Rule ID: SV-222541r1043189
- Severity: medium
- Rule Title: The application must require the change of at least eight of the total number of characters when passwords are changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password change policy enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to require the change of at least eight characters in the password when passwords are changed.

---

### 155. APSC-DV-001740 | SV-222542r1015704

- Rule ID: SV-222542r1015704
- Severity: high
- Rule Title: The application must only store cryptographic representations of passwords.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password storage logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password storage protections must be validated in Keycloak configuration and deployment.

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
- Static repository review completed on 2026-04-27.
- No password transmission logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password transmission protections (e.g., HTTPS/TLS) must be validated in Keycloak and deployment configuration.

Remediation:
Configure the application to encrypt passwords when they are being transmitted.

---

### 157. APSC-DV-001760 | SV-222544r1015705

- Rule ID: SV-222544r1015705
- Severity: medium
- Rule Title: The application must enforce 24 hours/1 day as the minimum password lifetime.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so minimum password lifetime enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to have a minimum password lifetime of 24 hours.

---

### 158. APSC-DV-001770 | SV-222545r1043190

- Rule ID: SV-222545r1043190
- Severity: medium
- Rule Title: The application must enforce a 60-day maximum password lifetime restriction.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so maximum password lifetime enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to have a maximum password lifetime of 60 days.

---

### 159. APSC-DV-001780 | SV-222546r1015267

- Rule ID: SV-222546r1015267
- Severity: medium
- Rule Title: The application must prohibit password reuse for a minimum of five generations.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so password reuse policy enforcement must be validated in Keycloak configuration.

Remediation:
Configure the application to prohibit password reuse for up to five passwords.

---

### 160. APSC-DV-001790 | SV-222547r985976

- Rule ID: SV-222547r985976
- Severity: medium
- Rule Title: The application must allow the use of a temporary password for system logons with an immediate change to a permanent password.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No password-based authentication logic is present in the application source code; authentication is delegated to Keycloak (external IdP), so temporary password and forced change on first login must be validated in Keycloak configuration.

Remediation:
Configure the application to specify when a password is temporary and change the temporary password on the first use.

---

### 161. APSC-DV-001795 | SV-222548r961863

- Rule ID: SV-222548r961863
- Severity: medium
- Rule Title: The application password must not be changeable by users other than the administrator or the user with which the password is associated.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to terminate existing sessions of users whose accounts are deleted.

---

### 163. APSC-DV-001810 | SV-222550r961038

- Rule ID: SV-222550r961038
- Severity: high
- Rule Title: The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Application references Keycloak for authentication (api/app/config.py, KEYCLOAK_URL), which may delegate PKI/certificate validation to Keycloak or the underlying platform.
- No direct certificate validation logic or PKI path construction is present in the application source code; this is likely handled by Keycloak or external IdP.
- System-level configuration and Keycloak settings must be reviewed to confirm certificate path validation.

Remediation:
Design the application to construct a certification path to an accepted trust anchor when using PKI-based authentication.

---

### 164. APSC-DV-001820 | SV-222551r961041

- Rule ID: SV-222551r961041
- Severity: high
- Rule Title: The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence of application-managed private key storage or direct cryptographic signing operations in the provided source code.
- Application delegates authentication to Keycloak and uses AWS S3 for storage; any private key management would be external to this codebase.
- Requires review of Keycloak and AWS IAM configuration for private key access controls.

Remediation:
Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).

---

### 165. APSC-DV-001830 | SV-222552r961044

- Rule ID: SV-222552r961044
- Severity: medium
- Rule Title: The application must map the authenticated identity to the individual user or group account for PKI-based authentication.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Application uses Keycloak for authentication (api/app/config.py), which is responsible for mapping PKI identities to users/groups.
- No custom certificate mapping logic is present in the application code; mapping is likely handled by Keycloak configuration.
- Requires review of Keycloak realm and user federation settings for PKI mapping.

Remediation:
Configure the application to map certificate information to individual users or group accounts or create a process for automatically determining the individual user or group based on certificate information provided in the logs.

---

### 166. APSC-DV-001840 | SV-222553r1015707

- Rule ID: SV-222553r1015707
- Severity: medium
- Rule Title: The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to certificate revocation checking, CRL, or OCSP is present in the application source.
- If PKI is used, revocation checking would be handled by Keycloak or the underlying platform, not by this application.
- Requires system-level validation of Keycloak or IdP revocation configuration.

Remediation:
Implement a CRL import process and configure the application to check the CRL if OCSP is not available.

---

### 167. APSC-DV-001850 | SV-222554r961047

- Rule ID: SV-222554r961047
- Severity: high
- Rule Title: The application must not display passwords/PINs as clear text.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- The application delegates authentication UI to Keycloak (see deploy/keycloak/themes/README.md and ui/README.md).
- Password/PIN entry and display are handled by Keycloak's login theme, not by this application's codebase.
- Control is not applicable to this application's source code.

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
- Static repository review completed on 2026-04-27.
- No direct cryptographic module authentication is implemented in the application code.
- If cryptographic modules are used (e.g., AWS S3, Keycloak), authentication and FIPS compliance must be validated at the service/platform level.
- Requires review of AWS and Keycloak configuration for FIPS-approved module usage.

Remediation:
Use FIPS-approved cryptographic modules.

---

### 169. APSC-DV-001870 | SV-222556r961053

- Rule ID: SV-222556r961053
- Severity: medium
- Rule Title: The application must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Application supports authentication via Keycloak (api/app/config.py), but user provisioning and identification of non-organizational users is not implemented in the codebase.
- Requires review of Keycloak realm configuration and user management policies to confirm unique identification and authentication of non-organizational users.

Remediation:
Configure the application to identify and authenticate all non-organizational users.

---

### 170. APSC-DV-001880 | SV-222557r961527

- Rule ID: SV-222557r961527
- Severity: medium
- Rule Title: The application must accept Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence in the codebase of explicit PIV credential acceptance logic.
- Application delegates authentication to Keycloak; PIV acceptance depends on Keycloak realm and IdP configuration.
- Requires system-level validation of Keycloak's PIV integration and configuration.

Remediation:
Configure the application to accept PIV credentials when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 171. APSC-DV-001890 | SV-222558r961530

- Rule ID: SV-222558r961530
- Severity: medium
- Rule Title: The application must electronically verify Personal Identity Verification (PIV) credentials from other federal agencies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence in the codebase of explicit PIV credential verification logic.
- Application delegates authentication to Keycloak; PIV verification depends on Keycloak and IdP configuration.
- Requires system-level validation of Keycloak's PIV verification and trust settings.

Remediation:
Configure the application to verify the PIV credentials presented when utilizing authentication provided by Federal (Non-DoD) agencies.

---

### 172. APSC-DV-001900 | SV-222559r1015708

- Rule ID: SV-222559r1015708
- Severity: medium
- Rule Title: The application must accept Federal Identity, Credential, and Access Management (FICAM)-approved third-party credentials.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence in the codebase of explicit FICAM-approved third-party credential acceptance logic.
- Application delegates authentication to Keycloak; FICAM compliance depends on Keycloak and IdP configuration.
- Requires system-level validation of Keycloak's third-party credential acceptance and FICAM compliance.

Remediation:
Configure applications intended to be accessible to nonfederal government agencies to use FICAM-approved third-party credentials.

---

### 173. APSC-DV-001910 | SV-222560r1067800

- Rule ID: SV-222560r1067800
- Severity: medium
- Rule Title: The application must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No evidence in the codebase of explicit FICAM profile conformance logic.
- Application delegates authentication to Keycloak; FICAM profile conformance depends on Keycloak and IdP configuration.
- Requires system-level validation of Keycloak's SAML/OpenID/FICAM profile support.

Remediation:
Configure the application to conform to FICAM-issued technical profiles when providing services that rely on external (federal government) identity providers.

---

### 174. APSC-DV-001930 | SV-222561r961548

- Rule ID: SV-222561r961548
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must audit non-local maintenance and diagnostic sessions for organization-defined auditable events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to non-local maintenance or diagnostic session auditing is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to log when application maintenance functionality is executed remotely.

---

### 175. APSC-DV-001940 | SV-222562r961554

- Rule ID: SV-222562r961554
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the integrity of non-local maintenance and diagnostic communications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to non-local maintenance or diagnostic session encryption is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 176. APSC-DV-001950 | SV-222563r961557

- Rule ID: SV-222563r961557
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of non-local maintenance and diagnostic communications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to non-local maintenance or diagnostic session encryption is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to encrypt remote application maintenance sessions.

---

### 177. APSC-DV-001960 | SV-222564r961560

- Rule ID: SV-222564r961560
- Severity: medium
- Rule Title: Applications used for non-local maintenance sessions must verify remote disconnection at the termination of non-local maintenance and diagnostic sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to non-local maintenance session disconnection or verification is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to verify termination of remote maintenance sessions.

---

### 178. APSC-DV-001970 | SV-222565r961062

- Rule ID: SV-222565r961062
- Severity: medium
- Rule Title: The application must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to non-local maintenance session authentication is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to use strong authentication (CAC) when accessing the application for maintenance purposes.

---

### 179. APSC-DV-001980 | SV-222566r985978

- Rule ID: SV-222566r985978
- Severity: medium
- Rule Title: The application must terminate all sessions and network connections when nonlocal maintenance is completed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code related to session timeout or termination for non-local maintenance is present in the application source.
- If such functionality exists, it is not implemented in the reviewed codebase.
- Requires system-level validation and review of operational procedures.

Remediation:
Configure the application to expire idle user sessions after 10 minutes of inactivity for admin users and after 15 minutes of inactivity for regular users.

---

### 180. APSC-DV-001995 | SV-222567r961863

- Rule ID: SV-222567r961863
- Severity: medium
- Rule Title: The application must not be vulnerable to race conditions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No static analysis results or explicit race condition mitigation strategies are present in the repository artifacts.
- Requires review of code testing, static analysis tool outputs, and organizational secure development practices to confirm absence of race conditions.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure or design the application to terminate application network sessions at the end of the session.

---

### 182. APSC-DV-002020 | SV-222570r1117181

- Rule ID: SV-222570r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when signing application components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Utilize FIPS-validated algorithms when signing application components.

---

### 183. APSC-DV-002030 | SV-222571r1117181

- Rule ID: SV-222571r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.

---

### 184. APSC-DV-002040 | SV-222572r1117181

- Rule ID: SV-222572r1117181
- Severity: medium
- Rule Title: The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 185. APSC-DV-002050 | SV-222573r1117181

- Rule ID: SV-222573r1117181
- Severity: medium
- Rule Title: Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No SAML assertion generation code or configuration found in the repository.
- Application uses Keycloak for authentication, which is OIDC-based in this deployment.
- SAML-specific controls are not applicable to this architecture.

Remediation:
Configure the application to use a FIPS-validated cryptographic module.

---

### 186. APSC-DV-002150 | SV-222574r1117171

- Rule ID: SV-222574r1117171
- Severity: medium
- Rule Title: The application user interface must be either physically or logically separated from data storage and management interfaces.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application so user interface to the application and management interface to the application is separated.

---

### 187. APSC-DV-002210 | SV-222575r1043178

- Rule ID: SV-222575r1043178
- Severity: medium
- Rule Title: The application must set the HTTPOnly flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No explicit code or configuration for setting the HTTPOnly flag on session cookies found in the repository.
- Session management is handled by Keycloak and/or the UI framework, but static evidence of HTTPOnly enforcement is not present.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application to set the HTTPOnly flag on session cookies.

---

### 188. APSC-DV-002220 | SV-222576r1043178

- Rule ID: SV-222576r1043178
- Severity: medium
- Rule Title: The application must set the secure flag on session cookies.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No explicit code or configuration for setting the Secure flag on session cookies found in the repository.
- Session management is handled by Keycloak and/or the UI framework, but static evidence of Secure flag enforcement is not present.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application to ensure the secure flag is set on session cookies.

---

### 189. APSC-DV-002230 | SV-222577r1043178

- Rule ID: SV-222577r1043178
- Severity: high
- Rule Title: The application must not expose session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration found that demonstrates encryption of session IDs in transit.
- Application relies on Keycloak for authentication, but static repository artifacts do not confirm transport security for session identifiers.
- Requires system-level validation of TLS/SSL configuration.

Remediation:
Configure the application to protect session IDs from interception or from manipulation.

---

### 190. APSC-DV-002240 | SV-222578r1043179

- Rule ID: SV-222578r1043179
- Severity: high
- Rule Title: The application must destroy the session ID value and/or cookie on logoff or browser close.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code found that explicitly destroys session IDs or cookies on logoff or browser close.
- Session lifecycle is managed by Keycloak and/or the UI, but static evidence of session destruction is not present.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application to destroy session ID cookies once the application session has terminated.

---

### 191. APSC-DV-002250 | SV-222579r1043180

- Rule ID: SV-222579r1043180
- Severity: medium
- Rule Title: Applications must use system-generated session identifiers that protect against session fixation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code found that demonstrates system-generated session identifiers with protection against session fixation.
- Session management is delegated to Keycloak, but static repository artifacts do not confirm session fixation protections.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Design the application to generate new session IDs with unique values when authenticating user sessions.

---

### 192. APSC-DV-002260 | SV-222580r1043180

- Rule ID: SV-222580r1043180
- Severity: medium
- Rule Title: Applications must validate session identifiers.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code found that demonstrates validation of session identifiers.
- Session management is handled by Keycloak, but static repository artifacts do not confirm session validation mechanisms.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application to configure user session identifiers.

---

### 193. APSC-DV-002270 | SV-222581r1043180

- Rule ID: SV-222581r1043180
- Severity: medium
- Rule Title: Applications must not use URL embedded session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration found that demonstrates prevention of URL-embedded session IDs.
- Session management is handled by Keycloak and/or the UI, but static repository artifacts do not confirm this control.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application to transmit session ID information via cookies.

---

### 194. APSC-DV-002280 | SV-222582r1043180

- Rule ID: SV-222582r1043180
- Severity: medium
- Rule Title: The application must not re-use or recycle session IDs.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code found that demonstrates prevention of session ID reuse or recycling.
- Session management is handled by Keycloak, but static repository artifacts do not confirm this control.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Design the application to not re-use session IDs.

---

### 195. APSC-DV-002290 | SV-222583r1051270

- Rule ID: SV-222583r1051270
- Severity: medium
- Rule Title: The application must generate a unique session identifier using a FIPS 140-2/140-3 approved random number generator.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code found that demonstrates use of a FIPS 140-2/140-3 approved random number generator for session ID generation.
- Session management is handled by Keycloak, but static repository artifacts do not confirm FIPS-compliant RNG usage.
- Requires runtime validation or Keycloak configuration artifact review.

Remediation:
Configure the application server to generate unique session identifiers and to use a FIPS 140-2/140-3 random number generator to generate the randomness of the session identifiers.

---

### 196. APSC-DV-002300 | SV-222584r961596

- Rule ID: SV-222584r961596
- Severity: medium
- Rule Title: The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration found that demonstrates enforcement of DoD-approved certificate authorities for protected session establishment.
- Application relies on Keycloak and/or infrastructure for certificate management, but static repository artifacts do not confirm CA enforcement.
- Requires system-level validation and certificate artifact review.

Remediation:
Configure the application to utilize DoD-approved PKI established CAs when verifying DoD-signed certificates.

---

### 197. APSC-DV-002310 | SV-222585r961122

- Rule ID: SV-222585r961122
- Severity: high
- Rule Title: The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).

---

### 198. APSC-DV-002320 | SV-222586r961125

- Rule ID: SV-222586r961125
- Severity: medium
- Rule Title: In the event of a system failure, applications must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create operational configuration documentation that identifies information needed for the application to return back into service or specify no such data is required, and retain data required to determine root cause of application failures.

---

### 199. APSC-DV-002330 | SV-222587r1136910

- Rule ID: SV-222587r1136910
- Severity: medium
- Rule Title: The application must protect the confidentiality and integrity of stored information when required by DOD policy or the information owner.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration found that demonstrates confidentiality and integrity protections for stored information as required by DoD policy or data owner.
- S3 is used for storage, but static repository artifacts do not confirm encryption or integrity controls.
- Requires system-level validation and S3 bucket configuration review.

Remediation:
Identify data elements that require protection. Document the data types and specify protection requirements and methods used.

---

### 200. APSC-DV-002340 | SV-222588r1067803

- Rule ID: SV-222588r1067803
- Severity: high
- Rule Title: The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration found that demonstrates use of approved cryptographic mechanisms to prevent unauthorized modification of information at rest.
- S3 is used for storage, but static repository artifacts do not confirm encryption or integrity controls.
- Requires system-level validation and S3 bucket configuration review.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.

---

### 203. APSC-DV-002370 | SV-222591r1117179

- Rule ID: SV-222591r1117179
- Severity: medium
- Rule Title: The application must maintain a separate execution domain for each executing process.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and configure applications to maintain a separate execution domain for each executing process.

---

### 204. APSC-DV-002380 | SV-222592r1117173

- Rule ID: SV-222592r1117173
- Severity: medium
- Rule Title: Applications must prevent unauthorized and unintended information transfer via shared system resources.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure or design the application to utilize a security control that will implement a boundary that will prevent unauthorized and unintended information transfer via shared system resources.

---

### 205. APSC-DV-002390 | SV-222593r961620

- Rule ID: SV-222593r961620
- Severity: medium
- Rule Title: XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No XML parsing, XML web services, or XML processing code was found in the provided source code or documentation.
- Application appears to be REST/JSON-based and does not utilize XML-based protocols or payloads.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design and deploy the application to utilize controls that will prevent the application from being affected by DoS attacks or being used to attack other systems. This includes but is not limited to utilizing throttling techniques for application traffic such as QoS or implementing logic controls within the application code itself that prevents application use that results in network or system capabilities being exceeded.

---

### 207. APSC-DV-002410 | SV-222595r961155

- Rule ID: SV-222595r961155
- Severity: medium
- Rule Title: The web service design must include redundancy mechanisms when used with high-availability systems.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Build the application to address issues that are found in a redundant environment and utilize redundancy mechanisms to provide high availability.

---

### 208. APSC-DV-002440 | SV-222596r961632

- Rule ID: SV-222596r961632
- Severity: high
- Rule Title: The application must protect the confidentiality and integrity of transmitted information.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure all of the application systems to require TLS encryption in accordance with data protection requirements.

---

### 209. APSC-DV-002450 | SV-222597r1117180

- Rule ID: SV-222597r1117180
- Severity: medium
- Rule Title: The application must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to use cryptographic protections to prevent unauthorized disclosure of application data based upon the application architecture.

---

### 210. APSC-DV-002460 | SV-222598r961638

- Rule ID: SV-222598r961638
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 211. APSC-DV-002470 | SV-222599r961641

- Rule ID: SV-222599r961641
- Severity: medium
- Rule Title: The application must maintain the confidentiality and integrity of information during reception.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure all of the application systems to require TLS encryption.

---

### 212. APSC-DV-002480 | SV-222600r961638

- Rule ID: SV-222600r961638
- Severity: medium
- Rule Title: The application must not disclose unnecessary information to users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to not display technical details about the application architecture on error events.

---

### 213. APSC-DV-002485 | SV-222601r961638

- Rule ID: SV-222601r961638
- Severity: high
- Rule Title: The application must not store sensitive information in hidden fields.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No static evidence of hidden fields containing sensitive data was found in the provided codebase.
- Full assessment requires dynamic analysis of rendered HTML and vulnerability scan results.

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
- Static repository review completed on 2026-04-27.
- No direct evidence of XSS protection (e.g., input sanitization, output encoding) was found in the provided codebase.
- React-based UI (ui/src/components/chat-assistant/chat-assistant.tsx) uses Markdown rendering, which may be vulnerable if not properly sanitized.
- Full assessment requires vulnerability scan results and/or dynamic testing.

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
- Static repository review completed on 2026-04-27.
- No direct evidence of CSRF protection (e.g., anti-CSRF tokens, SameSite cookies) was found in the provided codebase.
- Full assessment requires vulnerability scan results and/or dynamic testing.

Remediation:
Configure the application to use unpredictable challenge tokens and check the HTTP referrer to ensure the request was issued from the site itself.  Implement mitigating controls as required such as using web reputation services.

---

### 216. APSC-DV-002510 | SV-222604r961158

- Rule ID: SV-222604r961158
- Severity: high
- Rule Title: The application must protect from command injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No direct evidence of command injection vulnerabilities or mitigations was found in the provided codebase.
- Full assessment requires vulnerability scan results and/or dynamic testing.

Remediation:
Modify the application so as to escape/sanitize special character input or configure the system to protect against command injection attacks based on application architecture.

---

### 217. APSC-DV-002520 | SV-222605r961158

- Rule ID: SV-222605r961158
- Severity: medium
- Rule Title: The application must protect from canonical representation vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No explicit evidence of canonicalization or encoding/decoding logic was found in the provided codebase.
- Full assessment requires review of input handling and vulnerability scan results.

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
- Static repository review completed on 2026-04-27.
- No explicit input validation logic was found in the provided codebase.
- Full assessment requires review of API endpoints, input handling, and vulnerability scan results.

Remediation:
Design and configure the application to validate input prior to executing commands.

---

### 219. APSC-DV-002540 | SV-222607r961158

- Rule ID: SV-222607r961158
- Severity: high
- Rule Title: The application must not be vulnerable to SQL Injection.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No direct evidence of SQL injection vulnerabilities or mitigations was found in the provided codebase.
- Full assessment requires review of database access patterns and vulnerability scan results.

Remediation:
Modify the application and remove SQL injection vulnerabilities.

---

### 220. APSC-DV-002550 | SV-222608r961158

- Rule ID: SV-222608r961158
- Severity: high
- Rule Title: The application must not be vulnerable to XML-oriented attacks.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No XML processing, XML web services, or XML parsing code was found in the provided source code or documentation.
- Application appears to be REST/JSON-based and does not utilize XML-based protocols or payloads.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure or design the application to remove old components when updating.

---

### 226. APSC-DV-002630 | SV-222614r1117151

- Rule ID: SV-222614r1117151
- Severity: medium
- Rule Title: Security-relevant software updates and patches must be kept up to date.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Check for application updates at least weekly and apply patches immediately or in accordance with POA&Ms, IAVMs, CTOs, DTMs or other authoritative patching guidelines or sources.

---

### 227. APSC-DV-002760 | SV-222615r961731

- Rule ID: SV-222615r961731
- Severity: medium
- Rule Title: The application performing organization-defined security functions must verify correct operation of security functions.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design the application to verify the correct operation of security functions.

---

### 228. APSC-DV-002770 | SV-222616r961734

- Rule ID: SV-222616r961734
- Severity: medium
- Rule Title: The application must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design the application to verify the correct operation of security functions on command and on application startup and restart.

---

### 229. APSC-DV-002780 | SV-222617r961185

- Rule ID: SV-222617r961185
- Severity: low
- Rule Title: The application must notify the ISSO and ISSM of failed security verification tests.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to send notices to the ISSO and ISSM indicating the application failed a verification test.

---

### 230. APSC-DV-002870 | SV-222618r961083

- Rule ID: SV-222618r961083
- Severity: medium
- Rule Title: Unsigned Category 1A mobile code must not be used in the application in accordance with DoD policy.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-27.
- No mobile code (e.g., Java applets, ActiveX, Flash) is present in the reviewed source code or documentation.
- Application is not a client-distributed application and does not deliver mobile code to browsers.

Remediation:
Configure the application so Category 1A mobile code is signed.

---

### 231. APSC-DV-002880 | SV-222619r961863

- Rule ID: SV-222619r961863
- Severity: medium
- Rule Title: The ISSO must ensure an account management process is implemented, verifying only authorized users can gain access to the application, and individual accounts designated as inactive, suspended, or terminated are promptly removed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Establish an account management process.

---

### 232. APSC-DV-002890 | SV-222620r961863

- Rule ID: SV-222620r961863
- Severity: high
- Rule Title: Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Separate web server from other application tiers and place it on a separate network segment apart from the application and database servers in accordance with DoD DMZ data access controls requirements.

---

### 233. APSC-DV-002900 | SV-222621r1136913

- Rule ID: SV-222621r1136913
- Severity: medium
- Rule Title: The ISSO must ensure application audit trails are retained for at least 30 months (12 months active + 18 months cold storage) for applications without SAMI data and five years for applications including SAMI data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Retain application audit log files for 30 months (12 months active + 18 months cold storage) for non-SAMI data and five years for SAMI data.

---

### 234. APSC-DV-002910 | SV-222622r961863

- Rule ID: SV-222622r961863
- Severity: medium
- Rule Title: The ISSO must review audit trails periodically based on system documentation recommendations or immediately upon system security events.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create and maintain a policy to report IA violations.

---

### 236. APSC-DV-002930 | SV-222624r1051272

- Rule ID: SV-222624r1051272
- Severity: medium
- Rule Title: The ISSO must ensure active vulnerability testing is performed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- No web service implementation code (e.g., REST or SOAP endpoints) was found in the provided source code.
- Application does not expose or develop web services; requirement is not applicable.

Remediation:
Develop web services to account for deadlock issues.

---

### 238. APSC-DV-002960 | SV-222626r961863

- Rule ID: SV-222626r961863
- Severity: medium
- Rule Title: The designer must ensure the application does not store configuration and control files in the same directory as user data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.

---

### 239. APSC-DV-002970 | SV-222627r961863

- Rule ID: SV-222627r961863
- Severity: medium
- Rule Title: The ISSO must ensure if a DoD STIG or NSA guide is not available, a third-party product will be configured by following available guidance.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Register the application and ports in the Ports and Protocols Database.

---

### 242. APSC-DV-002995 | SV-222630r961863

- Rule ID: SV-222630r961863
- Severity: medium
- Rule Title: The Configuration Management (CM) repository must be properly patched and STIG compliant.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Patch the CM system when new security patches are made available and apply the relevant STIGs.

---

### 243. APSC-DV-003000 | SV-222631r961863

- Rule ID: SV-222631r961863
- Severity: medium
- Rule Title: Access privileges to the Configuration Management (CM) repository must be reviewed every three months.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Review access privileges to the CM repository at least every three months.

---

### 244. APSC-DV-003010 | SV-222632r961863

- Rule ID: SV-222632r961863
- Severity: medium
- Rule Title: A Software Configuration Management (SCM) plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization must be created and maintained.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create and update a SCM plan describing the configuration control and change management process of application objects developed by the organization and the roles and responsibilities of the organization.  Configure CMR to comply.

---

### 245. APSC-DV-003020 | SV-222633r961863

- Rule ID: SV-222633r961863
- Severity: medium
- Rule Title: A Configuration Control Board (CCB) that meets at least every release cycle, for managing the Configuration Management (CM) process must be established.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Setup and maintain a Configuration Control Board.

---

### 246. APSC-DV-003030 | SV-222634r987685

- Rule ID: SV-222634r987685
- Severity: medium
- Rule Title: The application services and interfaces must be compatible with and ready for IPv6 networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.

---

### 247. APSC-DV-003040 | SV-222635r961863

- Rule ID: SV-222635r961863
- Severity: medium
- Rule Title: The application must not be hosted on a general purpose machine if the application is designated as critical or high availability by the ISSO.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Deploy mission critical applications on servers that are not shared by other less critical applications.

---

### 248. APSC-DV-003050 | SV-222636r1051323

- Rule ID: SV-222636r1051323
- Severity: medium
- Rule Title: A contingency plan must exist in accordance with DOD policy based on the application's availability requirements.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create and maintain a contingency plan that identifies essential mission and business functions and associated contingency requirements.

---

### 249. APSC-DV-003060 | SV-222637r961863

- Rule ID: SV-222637r961863
- Severity: medium
- Rule Title: Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create and maintain a disaster recovery plan.

---

### 250. APSC-DV-003070 | SV-222638r961863

- Rule ID: SV-222638r961863
- Severity: medium
- Rule Title: Data backup must be performed at required intervals in accordance with DoD policy.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.

---

### 251. APSC-DV-003080 | SV-222639r961863

- Rule ID: SV-222639r961863
- Severity: medium
- Rule Title: Back-up copies of the application software or source code must be stored in a fire-rated container or stored separately (offsite).

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Store a back-up copy of the application software and source code in a fire-rated container or store it separately (offsite) from their respective environments.

---

### 252. APSC-DV-003090 | SV-222640r961863

- Rule ID: SV-222640r961863
- Severity: medium
- Rule Title: Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.

---

### 253. APSC-DV-003100 | SV-222641r961863

- Rule ID: SV-222641r961863
- Severity: medium
- Rule Title: The application must use encryption to implement key exchange and authenticate endpoints prior to establishing a communication channel for key exchange.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No explicit key exchange protocol implementation was found in the provided source code.
- AWS and Keycloak configuration are present, but cryptographic key exchange and FIPS-validated module usage cannot be confirmed from static code alone.
- Disposition set to Open pending system-level validation.

Remediation:
Use encryption for key exchange.

---

### 254. APSC-DV-003110 | SV-222642r961863

- Rule ID: SV-222642r961863
- Severity: high
- Rule Title: The application must not contain embedded authentication data.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Sensitive authentication data (AWS keys, database credentials) are present in api/app/config.py as default values, but these appear to be placeholders or development defaults.
- No hardcoded production credentials or certificates were found in code, but presence of defaults requires review of deployment practices and file permissions.
- Disposition set to Open pending system-level validation and deployment artifact review.

Remediation:
Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.

---

### 255. APSC-DV-003120 | SV-222643r1136915

- Rule ID: SV-222643r1136915
- Severity: high
- Rule Title: The application must have the capability to mark sensitive/classified output when required.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or documentation was found indicating support for marking sensitive/classified output in application-generated reports or UI.
- No classification guide or output marking logic is present in the reviewed files.
- Disposition set to Open pending further review of application output and documentation.

Remediation:
Enable the application to adequately mark sensitive/classified output.

---

### 256. APSC-DV-003130 | SV-222644r961863

- Rule ID: SV-222644r961863
- Severity: low
- Rule Title: Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Execute tests plans prior to release or patch update.

---

### 257. APSC-DV-003140 | SV-222645r961863

- Rule ID: SV-222645r961863
- Severity: medium
- Rule Title: Application files must be cryptographically hashed prior to deploying to DoD operational networks.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No cryptographic hash validation process for application files prior to deployment was found in the repository.
- No documentation or scripts for hash generation or verification are present.
- Disposition set to Open pending system-level validation.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Designate personnel to conduct security testing on the applications.

---

### 259. APSC-DV-003160 | SV-222647r961863

- Rule ID: SV-222647r961863
- Severity: low
- Rule Title: Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create test procedures to test the security state of the application and exercise test procedures annually.

---

### 260. APSC-DV-003170 | SV-222648r961863

- Rule ID: SV-222648r961863
- Severity: medium
- Rule Title: An application code review must be performed on the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Conduct and document code reviews on the application during development and identify and remediate all known and potential security vulnerabilities prior to releasing the application.

---

### 261. APSC-DV-003180 | SV-222649r961863

- Rule ID: SV-222649r961863
- Severity: low
- Rule Title: Code coverage statistics must be maintained for each release of the application.

Status: Not a Finding

Evidence:
- Static repository review completed on 2026-04-27.
- The ui/README.md documents the use of 'npm run test:coverage' to generate code coverage statistics for the UI component.
- The presence of this documented process indicates code coverage statistics are maintained for each release.

Remediation:
Track application testing and maintain statistics that show how much of the application function was tested.

---

### 262. APSC-DV-003190 | SV-222650r961863

- Rule ID: SV-222650r961863
- Severity: medium
- Rule Title: Flaws found during a code review must be tracked in a defect tracking system.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Track software defects in a defect tracking system.

---

### 263. APSC-DV-003200 | SV-222651r961863

- Rule ID: SV-222651r961863
- Severity: medium
- Rule Title: The changes to the application must be assessed for IA and accreditation impact prior to implementation.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Review IA impact to the system prior to implementing changes.

---

### 264. APSC-DV-003210 | SV-222652r961863

- Rule ID: SV-222652r961863
- Severity: medium
- Rule Title: Security flaws must be fixed or addressed in the project plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Address security flaws within a project plan to ensure they are tracked and addressed by management.

---

### 265. APSC-DV-003215 | SV-222653r961863

- Rule ID: SV-222653r961863
- Severity: low
- Rule Title: The application development team must follow a set of coding standards.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Establish and maintain threat models and review for each application release and when new threats are discovered. Identify potential mitigations to identified threats. Verify mitigations are implemented to threats based on their risk analysis.

---

### 268. APSC-DV-003235 | SV-222656r961863

- Rule ID: SV-222656r961863
- Severity: medium
- Rule Title: The application must not be subject to error handling vulnerabilities.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Ensure proper return code and exception handling is implemented throughout the application.

---

### 269. APSC-DV-003236 | SV-222657r961863

- Rule ID: SV-222657r961863
- Severity: medium
- Rule Title: The application development team must provide an application incident response plan.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Remove or decommission all unsupported software products in the application.

---

### 271. APSC-DV-003250 | SV-222659r961863

- Rule ID: SV-222659r961863
- Severity: high
- Rule Title: The application must be decommissioned when maintenance or support is no longer available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Ensure there is maintenance for the application.

---

### 272. APSC-DV-003260 | SV-222660r961863

- Rule ID: SV-222660r961863
- Severity: low
- Rule Title: Procedures must be in place to notify users when an application is decommissioned.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Create and establish procedures to notify users when an application is decommissioned.

---

### 273. APSC-DV-003270 | SV-222661r961863

- Rule ID: SV-222661r961863
- Severity: medium
- Rule Title: Unnecessary built-in application accounts must be disabled.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.

---

### 274. APSC-DV-003280 | SV-222662r961863

- Rule ID: SV-222662r961863
- Severity: high
- Rule Title: Default passwords must be changed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Configure the application to use strong authenticators instead of passwords when possible. Otherwise, change default passwords to a DoD-approved strength password and follow all guidance for passwords.

---

### 275. APSC-DV-003285 | SV-222663r961863

- Rule ID: SV-222663r961863
- Severity: medium
- Rule Title: An Application Configuration Guide must be created and included with the application.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- No evidence in the repository or configuration files indicates that the application processes classified information; this control is not applicable.

Remediation:
Create and maintain a security classification guide.

---

### 277. APSC-DV-003300 | SV-222665r961863

- Rule ID: SV-222665r961863
- Severity: medium
- Rule Title: The designer must ensure uncategorized or emerging mobile code is not used in applications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.

---

### 278. APSC-DV-003310 | SV-222666r961863

- Rule ID: SV-222666r961863
- Severity: medium
- Rule Title: Production database exports must have database administration credentials and sensitive data removed before releasing the export.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Remove sensitive data from production database exports.

---

### 279. APSC-DV-003320 | SV-222667r961863

- Rule ID: SV-222667r961863
- Severity: medium
- Rule Title: Protections against DoS attacks must be implemented.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Implement mitigations from the threat model for DOS attacks.

---

### 280. APSC-DV-003330 | SV-222668r961863

- Rule ID: SV-222668r961863
- Severity: medium
- Rule Title: The system must alert an administrator when low resource conditions are encountered.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Implement mechanisms to alert system administrators about a low resource condition.

---

### 281. APSC-DV-003340 | SV-222669r961863

- Rule ID: SV-222669r961863
- Severity: low
- Rule Title: At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Register administrators to receive update notifications so they can patch and update applications and application components.

---

### 282. APSC-DV-003345 | SV-222670r961863

- Rule ID: SV-222670r961863
- Severity: low
- Rule Title: The application must provide notifications or alerts when product update and security related patches are available.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

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
- Static repository review completed on 2026-04-27.
- No static configuration or infrastructure-as-code for DMZ enforcement is present in the repository.
- Application appears to be deployed in a cloud environment (AWS GovCloud), but DMZ enforcement is not verifiable from code artifacts.
- Requires system/network architecture documentation and deployment validation.

Remediation:
Setup a DMZ between DoD and public networks.

---

### 284. APSC-DV-003360 | SV-222672r961833

- Rule ID: SV-222672r961833
- Severity: low
- Rule Title: The application must generate audit records when concurrent logons from different workstations occur.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- No code or configuration was found that demonstrates audit record generation for concurrent logons from different workstations.
- Authentication is handled via Keycloak, but logon concurrency auditing is not evident in application source.
- Requires review of Keycloak audit configuration and runtime log artifacts.

Remediation:
Configure the application to log concurrent logons from different workstations.

---

### 285. APSC-DV-003400 | SV-222673r961863

- Rule ID: SV-222673r961863
- Severity: medium
- Rule Title: The Program Manager must verify all levels of program management, designers, developers, and testers receive annual security training pertaining to their job function.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; disposition set to Open pending system-level validation and artifact collection.

Remediation:
Provide application development/operational related security specific annual training for managers, designers, developers, and testers.

---

### 286. APSC-DV-002010 | SV-265634r1117183

- Rule ID: SV-265634r1117183
- Severity: medium
- Rule Title: The application must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

Status: Open

Evidence:
- Static repository review completed on 2026-04-27.
- Application uses AWS GovCloud and references Bedrock and S3 for data storage and processing, but no evidence of NSA-approved cryptography for classified data is present in the codebase.
- No indication that the application processes classified data, nor cryptographic module validation details.
- Requires system security plan, data classification, and cryptographic configuration review.

Remediation:
Configure application to encrypt stored classified information; Ensure encryption is performed using NIST FIPS 140-2-validated encryption.

Encrypt stored, non-SAMI classified information using NIST FIPS 140-2-validated encryption.

Implement NSA-validated type-1 encryption of all SAMI data stored in the enclave.

---
