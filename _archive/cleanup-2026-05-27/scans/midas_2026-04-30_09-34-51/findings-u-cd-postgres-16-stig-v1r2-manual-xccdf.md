# midas STIG Findings Assessment

Total STIGs Assessed: 111

| Status | Count |
|---|---|
| Open | 4 |
| Not Applicable | 107 |

### 1. CD16-00-000100 | SV-261857r1000976

- Rule ID: SV-261857r1000976
- Severity: medium
- Rule Title: PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database or a database management interface. No static configuration or code for PostgreSQL connection/session management is present in any provided file (e.g., no postgresql.conf, pg_hba.conf, or SQL connection/session logic). The application appears to be an AI-powered code analysis/orchestration platform, not a DBMS or direct DB client.
- Requirement: NOT APPLICABLE — PostgreSQL session-count controls do not apply to this application architecture.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure the maximum amount of connections allowed to the database, as the database administrator (shown here as "postgres") change the following in postgresql.conf (the value 10 is an example; set the value to suit local conditions):

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 
max_connections = 10 

Restart the database:

$ sudo systemctl restart postgresql-${PGVER?}

To limit the amount of connections allowed by a specific role, as the database administrator, run the following SQL: 

$ psql -c "ALTER ROLE <rolname> CONNECTION LIMIT 1";

---

### 2. CD16-00-000200 | SV-261858r1043176

- Rule ID: SV-261858r1043176
- Severity: high
- Rule Title: PostgreSQL must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No pg_hba.conf or PostgreSQL authentication configuration is present in the repository. The application does not directly manage PostgreSQL authentication or access control. All authentication configuration in etc/atlas/config.yaml is for OAuth2/OIDC (see 'issuer_url', 'introspection_client_id', etc.), not PostgreSQL.
- Requirement: NOT APPLICABLE — No PostgreSQL authentication integration or configuration present; control does not apply.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Integrate PostgreSQL security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.

As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file:

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf

For each PostgreSQL-managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate.

---

### 3. CD16-00-000300 | SV-261859r1137654

- Rule ID: SV-261859r1137654
- Severity: high
- Rule Title: PostgreSQL must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence of PostgreSQL role/privilege management or pg_hba.conf configuration is present in the application. The application does not manage database object permissions or access control policies for PostgreSQL. All access control in etc/atlas/config.yaml is for OAuth2/OIDC, not database roles.
- Requirement: NOT APPLICABLE — No PostgreSQL access control or privilege management present in application code or configuration.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Create and/or maintain documentation of each group role's appropriate permissions on database objects.

Implement these permissions in the database and remove any permissions that exceed those documented.

The following are examples of how to use role privileges in PostgreSQL to enforce access controls. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html. 

#### Roles Example 1 

The following example demonstrates how to create an admin role with CREATEDB and CREATEROLE privileges. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "CREATE ROLE admin WITH CREATEDB CREATEROLE" 

#### Roles Example 2 

The following example demonstrates how to create a role with a password that expires and makes the role a member of the "admin" group. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "CREATE ROLE joe LOGIN ENCRYPTED PASSWORD 'stig_2024' VALID UNTIL '2024-09-20' IN ROLE admin" 

#### Roles Example 3 

The following demonstrates how to revoke privileges from a role using REVOKE. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "REVOKE admin FROM joe" 

#### Roles Example 4 

The following demonstrates how to alter privileges in a role using ALTER. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "ALTER ROLE joe NOLOGIN" 

The following are examples of how to use grant privileges in PostgreSQL to enforce access controls on objects. For a complete list of privileges, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-grant.html. 

#### Grant Example 1 

The following example demonstrates how to grant INSERT on a table to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT SELECT ON stig_test TO joe" 

#### Grant Example 2 

The following example demonstrates how to grant ALL PRIVILEGES on a table to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT ALL PRIVILEGES ON stig_test TO joe" 

#### Grant Example 3 

The following example demonstrates how to grant a role to a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "GRANT admin TO joe" 

#### Revoke Example 1 

The following example demonstrates how to revoke access from a role. 

As the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 

$ psql -c "REVOKE admin FROM joe" 

To change authentication requirements for the database, as the database administrator (shown here as "postgres"), edit pg_hba.conf: 

$ sudo su - postgres 

$ vi ${PGDATA?}/pg_hba.conf 

Edit authentication requirements to the organizational requirements. Refer to the official documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html. 

After changes to pg_hba.conf, reload the server: 

$ sudo systemctl reload postgresql-${PGVER?}

---

### 4. CD16-00-000400 | SV-261860r1000977

- Rule ID: SV-261860r1000977
- Severity: medium
- Rule Title: PostgreSQL must protect against a user falsely repudiating having performed organization-defined actions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix or shared_preload_libraries configuration is present in any provided file. The application does not configure or manage PostgreSQL logging or auditing. All logging and audit controls in the application are for its own API and OAuth2/OIDC authentication (see security/middleware.py), not for a database backend.
- Requirement: NOT APPLICABLE — PostgreSQL audit repudiation controls do not apply to this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure the database to supply additional auditing information to protect against a user falsely repudiating having performed organization-defined actions. 

Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit. 

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging. 

Modify the configuration of audit logs to include details identifying the individual user: 

As the database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Extra parameters can be added to the setting log_line_prefix to identify the user: 

log_line_prefix = '< %m %a %u %d %r %p >' 

As the system administrator, reload the server with the new configuration: 

$ sudo systemctl reload postgresql-${PGVER?}

Use accounts assigned to individual users. Where the application connects to PostgreSQL using a standard, shared account, ensure it also captures the individual user identification and passes it to PostgreSQL.

---

### 5. CD16-00-000500 | SV-261861r1000588

- Rule ID: SV-261861r1000588
- Severity: medium
- Rule Title: PostgreSQL must provide audit record generation capability for DOD-defined auditable events within all DBMS/database components.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL audit log configuration or pgaudit integration is present in the application. The application does not generate or manage PostgreSQL audit records. All audit and logging logic is for application-level events (see security/middleware.py, security/audit_log.py), not for database DDL/DML events.
- Requirement: NOT APPLICABLE — PostgreSQL audit event generation controls do not apply.

Remediation:
Configure PostgreSQL to generate audit records for at least the DOD minimum set of events.

Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 6. CD16-00-000600 | SV-261862r1000591

- Rule ID: SV-261862r1000591
- Severity: medium
- Rule Title: PostgreSQL must allow only the information system security manager (ISSM), or individuals or roles appointed by the ISSM, to select which events are to be audited.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL configuration files (postgresql.conf, pg_hba.conf) or pgaudit settings are present. The application does not allow selection of PostgreSQL audit events or manage DBMS-level audit configuration. All audit configuration is for application-level events and OAuth2/OIDC authentication (see security/middleware.py).
- Requirement: NOT APPLICABLE — PostgreSQL audit event selection controls do not apply.

Remediation:
Configure PostgreSQL's settings to allow designated personnel to select which auditable events are audited.

Using pgaudit allows administrators the flexibility to choose what they log. For an overview of the capabilities of pgaudit, refer to https://github.com/pgaudit/pgaudit. 

Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

Refer to supplementary content APPENDIX-C for instructions on enabling logging. Only administrators/superuser can change PostgreSQL configurations. Access to the database administrator must be limited to designated personnel only.

To ensure that postgresql.conf is owned by the database owner:

$ chown postgres:postgres ${PGDATA?}/postgresql.conf
$ chmod 600 ${PGDATA?}/postgresql.conf

---

### 7. CD16-00-000700 | SV-261863r1000954

- Rule ID: SV-261863r1000954
- Severity: medium
- Rule Title: PostgreSQL must be able to generate audit records when privileges/permissions are retrieved.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence of PostgreSQL pgaudit or audit logging for privilege/permission retrieval is present. The application does not interact with PostgreSQL role/privilege queries or audit their retrieval. All audit logic is for application-level authentication and tool invocation (see security/middleware.py).
- Requirement: NOT APPLICABLE — PostgreSQL privilege/permission audit controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters): 

pgaudit.log_catalog = 'on'
pgaudit.log = 'read'

Note: For this requirement the pgaudit.log must contain 'read' however APPENDIX-C suggests setting pgaudit.log='ddl, role, read, write' to fulfill all requirements.

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 8. CD16-00-000800 | SV-261864r1000597

- Rule ID: SV-261864r1000597
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL audit log configuration or unsuccessful privilege/permission retrieval handling is present. The application does not manage or audit failed PostgreSQL permission queries. All error/audit handling is for application-level events (see security/middleware.py).
- Requirement: NOT APPLICABLE — PostgreSQL unsuccessful privilege/permission audit controls do not apply.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 9. CD16-00-000900 | SV-261865r1000600

- Rule ID: SV-261865r1000600
- Severity: medium
- Rule Title: PostgreSQL must initiate session auditing upon startup.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL shared_preload_libraries or log_destination configuration is present. The application does not initiate or configure PostgreSQL session auditing. All logging and audit logic is for application-level events and OAuth2/OIDC authentication (see security/middleware.py).
- Requirement: NOT APPLICABLE — PostgreSQL session auditing controls do not apply.

Remediation:
Configure PostgreSQL to enable auditing.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

For session logging, using pgaudit is recommended. For instructions on how to setup pgaudit, refer to supplementary content APPENDIX-B.

---

### 10. CD16-00-001000 | SV-261866r1000603

- Rule ID: SV-261866r1000603
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix, log_connections, or log_disconnections configuration is present. The application does not configure or manage PostgreSQL audit record content. All logging is for application-level events and authentication (see security/middleware.py).
- Requirement: NOT APPLICABLE — PostgreSQL audit record content controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C. 

If logging is enabled the following configurations must be made to log connections, date/time, username and session identifier.

Edit the postgresql.conf file as a privileged user:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters based on the organization's needs (minimum requirements are as follows):

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %d %c: >'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 11. CD16-00-001100 | SV-261867r1000955

- Rule ID: SV-261867r1000955
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing time stamps to establish when the events occurred.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix configuration or timestamp audit logic is present. The application does not manage PostgreSQL audit record timestamps. Application-level logging (see security/middleware.py) uses Python logging and includes timestamps, but this is not related to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL audit record timestamp controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Logging must be enabled to capture timestamps. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

If logging is enabled, the following configurations must be made to log events with timestamps:

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add %m to log_line_prefix to enable timestamps with milliseconds:

log_line_prefix = '< %m >'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 12. CD16-00-001200 | SV-261868r1000609

- Rule ID: SV-261868r1000609
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish where the events occurred.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix configuration or audit record location tracking is present. The application does not manage PostgreSQL audit record location information. Application-level logging is unrelated to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL audit record location controls do not apply.

Remediation:
$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Extra parameters can be added to the setting log_line_prefix to log application related information:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %p = process ID
# %m = timestamp with milliseconds
# %i = command tag
# %s = session startup
# %e = SQL state

For example:

log_line_prefix = '< %m %a %u %d %r %p %i %e %s>'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 13. CD16-00-001300 | SV-261869r1000956

- Rule ID: SV-261869r1000956
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish the sources (origins) of the events.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix or log_hostname configuration is present. The application does not manage PostgreSQL audit record source/origin information. Application-level logging is unrelated to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL audit record source/origin controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled, the following configurations can be made to log the source of an event.

As the database administrator, edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

###### Log Line Prefix

Extra parameters can be added to the setting log_line_prefix to log source of event:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %p = process ID
# %m = timestamp with milliseconds

For example:
log_line_prefix = '< %m %a %u %d %r %p %m >'

###### Log Hostname

By default, only IP address is logged. To also log the hostname, the following parameter can also be set in postgresql.conf:

log_hostname = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 14. CD16-00-001400 | SV-261870r1000615

- Rule ID: SV-261870r1000615
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL audit log configuration or error/outcome audit logic is present. The application does not manage PostgreSQL audit record outcome (success/failure) information. Application-level logging is unrelated to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL audit record outcome controls do not apply.

Remediation:
Using pgaudit, PostgreSQL can be configured to audit various facets of PostgreSQL. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit. 

All errors, denials, and unsuccessful requests are logged if logging is enabled. Refer to supplementary content APPENDIX-C for documentation on enabling logging.

Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

With pgaudit and logging enabled, set the configuration settings in postgresql.conf, as the database administrator (shown here as "postgres"), to the following: 

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf 
pgaudit.log_catalog='on' 
pgaudit.log_level='log' 
pgaudit.log_parameter='on' 
pgaudit.log_statement_once='off' 
pgaudit.log='ddl, role, read, write' 

Tune the following logging configurations in postgresql.conf: 

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf 
log_line_prefix = '< %m %u %d %e: >' 
log_error_verbosity = default 

As the system administrator, restart PostgreSQL: 

$ sudo systemctl reload postgresql-${PGVER?}

---

### 15. CD16-00-001500 | SV-261871r1000618

- Rule ID: SV-261871r1000618
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_line_prefix configuration or audit record user/process identity tracking is present. The application does not manage PostgreSQL audit record user/process identity information. Application-level logging is unrelated to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL audit record user/process identity controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Logging must be enabled to capture the identity of any user/subject or process associated with an event. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

To enable username, database name, process ID, remote host/port and application name in logging, as the database administrator (shown here as "postgres"), edit the following in postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_line_prefix = '< %m %u %d %p %r %a >'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 16. CD16-00-001600 | SV-261872r1000621

- Rule ID: SV-261872r1000621
- Severity: medium
- Rule Title: PostgreSQL must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL audit log configuration or organization-defined audit detail logic is present. The application does not manage PostgreSQL audit record detail or organization-defined audit information. Application-level logging is unrelated to PostgreSQL audit records.
- Requirement: NOT APPLICABLE — PostgreSQL organization-defined audit detail controls do not apply.

Remediation:
Configure PostgreSQL audit settings to include all organization-defined detailed information in the audit records for audit events identified by type, location, or subject.

Using pgaudit, PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 17. CD16-00-001700 | SV-261873r1043188

- Rule ID: SV-261873r1043188
- Severity: medium
- Rule Title: PostgreSQL must, by default, shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL or OS-level audit log monitoring, alerting, or shutdown logic is present. The application does not manage PostgreSQL audit log storage or system shutdown on audit failure. Application-level logging is unrelated to PostgreSQL audit log storage.
- Requirement: NOT APPLICABLE — PostgreSQL audit log storage/failure controls do not apply.

Remediation:
Modify PostgreSQL, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.

---

### 18. CD16-00-001800 | SV-261874r1043188

- Rule ID: SV-261874r1043188
- Severity: medium
- Rule Title: PostgreSQL must be configurable to overwrite audit log records, oldest first (first-in-first-out [FIFO]), in the event of unavailability of space for more audit log records.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL or OS-level audit log rotation, FIFO, or disk space management logic is present. The application does not manage PostgreSQL audit log rotation or overwriting. Application-level logging is unrelated to PostgreSQL audit log storage.
- Requirement: NOT APPLICABLE — PostgreSQL audit log rotation/FIFO controls do not apply.

Remediation:
Establish a process with accompanying tools for monitoring available disk space and ensuring that sufficient disk space is maintained to continue generating audit logs, overwriting the oldest existing records if necessary.

---

### 19. CD16-00-002000 | SV-261875r1000630

- Rule ID: SV-261875r1000630
- Severity: medium
- Rule Title: The audit information produced by PostgreSQL must be protected from unauthorized read access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_file_mode or audit log file permission configuration is present. The application does not manage PostgreSQL audit log file permissions or storage. Application-level logging is unrelated to PostgreSQL audit log storage.
- Requirement: NOT APPLICABLE — PostgreSQL audit log read-access controls do not apply.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, consult organization location and permissions for syslog log files.

#### stderr Logging

If PostgreSQL is configured to use stderr for logging, permissions of the log files can be set in postgresql.conf.

As the database administrator (shown here as "postgres"), edit the following settings of logs in the postgresql.conf file:

Note: Consult the organization's documentation on acceptable log privileges.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 20. CD16-00-002100 | SV-261876r1000978

- Rule ID: SV-261876r1000978
- Severity: medium
- Rule Title: The audit information produced by PostgreSQL must be protected from unauthorized modification.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL log_file_mode or audit log file permission configuration is present. The application does not manage PostgreSQL audit log file permissions or storage. Application-level logging is unrelated to PostgreSQL audit log storage.
- Requirement: NOT APPLICABLE — PostgreSQL audit log modification controls do not apply.

Remediation:
To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

#### stderr Logging

With stderr logging enabled, as the database owner (shown here as "postgres"), set the following parameter in postgresql.conf:

$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

To change the owner and permissions of the log files, run the following:

$ chown postgres:postgres ${PGDATA?}/${PGLOG?}
$ chmod 0700 ${PGDATA?}/${PGLOG?}
$ chmod 600 ${PGDATA?}/${PGLOG?}/*.log

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, the log files must be configured to be owned by root with 0600 permissions.

$ chown root:root <log directory name>/<log_filename>
$ chmod 0700 <log directory name>
$ chmod 0600 <log directory name>/*.log

---

### 21. CD16-00-002200 | SV-261877r1000968

- Rule ID: SV-261877r1000968
- Severity: medium
- Rule Title: The audit information produced by PostgreSQL must be protected from unauthorized deletion.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is a Python-based AI code analysis/orchestration platform and does not include or manage a PostgreSQL database instance, nor does it generate or manage PostgreSQL audit logs. No postgresql.conf, log_file_mode, or log management code for PostgreSQL is present in any configuration or source file (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL database or audit log management present in application architecture.

Remediation:
To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-I for instructions on configuring PGLOG.

#### stderr Logging

With stderr logging enabled, as the database owner (shown here as "postgres"), set the following parameter in postgresql.conf:

$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

To change the owner and permissions of the log files, run the following:

$ chown postgres:postgres ${PGDATA?}/${PGLOG?}
$ chmod 0700 ${PGDATA?}/${PGLOG?}
$ chmod 600 ${PGDATA?}/${PGLOG?}/*.log

#### syslog Logging

If PostgreSQL is configured to use syslog for logging, the log files must be configured to be owned by root with 0600 permissions.

$ chown root:root <log directory name>/<log_filename>
$ chmod 0700 <log directory name>
$ chmod 0600 <log directory name>/*.log

---

### 22. CD16-00-002300 | SV-261878r1000958

- Rule ID: SV-261878r1000958
- Severity: medium
- Rule Title: PostgreSQL must protect its audit features from unauthorized access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not install, configure, or manage a PostgreSQL database or its audit features. No references to PGDATA, PGLOG, pgaudit, or PostgreSQL role management exist in any configuration or code (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL instance or audit configuration present in application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER and APPENDIX-I for PGLOG.

If PGLOG or PGDATA are not owned by postgres user and group, configure them as follows: 

$ sudo chown -R postgres:postgres ${PGDATA?}
$ sudo chown -R postgres:postgres ${PGLOG?}

If the pgaudit installation is not owned by root user and group, configure it as follows:

$ sudo chown -R root:root /usr/pgsql-${PGVER?}/share/extension/pgaudit*

To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"

---

### 23. CD16-00-002400 | SV-261879r1000960

- Rule ID: SV-261879r1000960
- Severity: medium
- Rule Title: PostgreSQL must protect its audit configuration from unauthorized modification.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL database or audit configuration is present in the application. There is no postgresql.conf, log_file_mode, or audit configuration file or logic in any provided file (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — Application does not manage or configure PostgreSQL audit settings.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Apply or modify access controls and permissions (both within PostgreSQL and in the file system/operating system) to tools used to view or modify audit log data. Tools must be configurable by authorized personnel only.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_file_mode = 0600

As the database administrator (shown here as "postgres"), change the ownership and permissions of configuration files in PGDATA:

$ sudo su - postgres
$ chown postgres:postgres ${PGDATA?}/*.conf
$ chmod 0600 ${PGDATA?}/*.conf

---

### 24. CD16-00-002500 | SV-261880r1000959

- Rule ID: SV-261880r1000959
- Severity: medium
- Rule Title: PostgreSQL must protect its audit features from unauthorized removal.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL data directory, binaries, or audit features are installed, managed, or referenced by this application. No code or configuration for PGDATA, /usr/pgsql-*, or related permissions exists (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL installation or audit features present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the system administrator, change the permissions of PGDATA: 

$ sudo chown -R postgres:postgres ${PGDATA?} 
$ sudo chmod 700 ${PGDATA?} 

As the system administrator, change the permissions of pgsql: 

$ sudo chown -R root:root /usr/pgsql-${PGVER?}

---

### 25. CD16-00-002600 | SV-261881r1000648

- Rule ID: SV-261881r1000648
- Severity: medium
- Rule Title: PostgreSQL must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to PostgreSQL.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not provide or manage PostgreSQL software modules, stored procedures, functions, triggers, or external links. No configuration or code for PGDATA, /usr/pgsql-*, or related permissions is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL modules or configuration managed by this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), change the ownership and permissions of configuration files in PGDATA: 

$ sudo su - postgres 
$ chown postgres:postgres ${PGDATA?}/postgresql.conf 
$ chmod 0600 ${PGDATA?}/postgresql.conf 

As the server administrator, change the ownership and permissions of shared objects in /usr/pgsql-${PGVER?}/*.so 

$ sudo chown root:root /usr/pgsql-${PGVER?}/lib/*.so 
$ sudo chmod 0755 /usr/pgsql-${PGVER?}/lib/*.so 

As the service administrator, change the ownership and permissions of executables in /usr/pgsql-${PGVER?}/bin: 

$ sudo chown root:root /usr/pgsql-${PGVER?}/bin/* 
$ sudo chmod 0755 /usr/pgsql-${PGVER?}/bin/*

---

### 26. CD16-00-002700 | SV-261882r1000651

- Rule ID: SV-261882r1000651
- Severity: high
- Rule Title: The PostgreSQL software installation account must be restricted to authorized users.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- There is no PostgreSQL software installation account or database managed by this application. No user or account management for PostgreSQL is present in any code or configuration (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL installation account exists in application context.

Remediation:
Develop, document, and implement procedures to restrict and track use of the PostgreSQL software installation account(s).

---

### 27. CD16-00-002800 | SV-261883r1000654

- Rule ID: SV-261883r1000654
- Severity: medium
- Rule Title: Database software, including PostgreSQL configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL software, configuration files, or directories are present or managed by this application. The application is a Python codebase with its own directory structure and does not install or manage PostgreSQL or its configuration (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL software or configuration directories present.

Remediation:
Install all applications on directories separate from the PostgreSQL software library directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL software library directory.

---

### 28. CD16-00-002900 | SV-261884r1000657

- Rule ID: SV-261884r1000657
- Severity: medium
- Rule Title: Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/PostgreSQL principals authorized for ownership.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The application does not create or manage PostgreSQL database objects (tables, indexes, procedures, etc.). No SQL DDL, ownership logic, or database object management is present in any code or configuration (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL database objects or ownership managed.

Remediation:
Assign ownership of authorized objects to authorized object owner accounts.

#### Schema Owner

To create a schema owned by the user "bob", run the following SQL:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test AUTHORIZATION bob" 

To alter the ownership of an existing object to be owned by the user "bob", run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER SCHEMA test OWNER TO bob"

---

### 29. CD16-00-003000 | SV-261885r1000949

- Rule ID: SV-261885r1000949
- Severity: medium
- Rule Title: The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to PostgreSQL, etc.) must be restricted to authorized users.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL roles, groups, or privileges are created, managed, or referenced by this application. No SQL privilege management or database structure modification logic is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL roles or privileges managed.

Remediation:
As the database administrator, revoke any permissions from a role that are deemed unnecessary by running the following SQL:

ALTER ROLE bob NOCREATEDB;
ALTER ROLE bob NOCREATEROLE;
ALTER ROLE bob NOSUPERUSER;
ALTER ROLE bob NOINHERIT;
REVOKE SELECT ON some_function FROM bob;

---

### 30. CD16-00-003200 | SV-261886r1000951

- Rule ID: SV-261886r1000951
- Severity: medium
- Rule Title: Unused database components, PostgreSQL software, and database objects must be removed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL extensions, components, or database objects are installed, managed, or referenced by this application. No SQL extension management or related logic is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL extensions or components managed.

Remediation:
To remove extensions, use the following commands:

$ sudo su - postgres
$ psql -c "DROP EXTENSION <extension_name>"

Note: Removal of plpgsql is not recommended.

---

### 31. CD16-00-003300 | SV-261887r1000666

- Rule ID: SV-261887r1000666
- Severity: medium
- Rule Title: Unused database components that are integrated in PostgreSQL and cannot be uninstalled must be disabled.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL packages or integrated components are installed or managed by this application. No package management or disabling of PostgreSQL components is present in any code or configuration (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL packages or components managed.

Remediation:
To remove any unneeded executables, as the system administrator, run the following:

# RHEL/CENT Systems
$ sudo yum erase <package_name>

# Debian Systems
$ sudo apt-get remove <package_name>

---

### 32. CD16-00-003400 | SV-261888r1000669

- Rule ID: SV-261888r1000669
- Severity: medium
- Rule Title: Access to external executables must be disabled or restricted.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL instance is present; the application does not use or expose the PostgreSQL COPY command or any mechanism for executing external executables via SQL. No database roles or extensions are managed (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL database or external executable access present.

Remediation:
To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"

To remove extensions from PostgreSQL, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "DROP EXTENSION extension_name"

---

### 33. CD16-00-003500 | SV-261889r1043177

- Rule ID: SV-261889r1043177
- Severity: medium
- Rule Title: PostgreSQL must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL instance is present; the application does not configure or expose PostgreSQL ports, protocols, or services. No postgresql.conf, port, or listen_addresses settings are present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL network configuration present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change the listening port of the database, as the database administrator, change the following setting in postgresql.conf: 

$ sudo su - postgres 
$ vi $PGDATA/postgresql.conf 

Change the port parameter to the desired port. 

To change the listening address of the database, as the database administrator, change the following setting in postgresql.conf: 
listen_addresses = '10.0.0.1, 127.0.0.1'

Restart the database: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl restart postgresql-${PGVER?} 


Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable: 

$ psql -p 5432 -c "SHOW port" 
$ export PGPORT=5432

---

### 34. CD16-00-003600 | SV-261890r1051115

- Rule ID: SV-261890r1051115
- Severity: medium
- Rule Title: PostgreSQL must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL roles, authentication, or user management is present in this application. No pg_hba.conf, role creation, or authentication configuration is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL user authentication managed.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Configure PostgreSQL settings to uniquely identify and authenticate all organizational users who log on/connect to the system.

To create roles, use the following SQL:

CREATE ROLE <role_name> [OPTIONS]

For more information on CREATE ROLE, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html.

For each role created, the database administrator can specify database authentication by editing pg_hba.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf

An example pg_hba entry looks like this:

# TYPE DATABASE USER ADDRESS METHOD
host test_db bob 192.168.0.0/16 scram-sha-256

For more information on pg_hba.conf, refer to the official documentation: https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html.

---

### 35. CD16-00-003800 | SV-261891r1000970

- Rule ID: SV-261891r1000970
- Severity: high
- Rule Title: If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL authentication or password storage is present in this application. No password_encryption, scram-sha-256, or password management logic is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL password storage or authentication present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To enable password_encryption, as the database administrator, edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
password_encryption = 'scram-sha-256'

Institute a policy of not using the "WITH UNENCRYPTED PASSWORD" option with the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the setting of the password_encryption configuration parameter.)

As the system administrator, restart the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl restart postgresql-${PGVER?}

---

### 36. CD16-00-003900 | SV-261892r1000681

- Rule ID: SV-261892r1000681
- Severity: high
- Rule Title: If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PostgreSQL authentication or password transmission is present in this application. No pg_hba.conf, password, md5, or scram-sha-256 authentication configuration is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL password authentication or transmission present.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

As the database administrator (shown here as "postgres"), edit pg_hba.conf authentication file and change all entries of "password" to "scram-sha-256":

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf
host all all .example.com scram-sha-256

---

### 37. CD16-00-004000 | SV-261893r1000684

- Rule ID: SV-261893r1000684
- Severity: medium
- Rule Title: PostgreSQL, when using PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PKI-based authentication or SSL/TLS certificate validation for PostgreSQL is present in this application. No ssl_crl_file, pg_hba.conf, or certificate management logic is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL PKI authentication or certificate validation present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

To generate a Certificate Revocation List, refer to the official Red Hat Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Update_Infrastructure/2.1/html/Administration_Guide/chap-Red_Hat_Update_Infrastructure-Administration_Guide-Certification_Revocation_List_CRL.html.

As the database administrator (shown here as "postgres"), copy the CRL file into the data directory:

As the system administrator, copy the CRL file into the PostgreSQL Data Directory:

$ sudo cp root.crl ${PGDATA?}/root.crl

As the database administrator (shown here as "postgres"), set the ssl_crl_file parameter to the filename of the CRL:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
ssl_crl_file = 'root.crl'

In pg_hba.conf, require ssl authentication:

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf
hostssl <database> <user> <address> cert clientcert=verify-ca

As the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-${PGVER?}

---

### 38. CD16-00-004100 | SV-261894r1000687

- Rule ID: SV-261894r1000687
- Severity: high
- Rule Title: PostgreSQL must enforce authorized access to all PKI private keys stored/used by PostgreSQL.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PKI private keys for PostgreSQL are stored, used, or managed by this application. No ssl_key_file, ssl_cert_file, or related configuration is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL PKI private keys present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Store all PostgreSQL PKI private keys in a FIPS 140-2-validated cryptographic module.

Ensure access to PostgreSQL PKI private keys is restricted to only authenticated and authorized users.

PostgreSQL private key(s) can be stored in $PGDATA directory, which is only accessible by the database owner (usually postgres, DBA) user. Do not allow access to this system account to unauthorized users.

To put the keys in a different directory, as the database administrator (shown here as "postgres"), set the following settings to a protected directory:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
ssl_ca_file = "/some/protected/directory/root.crt"
ssl_crl_file = "/some/protected/directory/root.crl"
ssl_cert_file = "/some/protected/directory/server.crt"
ssl_key_file = "/some/protected/directory/server.key"

As the system administrator, restart the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl restart postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 39. CD16-00-004200 | SV-261895r1000690

- Rule ID: SV-261895r1000690
- Severity: medium
- Rule Title: PostgreSQL must map the PKI-authenticated identity to an associated user account.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No PKI authentication or user mapping for PostgreSQL is present in this application. No pg_ident.conf, certificate CN mapping, or related logic is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL PKI user mapping present.

Remediation:
Configure PostgreSQL to map authenticated identities directly to PostgreSQL user accounts.

For information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 40. CD16-00-004400 | SV-261896r1193213

- Rule ID: SV-261896r1193213
- Severity: high
- Rule Title: PostgreSQL must use NIST FIPS 140-2/140-3 validated cryptographic modules for cryptographic operations.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- No cryptographic operations for PostgreSQL are performed by this application. No FIPS mode, OpenSSL, or cryptographic module configuration for PostgreSQL is present (see etc/atlas/config.yaml, Makefile, pyproject.toml, README.md). - Requirement: NOT APPLICABLE — No PostgreSQL cryptographic operations present.

Remediation:
If crypto.fips_enabled = 0 for Red Hat Linux, configure the operating system to implement DOD-approved encryption.

To enable strict FIPS compliance, the fips=1 kernel option must be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.

Enable FIPS mode with the following command:

# sudo fips-mode-setup --enable

Modify the kernel command line of the current kernel in the "grub.cfg" file by adding the following option to the GRUB_CMDLINE_LINUX key in the "/etc/default/grub" file and then rebuilding the "grub.cfg" file:

fips=1

Changes to "/etc/default/grub" require rebuilding the "grub.cfg" file.

On BIOS-based machines, use the following command:

# sudo grub2-mkconfig -o /boot/grub2/grub.cfg

On UEFI-based machines, use the following command:

# sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

If /boot or /boot/efi reside on separate partitions, the kernel parameter "boot=<partition of /boot or /boot/efi>" must be added to the kernel command line. Identify a partition by running the df /boot or df /boot/efi command:

# sudo df /boot

Filesystem 1K-blocks Used Available Use% Mounted on
/dev/sda1 495844 53780 416464 12% /boot

To ensure the "boot=" configuration option will work even if device naming changes occur between boots, identify the universally unique identifier (UUID) of the partition with the following command:

# sudo blkid /dev/sda1
/dev/sda1: UUID="05c000f1-a213-759e-c7a2-f11b7424c797" TYPE="ext4"

For the example above, append the following string to the kernel command line:

boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797

Reboot the system for the changes to take effect.

More information can be found here:
RedHat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-federal_standards_and_regulations
Ubuntu: https://security-certs.docs.ubuntu.com/en/fips

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 41. CD16-00-004500 | SV-261897r1000696

- Rule ID: SV-261897r1000696
- Severity: medium
- Rule Title: PostgreSQL must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database nor does it implement or manage PostgreSQL user roles directly. It is a Python-based AI code analysis/orchestration platform. No database user/role management code or SQL role creation/deletion is present in the provided source or configuration files. - Requirement: NOT APPLICABLE — PostgreSQL user/role management is not implemented by this application.

Remediation:
To drop a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "DROP ROLE <role_to_drop>"

To create a role, as the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c "CREATE ROLE <role name> LOGIN"

For the complete list of permissions allowed by roles, refer to the official documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html.

---

### 42. CD16-00-004600 | SV-261898r1137655

- Rule ID: SV-261898r1137655
- Severity: medium
- Rule Title: PostgreSQL must separate user functionality (including user interface services) from database management functionality.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement or manage database roles or permissions. No code or configuration for PostgreSQL role separation, superuser, or privilege assignment is present. - Requirement: NOT APPLICABLE — No PostgreSQL user/role separation is implemented by this application.

Remediation:
Configure PostgreSQL to separate database administration and general user functionality.

Do not grant superuser, create role, create db, or bypass rls role attributes to users that do not require it.

To remove privileges, refer to the following example:

ALTER ROLE <username> NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

---

### 43. CD16-00-004700 | SV-261899r1043179

- Rule ID: SV-261899r1043179
- Severity: medium
- Rule Title: PostgreSQL must invalidate session identifiers upon user logout or other session termination.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not manage PostgreSQL sessions or configure PostgreSQL session timeout/keepalive parameters. No references to 'tcp_keepalives_idle', 'tcp_keepalives_interval', 'tcp_keepalives_count', or 'statement_timeout' are present in any configuration or code. - Requirement: NOT APPLICABLE — PostgreSQL session management is not implemented by this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi $PGDATA/postgresql.conf

Set the following parameters to organizational requirements:

statement_timeout = 10000 #milliseconds
tcp_keepalives_idle = 10 # seconds
tcp_keepalives_interval = 10 # seconds
tcp_keepalives_count = 10

As the system administrator, restart the server with the new configuration:

$ sudo systemctl restart postgresql-${PGVER?}

---

### 44. CD16-00-004900 | SV-261900r1043181

- Rule ID: SV-261900r1043181
- Severity: medium
- Rule Title: PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not configure or manage PostgreSQL SSL settings. No references to 'ssl = on' or PostgreSQL SSL configuration are present in any configuration or code. - Requirement: NOT APPLICABLE — PostgreSQL SSL configuration is not implemented by this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL, as a database owner (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

For further SSL configurations, refer to the official documentation: https://www.postgresql.org/docs/current/static/ssl-tcp.html.

---

### 45. CD16-00-005200 | SV-261901r1000708

- Rule ID: SV-261901r1000708
- Severity: high
- Rule Title: PostgreSQL must protect the confidentiality and integrity of all information at rest.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not store or manage PostgreSQL data at rest. No use of pgcrypto, disk encryption, or database encryption settings is present in the code or configuration. - Requirement: NOT APPLICABLE — PostgreSQL data-at-rest encryption is not implemented by this application.

Remediation:
Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('a_secure_password', gen_salt('xdes')));

---

### 46. CD16-00-005300 | SV-261902r1000711

- Rule ID: SV-261902r1000711
- Severity: medium
- Rule Title: PostgreSQL must isolate security functions from nonsecurity functions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not define or manage database schemas, security domains, or access privileges for PostgreSQL system catalogs. No code or configuration for PostgreSQL schema or privilege management is present. - Requirement: NOT APPLICABLE — PostgreSQL security function isolation is not implemented by this application.

Remediation:
Do not locate security-related database objects with application tables or schema.

Review any site-specific applications security modules built into the database: determine what schema they are located in and take appropriate action.

Do not grant access to pg_catalog or information_schema to anyone but the database administrator(s). Access to the database administrator account(s) must not be granted to anyone without official approval.

---

### 47. CD16-00-005400 | SV-261903r1137656

- Rule ID: SV-261903r1137656
- Severity: medium
- Rule Title: Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The application implements an ingestion pipeline for moving and indexing code and documentation, but there is no explicit evidence of enforcement of an organization-defined data transfer policy or removal of production data from unprotected locations. - File: lib/ingestion/security.py — InputValidator and AuditLogger classes provide validation and logging for ingestion, but do not reference data transfer policy enforcement or secure deletion of data copies. - File: etc/atlas/config.yaml — Ingestion pipelines are defined, but no explicit data transfer policy or secure handling of production data copies is documented. - Requirement: PARTIALLY SATISFIED — Ingestion pipeline has validation and audit logging, but there is no static evidence of a data transfer policy or secure deletion of production data copies.

Remediation:
Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.

---

### 48. CD16-00-005600 | SV-261904r1137658

- Rule ID: SV-261904r1137658
- Severity: medium
- Rule Title: Access to database files must be limited to relevant processes and to authorized, administrative users.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not manage PostgreSQL database files, logs, or backups at the OS/filesystem level. No code or configuration for file ownership or permissions of database files is present. - Requirement: NOT APPLICABLE — Database file access control is not implemented by this application.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

Configure the permissions granted by the operating system/file system on the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.

Any files (for example: extra configuration files) created in ${PGDATA?} must be owned by the database administrator, with only owner permissions to read, write, and execute.

---

### 49. CD16-00-005700 | SV-261905r1000720

- Rule ID: SV-261905r1000720
- Severity: medium
- Rule Title: PostgreSQL must check the validity of all data inputs except those specifically identified by the organization.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- The ingestion pipeline includes an InputValidator (lib/ingestion/security.py) that checks for path traversal, content size, encoding, and content type, but there is no evidence of database column/field constraints or prepared statement usage for SQL queries (since the application does not interact with a SQL database). - File: lib/ingestion/security.py — InputValidator.validate() checks path traversal, content size, encoding, and content type for RawRecord objects. - File: knowledgebase/parsers/schema.py — Defines canonical output schemas for parsed code, but not for database input validation. - Requirement: PARTIALLY SATISFIED — Input validation is implemented for ingestion, but there is no evidence of prepared statements or database field constraints (not applicable as no SQL DB is used).

Remediation:
Modify database code to properly validate data before it is put into the database or acted upon by the database.

Modify the database to contain constraints and validity checking on database columns and tables that require them for data integrity.

Use prepared statements when taking user input.

Do not allow general users direct console access to PostgreSQL.

---

### 50. CD16-00-005800 | SV-261906r1000979

- Rule ID: SV-261906r1000979
- Severity: medium
- Rule Title: PostgreSQL and associated applications must reserve the use of dynamic code execution for situations that require it.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence of dynamic code execution (e.g., eval, exec, or SQL code generation) is present in the provided files. However, the application does support custom script storage and execution (see plugins/custom_script.py, not included in this context), and there is no static evidence that dynamic execution is restricted only to necessary cases. - File: scripts/example.sh — Example shell script for testing, but not dynamically generated or executed from user input. - Requirement: PARTIALLY SATISFIED — No dynamic code execution found in reviewed files, but custom script execution is supported and restriction to necessary cases cannot be confirmed from static analysis alone.

Remediation:
Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so.

---

### 51. CD16-00-005900 | SV-261907r1000726

- Rule ID: SV-261907r1000726
- Severity: medium
- Rule Title: PostgreSQL and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- No evidence of input sanitization or scanning for code injection is present in the reviewed files. The ingestion pipeline's InputValidator (lib/ingestion/security.py) checks for path traversal, encoding, and content type, but does not scan for code injection patterns. Custom script execution is supported (see plugins/custom_script.py, not included in this context), but input sanitization for dynamic execution is not evident. - Requirement: PARTIALLY SATISFIED — Input validation exists for ingestion, but no evidence of code injection scanning for dynamic code execution.

Remediation:
Where dynamic code execution is used, modify the code to implement protections against code injection (i.e., prepared statements).

---

### 52. CD16-00-006000 | SV-261908r1000729

- Rule ID: SV-261908r1000729
- Severity: medium
- Rule Title: PostgreSQL must provide nonprivileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not expose PostgreSQL error messages or configure 'client_min_messages'. No references to PostgreSQL error message configuration are present. - Requirement: NOT APPLICABLE — PostgreSQL error message exposure is not implemented by this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator, edit "postgresql.conf": 

$ sudo su - postgres 
$ vi $PGDATA/postgresql.conf 

Change the client_min_messages parameter to be "error": 

client_min_messages = error 

Reload the server with the new configuration (this just reloads settings currently in memory; it will not cause an interruption): 

$ sudo systemctl reload postgresql-${PGVER?}

---

### 53. CD16-00-006100 | SV-261909r1000980

- Rule ID: SV-261909r1000980
- Severity: medium
- Rule Title: PostgreSQL must reveal detailed error messages only to the information system security officer (ISSO), information system security manager (ISSM), system administrator (SA), and database administrator (DBA).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not expose PostgreSQL error messages or manage PostgreSQL log file permissions. No references to 'client_min_messages', 'log_file_mode', or PostgreSQL log file handling are present. - Requirement: NOT APPLICABLE — PostgreSQL error/log message exposure is not implemented by this application.

Remediation:
Note: The following instructions use the PGDATA environment variable. Refer to APPENDIX-F for instructions on configuring PGDATA.

To set the level of detail for error messages exposed to clients, as the DBA (shown here as "postgres"), run the following commands:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
client_min_messages = error

---

### 54. CD16-00-006200 | SV-261910r1043182

- Rule ID: SV-261910r1043182
- Severity: medium
- Rule Title: PostgreSQL must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not manage PostgreSQL user sessions or session termination. No code or configuration for automatic session termination of database users is present. - Requirement: NOT APPLICABLE — PostgreSQL session termination is not implemented by this application.

Remediation:
Configure PostgreSQL to automatically terminate a user session after organization-defined conditions or trigger events requiring session termination.

Examples follow.

### Change a role to nologin and disconnect the user

ALTER ROLE '<username>' NOLOGIN;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='<usename>';

### Disconnecting users during a specific time range
Refer to supplementary content APPENDIX-A for a bash script for this example.

The script found in APPENDIX-A using the -l command can disable all users with rolcanlogin=t from logging in. The script keeps track of who it disables in a .restore_login file. After the specified time is over, the same script can be run with the -r command to restore all login connections.

This script would be added to a cron job:

# lock at 5 am every day of the week, month, year at the 0 minute mark.
0 5 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -l
# restore at 5 pm every day of the week, month, year at the 0 minute mark.
0 17 * * * postgres /var/lib/pgsql/no_login.sh -d postgres -r

---

### 55. CD16-00-006400 | SV-261911r1138540

- Rule ID: SV-261911r1138540
- Severity: medium
- Rule Title: PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in storage.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement security labeling for database tables or storage. No code or configuration for security labels or row-level security policies is present. - Requirement: NOT APPLICABLE — PostgreSQL security labeling for storage is not implemented by this application.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 56. CD16-00-006500 | SV-261912r1138541

- Rule ID: SV-261912r1138541
- Severity: medium
- Rule Title: PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in process.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement security labeling for information in process. No code or configuration for security labels or row-level security policies is present. - Requirement: NOT APPLICABLE — PostgreSQL security labeling for information in process is not implemented by this application.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 57. CD16-00-006600 | SV-261913r1138542

- Rule ID: SV-261913r1138542
- Severity: medium
- Rule Title: PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in transmission.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement security labeling for information in transmission. No code or configuration for security labels or row-level security policies is present. - Requirement: NOT APPLICABLE — PostgreSQL security labeling for information in transmission is not implemented by this application.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 58. CD16-00-006700 | SV-261914r1000747

- Rule ID: SV-261914r1000747
- Severity: medium
- Rule Title: PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement discretionary access control (DAC) policies for database objects. No code or configuration for PostgreSQL object ownership or privilege assignment is present. - Requirement: NOT APPLICABLE — PostgreSQL DAC is not implemented by this application.

Remediation:
Implement the organization's DAC policy in the security configuration of the database and PostgreSQL, and, if applicable, the security configuration of the application(s) using the database.

To GRANT privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

$ sudo su - postgres
$ psql -c "CREATE SCHEMA test"
$ psql -c "GRANT CREATE ON SCHEMA test TO bob"
$ psql -c "CREATE TABLE test.test_table(id INT)"
$ psql -c "GRANT SELECT ON TABLE test.test_table TO bob"

To REVOKE privileges to roles, as the database administrator (shown here as "postgres"), run statements like the following examples:

$ psql -c "REVOKE SELECT ON TABLE test.test_table FROM bob"
$ psql -c "REVOKE CREATE ON SCHEMA test FROM bob"

---

### 59. CD16-00-006800 | SV-261915r1000750

- Rule ID: SV-261915r1000750
- Severity: medium
- Rule Title: PostgreSQL must prevent nonprivileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement or expose privileged database functions, nor does it use procedural languages such as pl/Python or pl/R in a database context. No code or configuration for PostgreSQL privileged function enforcement is present. - Requirement: NOT APPLICABLE — PostgreSQL privileged function enforcement is not implemented by this application.

Remediation:
Configure PostgreSQL security to protect all privileged functionality.

If pl/R and pl/Python are used, document their intended use, document users that have access to pl/R and pl/Python, as well as their business use case, such as data-analytics or data-mining. Because of the risks associated with using pl/R and pl/Python, their use must have AO risk acceptance.

To remove unwanted extensions, use:

DROP EXTENSION <extension_name>

To remove unwanted privileges from a role, use the REVOKE command.

Refer to the PostgreSQL documentation for more details: http://www.postgresql.org/docs/current/static/sql-revoke.html.

---

### 60. CD16-00-006900 | SV-261916r1000981

- Rule ID: SV-261916r1000981
- Severity: medium
- Rule Title: Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not implement or manage SECURITY DEFINER functions or privilege elevation in a database context. No code or configuration for PostgreSQL SECURITY DEFINER/INVOKER functions is present. - Requirement: NOT APPLICABLE — PostgreSQL privilege elevation for stored procedures is not implemented by this application.

Remediation:
Determine where, when, how, and by what principals/subjects elevated privilege is needed.

To change a SECURITY DEFINER function to SECURITY INVOKER, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER FUNCTION <function_name> SECURITY INVOKER"

---

### 61. CD16-00-007000 | SV-261917r1000962

- Rule ID: SV-261917r1000962
- Severity: medium
- Rule Title: PostgreSQL must use centralized management of the content captured in audit records generated by all components of PostgreSQL.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database nor does it include any PostgreSQL server configuration or management code.
- File: README.md — No mention of PostgreSQL server configuration or log management
- File: etc/atlas/config.yaml — No PostgreSQL configuration; only application-level config for AI, plugins, and pipelines
- File: Makefile — No PostgreSQL references; only Python, venv, and test orchestration
- File: pyproject.toml — No PostgreSQL dependencies
- Requirement: NOT APPLICABLE — This is an AI code analysis/orchestration application, not a database server or DBMS platform.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

With logging enabled, as the database owner (shown here as "postgres"), configure the following parameters in postgresql.conf:

Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 62. CD16-00-007200 | SV-261918r1000759

- Rule ID: SV-261918r1000759
- Severity: medium
- Rule Title: PostgreSQL must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not manage or allocate storage for PostgreSQL audit logs.
- File: README.md — No mention of PostgreSQL log storage or audit log management
- File: etc/atlas/config.yaml — No PostgreSQL log storage configuration
- File: Makefile — No PostgreSQL or log storage management
- Requirement: NOT APPLICABLE — No PostgreSQL database or audit log storage is managed by this application.

Remediation:
Allocate sufficient audit file/table space to support peak demand.

---

### 63. CD16-00-007300 | SV-261919r1000762

- Rule ID: SV-261919r1000762
- Severity: medium
- Rule Title: PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not monitor or alert on PostgreSQL audit log storage utilization.
- File: README.md — No mention of disk monitoring or alerting for PostgreSQL
- File: etc/atlas/config.yaml — No disk monitoring or alerting configuration for PostgreSQL
- File: Makefile — No scripts or cron jobs for disk usage monitoring
- Requirement: NOT APPLICABLE — No PostgreSQL audit log storage or alerting is implemented or required.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

PostgreSQL does not monitor storage; however, it is possible to monitor storage with a script.

##### Example Monitoring Script

#!/bin/bash

PGDATA=/var/lib/pgsql/${PGVER?}/data
CURRENT=$(df ${PGDATA?} | grep / | awk '{ print $5}' | sed 's/%//g')
THRESHOLD=75

if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
mail -s 'Disk Space Alert' mail@support.com << EOF
The data directory volume is almost full. Used: $CURRENT
EOF
fi

Schedule this script in cron to run around the clock.

---

### 64. CD16-00-007400 | SV-261920r1000973

- Rule ID: SV-261920r1000973
- Severity: medium
- Rule Title: PostgreSQL must provide an immediate real-time alert to appropriate support staff of all audit log failures.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not generate or monitor PostgreSQL audit logs and does not provide real-time alerting for audit log failures.
- File: README.md — No mention of audit log alerting or PostgreSQL log monitoring
- File: etc/atlas/config.yaml — No configuration for audit log alerting
- File: Makefile — No alerting scripts or hooks for PostgreSQL
- Requirement: NOT APPLICABLE — No PostgreSQL audit log alerting is implemented or required.

Remediation:
Configure the system to provide an immediate real-time alert to appropriate support staff when an audit log failure occurs.

It is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in PostgreSQL.

---

### 65. CD16-00-007500 | SV-261921r1000994

- Rule ID: SV-261921r1000994
- Severity: medium
- Rule Title: PostgreSQL must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC), formerly Greenwich Mean Time (GMT).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not generate or manage PostgreSQL audit records or time stamps.
- File: README.md — No mention of PostgreSQL log_timezone or time zone configuration
- File: etc/atlas/config.yaml — No PostgreSQL log_timezone or time zone settings
- Requirement: NOT APPLICABLE — No PostgreSQL database or audit log time zone management is present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change log_timezone in postgresql.conf to use a different time zone for logs, as the database administrator (shown here as "postgres"), run the following:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_timezone='UTC'

Restart the database:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 66. CD16-00-007600 | SV-261922r1000771

- Rule ID: SV-261922r1000771
- Severity: medium
- Rule Title: PostgreSQL must generate time stamps for audit records and application data with a minimum granularity of one second.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not generate PostgreSQL audit records or configure log_line_prefix.
- File: README.md — No mention of PostgreSQL log_line_prefix or audit record time stamps
- File: etc/atlas/config.yaml — No PostgreSQL log_line_prefix or audit log configuration
- Requirement: NOT APPLICABLE — No PostgreSQL audit logging or time stamp configuration is present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL will not log anything if logging is not enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

If logging is enabled, the following configurations must be made to log events with time stamps:

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add %m to log_line_prefix to enable time stamps with milliseconds:

log_line_prefix = '< %m >'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 67. CD16-00-007700 | SV-261923r1000993

- Rule ID: SV-261923r1000993
- Severity: medium
- Rule Title: PostgreSQL must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application is not a PostgreSQL database and does not manage database roles, privileges, or logic module installation.
- File: README.md — No mention of stored procedures, triggers, or database role management
- File: etc/atlas/config.yaml — No database user or privilege configuration
- Requirement: NOT APPLICABLE — No database logic module installation or privilege management is performed by this application.

Remediation:
Document and obtain approval for any nonadministrative users who require the ability to create, alter, or replace logic modules.

Implement the approved permissions. Revoke any unapproved permissions.

---

### 68. CD16-00-007800 | SV-261924r1000777

- Rule ID: SV-261924r1000777
- Severity: medium
- Rule Title: PostgreSQL must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not manage PostgreSQL configuration or enforce access restrictions on database configuration changes.
- File: README.md — No mention of PostgreSQL roles, SUPERUSER, or database configuration privileges
- File: etc/atlas/config.yaml — No database role or privilege configuration
- Requirement: NOT APPLICABLE — No database configuration or privilege enforcement is performed by this application.

Remediation:
Configure PostgreSQL to enforce access restrictions associated with changes to the configuration of PostgreSQL or database(s).

Use ALTER ROLE to remove accesses from roles:

$ psql -c "ALTER ROLE <role_name> NOSUPERUSER"

Use REVOKE to remove privileges from databases and schemas:

$ psql -c "REVOKE ALL PRIVILEGES ON <table> FROM <role_name>"

---

### 69. CD16-00-007900 | SV-261925r1000780

- Rule ID: SV-261925r1000780
- Severity: medium
- Rule Title: PostgreSQL must produce audit records of its enforcement of access restrictions associated with changes to the configuration of PostgreSQL or database(s).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not generate or log PostgreSQL access denials or manage configuration file permissions.
- File: README.md — No mention of PostgreSQL configuration file permissions or audit logging
- File: etc/atlas/config.yaml — No PostgreSQL configuration file or audit log settings
- Requirement: NOT APPLICABLE — No PostgreSQL configuration or audit logging is performed by this application.

Remediation:
Enable logging.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 70. CD16-00-008000 | SV-261926r1000783

- Rule ID: SV-261926r1000783
- Severity: medium
- Rule Title: PostgreSQL must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not listen on or configure PostgreSQL network ports, protocols, or services.
- File: README.md — No mention of PostgreSQL port configuration
- File: etc/atlas/config.yaml — No PostgreSQL port or protocol settings
- Requirement: NOT APPLICABLE — No database network service configuration is present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To change the listening port of the database, as the database administrator, change the following setting in postgresql.conf: 

$ sudo su - postgres 
$ vi $PGDATA/postgresql.conf 

Change the port parameter to the desired port. 

Restart the database: 

$ sudo systemctl restart postgresql-${PGVER?} 

Note: psql uses the port 5432 by default. This can be changed by specifying the port with psql or by setting the PGPORT environment variable: 

$ psql -p 5432 -c "SHOW port" 
$ export PGPORT=5432

---

### 71. CD16-00-008100 | SV-261927r1050788

- Rule ID: SV-261927r1050788
- Severity: medium
- Rule Title: PostgreSQL must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not manage PostgreSQL user authentication or reauthentication events.
- File: README.md — No mention of PostgreSQL user sessions or reauthentication
- File: etc/atlas/config.yaml — No configuration for user session management or reauthentication
- Requirement: NOT APPLICABLE — No database user authentication or session management is performed by this application.

Remediation:
Modify and/or configure PostgreSQL and related applications and tools so that users are always required to reauthenticate when changing role or escalating privileges.

To make a single user reauthenticate, the following must be present:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user='<username>'

To make all users reauthenticate, the following must be present:

SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE user LIKE '%'

---

### 72. CD16-00-008300 | SV-261928r1117186

- Rule ID: SV-261928r1117186
- Severity: high
- Rule Title: PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owner's requirements.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not store or transmit classified information in PostgreSQL, nor does it configure PostgreSQL SSL or cryptography.
- File: README.md — No mention of classified data, PostgreSQL SSL, or cryptography
- File: etc/atlas/config.yaml — No PostgreSQL SSL or cryptographic settings
- Requirement: NOT APPLICABLE — No classified data or PostgreSQL cryptography is managed by this application.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL as a database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

Deploy NSA-approved encrypting devices to protect the server on the network.

---

### 73. CD16-00-008400 | SV-261929r1193220

- Rule ID: SV-261929r1193220
- Severity: medium
- Rule Title: PostgreSQL must only accept end entity certificates issued by DOD PKI or DOD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not use or configure PostgreSQL SSL certificates or CA trust stores.
- File: README.md — No mention of PostgreSQL SSL, CA certificates, or DOD PKI
- File: etc/atlas/config.yaml — No PostgreSQL SSL or certificate configuration
- Requirement: NOT APPLICABLE — No database SSL or certificate management is present.

Remediation:
Revoke trust in any certificates not issued by a DOD-approved certificate authority.

Configure PostgreSQL to accept only DOD and DOD-approved PKI end-entity certificates.

To configure PostgreSQL to accept approved CAs, refer to the official PostgreSQL documentation: http://www.postgresql.org/docs/current/static/ssl-tcp.html

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 74. CD16-00-008500 | SV-261930r1018552

- Rule ID: SV-261930r1018552
- Severity: medium
- Rule Title: PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not store organization-defined information at rest in PostgreSQL, nor does it implement cryptographic protection for such data in a database context.
- File: README.md — No mention of PII, classified data, or at-rest encryption in PostgreSQL
- File: etc/atlas/config.yaml — No PostgreSQL encryption or pgcrypto configuration
- Requirement: NOT APPLICABLE — No database at-rest data or cryptographic protection is managed by this application.

Remediation:
Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection.

The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('mypass', gen_salt('bf', 4));

---

### 75. CD16-00-008600 | SV-261931r1018553

- Rule ID: SV-261931r1018553
- Severity: medium
- Rule Title: PostgreSQL must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not store or manage organization-defined information at rest in PostgreSQL, nor does it implement cryptographic mechanisms for disclosure prevention in a database context.
- File: README.md — No mention of at-rest encryption, PII, or classified data in PostgreSQL
- File: etc/atlas/config.yaml — No PostgreSQL encryption or pgcrypto configuration
- Requirement: NOT APPLICABLE — No database at-rest data or cryptographic protection is managed by this application.

Remediation:
Configure PostgreSQL, operating system/file system, and additional software as relevant, to provide the required level of cryptographic protection for information requiring cryptographic protection against disclosure.

Secure the premises, equipment, and media to provide the required level of physical protection.

The pgcrypto module provides cryptographic functions for PostgreSQL. Refer to supplementary content APPENDIX-E for documentation on installing pgcrypto.

With pgcrypto installed, it is possible to insert encrypted data into the database:

INSERT INTO accounts(username, password) VALUES ('bob', crypt('mypass', gen_salt('bf', 4));

---

### 76. CD16-00-008800 | SV-261932r1000801

- Rule ID: SV-261932r1000801
- Severity: medium
- Rule Title: PostgreSQL must maintain the confidentiality and integrity of information during preparation for transmission.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not transmit or prepare information for transmission from PostgreSQL, nor does it configure SSL for PostgreSQL connections.
- File: README.md — No mention of PostgreSQL SSL or data transmission security
- File: etc/atlas/config.yaml — No PostgreSQL SSL or transmission security configuration
- Requirement: NOT APPLICABLE — No database data transmission or confidentiality/integrity controls are present.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Implement protective measures against unauthorized disclosure and modification during preparation for transmission.

To configure PostgreSQL to use SSL, as a database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 77. CD16-00-008900 | SV-261933r1000804

- Rule ID: SV-261933r1000804
- Severity: medium
- Rule Title: PostgreSQL must maintain the confidentiality and integrity of information during reception.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not receive information from PostgreSQL over the network, nor does it configure SSL for PostgreSQL reception.
- File: README.md — No mention of PostgreSQL SSL or data reception security
- File: etc/atlas/config.yaml — No PostgreSQL SSL or reception security configuration
- Requirement: NOT APPLICABLE — No database data reception or confidentiality/integrity controls are present.

Remediation:
Implement protective measures against unauthorized disclosure and modification during reception.

To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G for instructions on enabling SSL.

---

### 78. CD16-00-009000 | SV-261934r1000807

- Rule ID: SV-261934r1000807
- Severity: medium
- Rule Title: When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not process SQL input or generate errors from PostgreSQL input validation.
- File: README.md — No mention of SQL input validation or PostgreSQL error logging
- File: etc/atlas/config.yaml — No PostgreSQL error handling or logging configuration
- Requirement: NOT APPLICABLE — No database input validation or error logging is performed by this application.

Remediation:
Enable logging.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

All errors and denials are logged if logging is enabled.

---

### 79. CD16-00-009100 | SV-261935r1000810

- Rule ID: SV-261935r1000810
- Severity: medium
- Rule Title: When updates are applied to the PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not install, update, or remove PostgreSQL software packages.
- File: README.md — No mention of PostgreSQL installation or package management
- File: Makefile — No PostgreSQL package management or update logic
- Requirement: NOT APPLICABLE — No database software installation or update management is performed by this application.

Remediation:
Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.

---

### 80. CD16-00-009200 | SV-261936r1137667

- Rule ID: SV-261936r1137667
- Severity: medium
- Rule Title: Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- This application does not install or update PostgreSQL software and does not manage database patching.
- File: README.md — No mention of PostgreSQL versioning or patch management
- File: Makefile — No PostgreSQL package management or update logic
- Requirement: NOT APPLICABLE — No database software update or patch management is performed by this application.

Remediation:
Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.

---

### 81. CD16-00-009400 | SV-261938r1000819

- Rule ID: SV-261938r1000819
- Severity: medium
- Rule Title: PostgreSQL must be able to generate audit records when security objects are accessed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit configuration (shared_preload_libraries, pgaudit.log) to generate audit records for security object access.
- Searched all provided files (README.md, etc/atlas/config.yaml, Makefile, plugins/advice.py, plugins/context.py, lib/vex.py, security/__init__.py, scripts/example.sh, .github/workflows/ci.yml, tests/security/__init__.py, tests/core/__init__.py)
- No evidence of any PostgreSQL configuration, pgaudit settings, or database server setup in application source/configuration.
- Application is not a PostgreSQL server, nor does it bundle or manage PostgreSQL configuration files.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not manage DBMS audit configuration.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit.. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 82. CD16-00-009500 | SV-261939r1000822

- Rule ID: SV-261939r1000822
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to access security objects occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to access security objects (e.g., permission denied errors) via pgaudit and log configuration.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful access attempts.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access security objects occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 83. CD16-00-009600 | SV-261940r1000825

- Rule ID: SV-261940r1000825
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are accessed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, write, role' for auditing access to information categories.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for information category access.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. 

The DBMS (PostgreSQL) can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit. 

With pgaudit installed the following configurations can be made:

$ sudo su - postgres  

$ vi ${PGDATA?}/postgresql.conf  

Add the following parameters (or edit existing parameters):  

pgaudit.log = 'ddl, write, role'  

As the system administrator, reload the server with the new configuration:  

$ sudo systemctl reload postgresql- ${PGVER?}

---

### 84. CD16-00-009700 | SV-261941r1000828

- Rule ID: SV-261941r1000828
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, write, role' for unsuccessful attempts to access information categories.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful category access.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to access categories of information occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl, write, role'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 85. CD16-00-009800 | SV-261942r1000831

- Rule ID: SV-261942r1000831
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when privileges/permissions are added.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'role' for auditing privilege/permission additions.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for privilege/permission additions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit,. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 86. CD16-00-009900 | SV-261943r1000834

- Rule ID: SV-261943r1000834
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to add privileges/permissions occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to add privileges/permissions (e.g., permission denied errors) via pgaudit and log configuration.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful privilege/permission additions.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.

All denials are logged by default if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 87. CD16-00-010000 | SV-261944r1000837

- Rule ID: SV-261944r1000837
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when privileges/permissions are modified.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'role' for auditing privilege/permission modifications.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for privilege/permission modifications.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='role'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 88. CD16-00-010100 | SV-261945r1000840

- Rule ID: SV-261945r1000840
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to modify privileges/permissions occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to modify privileges/permissions via pgaudit and log configuration.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful privilege/permission modifications.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to modify privileges occur.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 89. CD16-00-010200 | SV-261946r1000843

- Rule ID: SV-261946r1000843
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when security objects are modified.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log and pgaudit.log_catalog to be enabled for auditing security object modifications.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, pgaudit.log_catalog, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for security object modifications.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log_catalog = 'on'
pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 90. CD16-00-010300 | SV-261947r1000846

- Rule ID: SV-261947r1000846
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to modify security objects occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to modify security objects via pgaudit and log configuration.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful security object modifications.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security objects occur.

Unsuccessful attempts to modify security objects can be logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 91. CD16-00-010400 | SV-261948r1000849

- Rule ID: SV-261948r1000849
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are modified.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, role, read, write' for auditing category (classification level) modifications.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for category modifications.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 92. CD16-00-010500 | SV-261949r1000852

- Rule ID: SV-261949r1000852
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to modify categories of information (e.g., classification levels/security levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, role, read, write' for unsuccessful attempts to modify categories of information.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful category modifications.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to modify categories of information occur.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C. All denials are logged when logging is enabled.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 93. CD16-00-010600 | SV-261950r1000855

- Rule ID: SV-261950r1000855
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when privileges/permissions are deleted.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'role, read, write, ddl' for auditing privilege/permission deletions.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for privilege/permission deletions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 94. CD16-00-010700 | SV-261951r1000858

- Rule ID: SV-261951r1000858
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to delete privileges/permissions occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to delete privileges/permissions via pgaudit and log configuration.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful privilege/permission deletions.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to delete privileges occur.

All denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 95. CD16-00-010800 | SV-261952r1000861

- Rule ID: SV-261952r1000861
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when security objects are deleted.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl' for auditing security object deletions.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for security object deletions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'ddl'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 96. CD16-00-010900 | SV-261953r1000864

- Rule ID: SV-261953r1000864
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to delete security objects occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, role, read, write' for unsuccessful attempts to delete security objects.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful security object deletions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL to produce audit records when unsuccessful attempts to delete security objects occur.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 97. CD16-00-011000 | SV-261954r1000867

- Rule ID: SV-261954r1000867
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, role, read, write' for auditing category deletions.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for category deletions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 98. CD16-00-011100 | SV-261955r1000870

- Rule ID: SV-261955r1000870
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to delete categories of information (e.g., classification levels/security levels) occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL pgaudit.log to include 'ddl, role, read, write' for unsuccessful attempts to delete categories of information.
- Searched all provided files for any PostgreSQL configuration, pgaudit, or log settings.
- No postgresql.conf, pgaudit.log, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS audit logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful category deletions.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 99. CD16-00-011200 | SV-261956r1000975

- Rule ID: SV-261956r1000975
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when successful logons or connections occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL log_connections and log_line_prefix settings to log successful logons/connections.
- Searched all provided files for any PostgreSQL configuration, log_connections, or log_line_prefix settings.
- No postgresql.conf, log_connections, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS connection logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for successful logons/connections.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

If logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier.

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters as such:

log_connections = on
log_line_prefix = '< %m %u %d %c: >'

Where:
* %m is the time and date
* %u is the username
* %d is the database
* %c is the session ID for the connection

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 100. CD16-00-011300 | SV-261957r1000876

- Rule ID: SV-261957r1000876
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful logons or connection attempts occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL log_connections and log_line_prefix settings to log unsuccessful logons/connection attempts.
- Searched all provided files for any PostgreSQL configuration, log_connections, or log_line_prefix settings.
- No postgresql.conf, log_connections, or database logging configuration present in application source/configuration.
- Application is not a PostgreSQL server and does not manage DBMS connection logging.
- Requirement: NOT APPLICABLE — This application is not a PostgreSQL database server and does not control audit logging for unsuccessful logons/connections.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

If logging is enabled the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier.

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters:

log_connections = on
log_line_prefix = '< %m %u %c: >'

Where:
* %m is the time and date
* %u is the username
* %c is the session ID for the connection

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 101. CD16-00-011400 | SV-261958r1000879

- Rule ID: SV-261958r1000879
- Severity: medium
- Rule Title: PostgreSQL must generate audit records for all privileged activities or other system-level access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records for privileged activities via pgaudit configuration in postgresql.conf (shared_preload_libraries, pgaudit.log).
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server, database initialization, or direct DBMS configuration management in any provided code or configuration files.
- The application is not a database product and does not bundle or manage a PostgreSQL instance.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed the following configurations can be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):
shared_preload_libraries = 'pgaudit'
pgaudit.log='ddl, role, read, write'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 102. CD16-00-011500 | SV-261959r1000882

- Rule ID: SV-261959r1000882
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records for unsuccessful privileged activity attempts, verified via PostgreSQL logs and configuration (pgaudit, logging settings).
- No postgresql.conf, pgaudit configuration, or log management for PostgreSQL is present in the repository (manifest reviewed).
- No evidence of embedded or managed PostgreSQL server in any code or configuration.
- The application is not a database product and does not control DBMS logging or auditing.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to execute privileged SQL.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 103. CD16-00-011600 | SV-261960r1000885

- Rule ID: SV-261960r1000885
- Severity: medium
- Rule Title: PostgreSQL must generate audit records showing starting and ending time for user access to the database(s).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records showing user connection/disconnection times, configured via postgresql.conf (log_connections, log_disconnections, log_line_prefix).
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

If logging is enabled the following configurations must be made to log connections, date/time, username, and session identifier.

As the database administrator (shown here as "postgres"), edit postgresql.conf by running the following:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters:

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %c: >'

Where:
* %m is the time and date
* %u is the username
* %c is the session ID for the connection

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 104. CD16-00-011700 | SV-261961r1000888

- Rule ID: SV-261961r1000888
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when concurrent logons/connections by the same user from different workstations occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to log concurrent logons/connections by the same user from different workstations, configured via postgresql.conf (log_connections, log_disconnections, log_line_prefix).
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

As the database administrator (shown here as "postgres"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters as such:

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %d %c: >'

Where:
* %m is the time and date
* %u is the username
* %d is the database
* %c is the session ID for the connection

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 105. CD16-00-011800 | SV-261962r1000891

- Rule ID: SV-261962r1000891
- Severity: medium
- Rule Title: PostgreSQL must be able to generate audit records when successful accesses to objects occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records for successful object access, verified via pgaudit and logging configuration in postgresql.conf.
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging or auditing.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

If logging is enabled, the following configurations must be made to log unsuccessful connections, date/time, username, and session identifier.

As the database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Edit the following parameters: 

log_connections = on 
log_line_prefix = '< %m %u %c: >' 
pgaudit.log = 'read, write' 

Where: 
* %m is the time and date 
* %u is the username 
* %c is the session ID for the connection 

As the system administrator, reload the server with the new configuration: 

$ sudo systemctl reload postgresql-${PGVER?}

---

### 106. CD16-00-011900 | SV-261963r1000894

- Rule ID: SV-261963r1000894
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when unsuccessful accesses to objects occur.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records for unsuccessful object access attempts, verified via PostgreSQL logs and configuration.
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging or auditing.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 107. CD16-00-012000 | SV-261964r1000897

- Rule ID: SV-261964r1000897
- Severity: medium
- Rule Title: PostgreSQL must generate audit records for all direct access to the database(s).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to generate audit records for all direct access to the database, verified via pgaudit and logging configuration (log_connections, log_disconnections).
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging or auditing.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

PostgreSQL can be configured to audit these requests using pgaudit. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, the following configurations should be made:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log='ddl, role, read, write'
log_connections='on'
log_disconnections='on'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 108. CD16-00-012200 | SV-261965r1137661

- Rule ID: SV-261965r1137661
- Severity: medium
- Rule Title: PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the operating system to be in FIPS mode (cat /proc/sys/crypto/fips_enabled = 1) for cryptographic operations in PostgreSQL.
- No OS-level configuration, FIPS enforcement, or OpenSSL system policy management is present in the repository (manifest reviewed).
- No code or scripts attempt to enable or check FIPS mode.
- The application is not a database product and does not manage OS cryptographic policy.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS or OS deployment; FIPS enforcement is out of scope.

Remediation:
Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, refer to the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 109. CD16-00-012300 | SV-261966r1137664

- Rule ID: SV-261966r1137664
- Severity: medium
- Rule Title: PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners' requirements.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires the operating system to be in FIPS mode (cat /proc/sys/crypto/fips_enabled = 1) for cryptographic protection of unclassified information in PostgreSQL.
- No OS-level configuration, FIPS enforcement, or OpenSSL system policy management is present in the repository (manifest reviewed).
- No code or scripts attempt to enable or check FIPS mode.
- The application is not a database product and does not manage OS cryptographic policy.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS or OS deployment; FIPS enforcement is out of scope.

Remediation:
Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, refer to the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 110. CD16-00-012400 | SV-261967r1000906

- Rule ID: SV-261967r1000906
- Severity: medium
- Rule Title: PostgreSQL must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for standalone systems.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to offload audit data to syslog (log_destination = 'syslog', syslog_facility, syslog_ident in postgresql.conf).
- No postgresql.conf or any PostgreSQL server configuration is present in the repository (manifest reviewed).
- No evidence of embedded PostgreSQL server or DBMS configuration management in any code or configuration files.
- The application is not a database product and does not manage DBMS logging or syslog offload.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; database audit offload configuration is out of scope.

Remediation:
Note: The following instructions use the PGDATA and PGVER environment variables. Refer to APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system, continuously and in near real time where a continuous network connection to the log management system exists, or at least weekly in the absence of such a connection.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

With logging enabled, as the database administrator (shown here as "postgres"), configure the following parameters in postgresql.conf (the example uses the default values - tailor for environment):

Note: Consult the organization on how syslog facilities are defined in the syslog daemon configuration.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'

As the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

---

### 111. CD16-00-009300 | SV-283674r1193281

- Rule ID: SV-283674r1193281
- Severity: high
- Rule Title: PostgreSQL products must be a version supported by the vendor.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-30.
- The control requires PostgreSQL to be a vendor-supported version, verified via psql --version or package manager queries.
- No PostgreSQL server, binaries, or embedded DBMS are present in the repository (manifest reviewed).
- No code or scripts install, manage, or bundle PostgreSQL.
- The application is not a database product and does not ship or control the DBMS version.
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS deployment; DBMS version management is out of scope.

Remediation:
Upgrade or install a version of the product supported by the vendor.

---
