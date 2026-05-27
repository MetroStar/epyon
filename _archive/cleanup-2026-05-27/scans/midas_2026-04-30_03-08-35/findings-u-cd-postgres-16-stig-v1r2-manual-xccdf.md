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
- This application is not a PostgreSQL database or a database management system. It is an AI-powered code analysis and migration platform (MIDAS) with no embedded or managed PostgreSQL instance. No postgresql.conf, pg_hba.conf, or SQL role/connection management is present in the provided source code or configuration files.
- File: etc/atlas/config.yaml — no PostgreSQL configuration or connection settings
- File: README.md — no mention of PostgreSQL as a runtime dependency or embedded component
- File: Makefile — no database setup, migration, or connection logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; session-count controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no pg_hba.conf, no PostgreSQL authentication configuration, and no evidence of direct PostgreSQL user/role management. The application does not embed or manage a PostgreSQL instance.
- File: etc/atlas/config.yaml — no PostgreSQL authentication or pg_hba.conf settings
- File: README.md — no mention of PostgreSQL authentication integration
- File: Makefile — no database authentication or user management logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; authentication integration controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There are no SQL role/privilege management operations, no pg_hba.conf, and no database object access control configuration. The application does not manage PostgreSQL roles or privileges.
- File: etc/atlas/config.yaml — no PostgreSQL role or privilege configuration
- File: README.md — no mention of PostgreSQL object access control
- File: Makefile — no database privilege management logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; access control policy enforcement does not apply

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
- This application is not a PostgreSQL database or DBMS. There is no postgresql.conf, no log_line_prefix, and no shared_preload_libraries configuration. The application does not generate or manage PostgreSQL audit logs.
- File: etc/atlas/config.yaml — no PostgreSQL logging or audit configuration
- File: README.md — no mention of PostgreSQL audit log settings
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit repudiation controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no audit log generation for DOD-defined events at the database level, and no pgaudit or equivalent audit configuration is present.
- File: etc/atlas/config.yaml — no PostgreSQL audit log or pgaudit configuration
- File: README.md — no mention of PostgreSQL audit event logging
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record generation controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no postgresql.conf, no audit event selection, and no database administrator role management. The application does not allow or restrict audit event selection for PostgreSQL.
- File: etc/atlas/config.yaml — no PostgreSQL audit event configuration
- File: README.md — no mention of PostgreSQL audit event selection
- File: Makefile — no database audit event management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit event selection controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no pgaudit, no shared_preload_libraries, and no audit record generation for privilege/permission retrieval. The application does not manage or audit PostgreSQL privileges.
- File: etc/atlas/config.yaml — no PostgreSQL audit or pgaudit configuration
- File: README.md — no mention of PostgreSQL privilege audit logging
- File: Makefile — no database privilege audit logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; privilege audit controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no audit record generation for unsuccessful privilege/permission retrieval attempts, and no pgaudit or equivalent configuration.
- File: etc/atlas/config.yaml — no PostgreSQL audit or pgaudit configuration
- File: README.md — no mention of PostgreSQL unsuccessful privilege audit logging
- File: Makefile — no database privilege audit logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; unsuccessful privilege audit controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no pgaudit, no shared_preload_libraries, and no log_destination configuration for session auditing. The application does not manage PostgreSQL session audit logs.
- File: etc/atlas/config.yaml — no PostgreSQL audit or session logging configuration
- File: README.md — no mention of PostgreSQL session audit logging
- File: Makefile — no database session audit logic
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; session audit controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_line_prefix, log_connections, or log_disconnections configuration for audit record content. The application does not generate PostgreSQL audit records.
- File: etc/atlas/config.yaml — no PostgreSQL audit log configuration
- File: README.md — no mention of PostgreSQL audit record content
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record content controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_line_prefix configuration for timestamped audit records. The application does not generate PostgreSQL audit logs with timestamps.
- File: etc/atlas/config.yaml — no PostgreSQL log_line_prefix or timestamp configuration
- File: README.md — no mention of PostgreSQL audit record timestamps
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record timestamp controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_line_prefix configuration for location information in audit records. The application does not generate PostgreSQL audit logs with location data.
- File: etc/atlas/config.yaml — no PostgreSQL log_line_prefix or location configuration
- File: README.md — no mention of PostgreSQL audit record location
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record location controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_line_prefix or log_hostname configuration for source/origin information in audit records. The application does not generate PostgreSQL audit logs with source/origin data.
- File: etc/atlas/config.yaml — no PostgreSQL log_line_prefix or log_hostname configuration
- File: README.md — no mention of PostgreSQL audit record source/origin
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record source/origin controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no audit record generation for event outcomes (success/failure), and no pgaudit or equivalent configuration. The application does not generate PostgreSQL audit logs with event outcomes.
- File: etc/atlas/config.yaml — no PostgreSQL audit or pgaudit configuration
- File: README.md — no mention of PostgreSQL audit record outcomes
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record outcome controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_line_prefix configuration for user/subject/process identity in audit records. The application does not generate PostgreSQL audit logs with user/process identity.
- File: etc/atlas/config.yaml — no PostgreSQL log_line_prefix or identity configuration
- File: README.md — no mention of PostgreSQL audit record identity
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit record identity controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no configuration or evidence of organization-defined additional audit information in PostgreSQL audit records. The application does not generate or manage PostgreSQL audit logs.
- File: etc/atlas/config.yaml — no PostgreSQL audit or additional information configuration
- File: README.md — no mention of PostgreSQL audit record customization
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; organization-defined audit record controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no audit log storage, monitoring, or shutdown-on-audit-failure logic for PostgreSQL. The application does not generate or manage PostgreSQL audit logs or storage.
- File: etc/atlas/config.yaml — no PostgreSQL audit log storage or monitoring configuration
- File: README.md — no mention of PostgreSQL audit log storage or shutdown procedures
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit log storage/shutdown controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no audit log rotation, FIFO, or disk space management for PostgreSQL audit logs. The application does not generate or manage PostgreSQL audit logs or log rotation.
- File: etc/atlas/config.yaml — no PostgreSQL audit log rotation or disk management configuration
- File: README.md — no mention of PostgreSQL audit log rotation or FIFO
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit log FIFO/rotation controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_file_mode or audit log file permission configuration for PostgreSQL. The application does not generate or manage PostgreSQL audit logs or their file permissions.
- File: etc/atlas/config.yaml — no PostgreSQL log_file_mode or audit log permission configuration
- File: README.md — no mention of PostgreSQL audit log file permissions
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit log read-access controls do not apply

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
- This application is not a PostgreSQL database or DBMS. There is no log_file_mode or audit log file permission/ownership configuration for PostgreSQL. The application does not generate or manage PostgreSQL audit logs or their file permissions/ownership.
- File: etc/atlas/config.yaml — no PostgreSQL log_file_mode or audit log permission/ownership configuration
- File: README.md — no mention of PostgreSQL audit log file permissions/ownership
- File: Makefile — no database audit log management
- Requirement: NOT APPLICABLE — application is not a PostgreSQL DBMS; audit log modification controls do not apply

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
- This application is a Python-based AI/code analysis platform and does not include or manage a PostgreSQL database instance, nor does it configure or control PostgreSQL audit log storage or permissions.
- No files named or referencing 'postgresql.conf', 'PGLOG', or log file permissions found in the provided source or configuration files.
- No code or configuration for database log file management or OS-level file permissions.
- Requirement: NOT APPLICABLE — No PostgreSQL database or audit log management present in this application.

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
- This application does not install, configure, or manage a PostgreSQL database or its audit features.
- No references to 'PGLOG', 'PGDATA', 'pgaudit', or PostgreSQL role/privilege management in any provided code or configuration.
- No SQL, database user, or privilege management code present.
- Requirement: NOT APPLICABLE — PostgreSQL audit feature access is not managed by this application.

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
- No PostgreSQL database or audit configuration is present or managed by this application.
- No 'postgresql.conf', 'PGDATA', or log_file_mode settings found in any configuration or code.
- No code or documentation for managing database configuration file permissions.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL audit configuration.

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
- No PostgreSQL installation, binaries, or audit features are managed by this application.
- No references to 'PGDATA', '/usr/pgsql-', or database binaries in any code or configuration.
- No code for managing file system permissions or ownership of database files.
- Requirement: NOT APPLICABLE — Application does not manage or remove PostgreSQL audit features.

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
- No PostgreSQL configuration files, shared libraries, or binaries are present or managed by this application.
- No code for managing permissions or ownership of database configuration or binaries.
- No references to 'postgresql.conf', '/usr/pgsql-', or related file paths.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL software modules or permissions.

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
- No PostgreSQL software installation accounts are created, managed, or referenced by this application.
- No code or documentation for user account management related to PostgreSQL installation.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL installation accounts.

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
- No PostgreSQL software, configuration files, or directories are installed or managed by this application.
- No code or configuration for database software directory management.
- Requirement: NOT APPLICABLE — Application does not install or manage PostgreSQL software directories.

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
- No database objects (tables, indexes, stored procedures, etc.) are created or managed by this application.
- No SQL DDL, database schema, or object ownership code present.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL database objects or their ownership.

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
- No code or configuration for managing PostgreSQL roles, groups, or privileges is present.
- No SQL privilege management, role assignment, or database directory permission code found.
- Requirement: NOT APPLICABLE — Application does not manage database structure or logic module privileges.

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
- No PostgreSQL extensions or database components are installed, managed, or removed by this application.
- No code for listing, installing, or removing database extensions.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL extensions or components.

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
- No PostgreSQL packages or integrated components are installed or managed by this application.
- No code for package management or disabling database components.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL packages or integrated components.

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
- No use of PostgreSQL COPY command, superuser roles, or extensions that access external executables is present.
- No code for database role management or extension installation.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL access to external executables.

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
- No PostgreSQL port, protocol, or service configuration is present in this application.
- No code or configuration for database network settings.
- Requirement: NOT APPLICABLE — Application does not configure PostgreSQL ports, protocols, or services.

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
- No PostgreSQL user, role, or authentication configuration is present or managed by this application.
- No code for user creation, authentication, or pg_hba.conf management.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL user authentication.

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
- No PostgreSQL password storage or authentication is implemented or managed by this application.
- No code for password storage, encryption, or database user management.
- Requirement: NOT APPLICABLE — Application does not store or manage PostgreSQL passwords.

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
- No PostgreSQL authentication or password transmission is implemented or managed by this application.
- No code for pg_hba.conf, password authentication, or transmission method configuration.
- Requirement: NOT APPLICABLE — Application does not transmit PostgreSQL passwords.

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
- No PKI-based authentication or certificate validation for PostgreSQL is implemented or managed by this application.
- No code or configuration for SSL, CRL files, or certificate validation in a database context.
- Requirement: NOT APPLICABLE — Application does not use or manage PostgreSQL PKI authentication.

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
- No PKI private keys for PostgreSQL are stored, used, or managed by this application.
- No code or configuration for SSL key file management or access control.
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL PKI private keys.

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
- No PKI authentication or user mapping for PostgreSQL is implemented or managed by this application.
- No code for certificate CN mapping, pg_ident.conf, or user mapping logic.
- Requirement: NOT APPLICABLE — Application does not map PKI identities to PostgreSQL users.

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
- No cryptographic operations for PostgreSQL are performed or managed by this application, nor is FIPS mode relevant to its operation.
- No code for enabling FIPS mode, checking OpenSSL providers, or configuring cryptographic modules for a database.
- Requirement: NOT APPLICABLE — Application does not perform PostgreSQL cryptographic operations or require FIPS validation.

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
- This application is not a PostgreSQL database nor does it implement or manage PostgreSQL user roles directly. No SQL, role management, or user authentication logic for PostgreSQL is present in any provided code or configuration file. All authentication is handled via OIDC/OAuth2 (see security/middleware.py and etc/atlas/config.yaml). - Requirement: NOT APPLICABLE — No PostgreSQL user management or direct DBMS role handling in scope.

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
- This application does not implement or expose PostgreSQL user or administrative roles. All user authentication and authorization is handled via OAuth2/OIDC middleware (see security/middleware.py), and there is no evidence of PostgreSQL administrative or user role separation logic. - Requirement: NOT APPLICABLE — No PostgreSQL user/administrator role management in application scope.

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
- No PostgreSQL session management or configuration is present in the application. The application does not manage PostgreSQL sessions or configure session timeouts (e.g., tcp_keepalives_idle, statement_timeout). All session management is handled at the application layer via OAuth2/OIDC (see security/middleware.py). - Requirement: NOT APPLICABLE — No PostgreSQL session management in application.

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
- No PostgreSQL SSL/TLS configuration or direct database connection logic is present in the application. The application does not configure or manage PostgreSQL network security (e.g., 'ssl = on'). All network security is handled at the application layer via HTTP/ASGI/OAuth2. - Requirement: NOT APPLICABLE — No PostgreSQL network configuration in application.

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
- No PostgreSQL data storage or encryption at rest is implemented or configured by the application. The application does not store or manage PostgreSQL data directly, nor does it use or configure pgcrypto or disk encryption for PostgreSQL. - Requirement: NOT APPLICABLE — No PostgreSQL data at rest in application.

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
- No PostgreSQL schemas, security objects, or access controls are managed by the application. The application does not define or separate security functions within PostgreSQL schemas or databases. All security logic is implemented at the application layer (see security/middleware.py). - Requirement: NOT APPLICABLE — No PostgreSQL schema or security object management in application.

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
- The application implements ingestion pipelines for moving and indexing data from various sources (see etc/atlas/config.yaml 'ingestion.pipelines'), but there is no explicit evidence of enforcement of a data-transfer policy or removal of production data from unprotected locations. - File: etc/atlas/config.yaml — ingestion.pipelines: defines multiple pipelines for moving data (e.g., python-project, java-project, git-project), but no explicit data-transfer policy enforcement or secure deletion logic is present. - File: lib/ingestion/security.py — InputValidator and AuditLogger provide validation and logging, but do not enforce data-transfer policy or secure deletion of production data copies. - Requirement: PARTIALLY SATISFIED — Data movement is implemented, but enforcement of organization-defined data-transfer policy and secure removal of production data from unprotected locations is not evidenced.

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
- The application does not manage or store PostgreSQL database files, logs, or backups. All data storage is handled at the application layer (e.g., vectorstores, knowledgebase), not at the PostgreSQL file system level. No file permission logic for PostgreSQL data files is present. - Requirement: NOT APPLICABLE — No PostgreSQL file system or database file management in application.

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
- The ingestion pipeline includes an InputValidator (lib/ingestion/security.py) that checks for path traversal, content size, encoding, and content type, but there is no evidence of database column/field constraints or prepared statement usage for PostgreSQL. - File: lib/ingestion/security.py — InputValidator: validates path traversal, content size, encoding, and content type for RawRecord objects. - File: knowledgebase/parsers/schema.py — Defines canonical output schemas for parsed files, but does not enforce database constraints. - No evidence of prepared statement usage for PostgreSQL or explicit input validation at the database layer. - Requirement: PARTIALLY SATISFIED — Application validates input at the ingestion layer, but does not use prepared statements or enforce database constraints for PostgreSQL.

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
- No direct evidence of dynamic code execution (e.g., eval, exec, or SQL code generation) is present in the provided files. However, the ingestion pipeline and plugin system may allow for dynamic script execution (see plugins/custom_script.py, not included in context). - File: lib/ingestion/security.py — InputValidator and AuditLogger provide input validation and logging, but do not restrict dynamic code execution. - File: scripts/example.sh — Example shell script for testing, but not dynamically executed by the application. - Requirement: PARTIALLY SATISFIED — No evidence of unrestricted dynamic code execution, but enforcement of restriction to necessary cases only cannot be confirmed from static artifacts alone.

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
- No direct evidence of dynamic code execution with input scanning for code injection is present in the provided files. InputValidator (lib/ingestion/security.py) checks for path traversal, encoding, and content type, but does not scan for code injection patterns. - File: lib/ingestion/security.py — InputValidator: validates path traversal, encoding, and content type, but does not implement code injection scanning. - Requirement: PARTIALLY SATISFIED — Input validation is present, but explicit scanning for code injection in dynamic code execution contexts is not evidenced.

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
- No PostgreSQL database or configuration is present in the application. The application does not expose or configure PostgreSQL error message levels (e.g., client_min_messages). All error handling is performed at the application layer (see security/middleware.py). - Requirement: NOT APPLICABLE — No PostgreSQL error message configuration in application.

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
- No PostgreSQL database or log file management is present in the application. The application does not configure client_min_messages or log_file_mode for PostgreSQL. All error handling and logging is performed at the application layer (see security/middleware.py and lib/clio.py). - Requirement: NOT APPLICABLE — No PostgreSQL error message or log file management in application.

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
- No PostgreSQL session management or user session termination logic is present in the application. All session management is handled via OAuth2/OIDC middleware (see security/middleware.py), not at the PostgreSQL layer. - Requirement: NOT APPLICABLE — No PostgreSQL session termination logic in application.

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
- No PostgreSQL database or security labeling is implemented or required by the application. The application does not define or manage security labels for database tables or rows. - Requirement: NOT APPLICABLE — No PostgreSQL security labeling in application.

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
- No PostgreSQL database or security labeling is implemented or required by the application. The application does not define or manage security labels for information in process. - Requirement: NOT APPLICABLE — No PostgreSQL security labeling in application.

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
- No PostgreSQL database or security labeling is implemented or required by the application. The application does not define or manage security labels for information in transmission. - Requirement: NOT APPLICABLE — No PostgreSQL security labeling in application.

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
- No PostgreSQL database objects, schemas, or discretionary access control policies are managed by the application. All access control is handled at the application layer via OAuth2/OIDC (see security/middleware.py). - Requirement: NOT APPLICABLE — No PostgreSQL DAC policy enforcement in application.

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
- No PostgreSQL privileged functions or procedural language extensions (pl/Python, pl/R) are used or managed by the application. All privileged functionality is handled at the application layer via OAuth2/OIDC and application logic. - Requirement: NOT APPLICABLE — No PostgreSQL privileged function management in application.

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
- No PostgreSQL stored procedures, functions, or triggers with elevated privileges are created or managed by the application. All privilege management is handled at the application layer via OAuth2/OIDC and application logic. - Requirement: NOT APPLICABLE — No PostgreSQL SECURITY DEFINER or privilege elevation in application.

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
- This application is not a PostgreSQL database nor does it include any embedded PostgreSQL instance or configuration. No postgresql.conf, SQL, or database management code is present in the provided files. All configuration is for the MIDAS application and its plugins, not for a database server.
- File: etc/atlas/config.yaml — no PostgreSQL configuration present
- File: Makefile — no PostgreSQL service management or configuration
- File: pyproject.toml — no PostgreSQL dependency
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; centralized audit record management for PostgreSQL does not apply.

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
- This application does not manage PostgreSQL audit log storage or allocate storage for PostgreSQL logs. No PostgreSQL instance or log management is present in the codebase or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL log or storage configuration
- File: Makefile — no log storage allocation for PostgreSQL
- File: pyproject.toml — no PostgreSQL dependency
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL audit log storage; control applies only to DBMS administrators.

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
- No scripts, tools, or configuration in this repository monitor PostgreSQL log storage or notify support staff about audit log storage thresholds. The application does not manage PostgreSQL or its logs.
- File: etc/atlas/config.yaml — no monitoring scripts or alerting for PostgreSQL log storage
- File: Makefile — no cron jobs or disk monitoring for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage or monitor PostgreSQL audit log storage; this is a DBMS/OS administrator responsibility.

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
- No configuration or code in this repository provides real-time alerting for PostgreSQL audit log failures. The application does not operate or monitor a PostgreSQL instance.
- File: etc/atlas/config.yaml — no audit log failure alerting for PostgreSQL
- File: Makefile — no alerting scripts or hooks for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL auditing or alerting; this is a DBMS/OS administrator responsibility.

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
- No PostgreSQL instance or log_timezone configuration is present in the application. The application does not generate or manage PostgreSQL audit records or timestamps.
- File: etc/atlas/config.yaml — no log_timezone or time zone configuration for PostgreSQL
- File: Makefile — no PostgreSQL cluster initialization or timezone management
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL audit records or time zones.

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
- No PostgreSQL log_line_prefix or logging configuration is present in the application. The application does not generate or manage PostgreSQL audit logs or timestamps.
- File: etc/atlas/config.yaml — no log_line_prefix or PostgreSQL logging configuration
- File: Makefile — no PostgreSQL logging management
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL logging or audit records.

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
- No PostgreSQL user, role, or privilege management is present in the application. The application does not provide a database or stored procedure environment for users to install logic modules.
- File: etc/atlas/config.yaml — no PostgreSQL user or privilege configuration
- File: Makefile — no database privilege management
- Requirement: NOT APPLICABLE — Application does not provide a PostgreSQL environment for user logic modules.

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
- No PostgreSQL role, SUPERUSER, or privilege management is present in the application. The application does not provide or manage a database configuration environment.
- File: etc/atlas/config.yaml — no PostgreSQL role or privilege configuration
- File: Makefile — no ALTER ROLE or REVOKE commands
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL configuration or access restrictions.

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
- No PostgreSQL configuration file ownership or audit denial logging is present in the application. The application does not manage or operate a PostgreSQL instance.
- File: etc/atlas/config.yaml — no postgresql.conf or file permission management
- File: Makefile — no PostgreSQL file management
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL configuration files or audit logging.

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
- No PostgreSQL port, protocol, or network function configuration is present in the application. The application does not operate or configure a PostgreSQL server.
- File: etc/atlas/config.yaml — no PostgreSQL port or protocol configuration
- File: Makefile — no PostgreSQL port management
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL network functions or ports.

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
- No PostgreSQL user session or reauthentication management is present in the application. The application does not provide a database or session environment for users.
- File: etc/atlas/config.yaml — no PostgreSQL session or reauthentication configuration
- File: Makefile — no session management for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL user sessions or reauthentication.

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
- No PostgreSQL SSL or cryptography configuration is present in the application. The application does not operate a PostgreSQL server or manage classified information at the database level.
- File: etc/atlas/config.yaml — no PostgreSQL SSL or cryptography settings
- File: Makefile — no SSL configuration for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL cryptography or classified data.

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
- No PostgreSQL certificate or CA configuration is present in the application. The application does not operate a PostgreSQL server or manage SSL/TLS certificates for database connections.
- File: etc/atlas/config.yaml — no ssl_ca_file or ssl_cert_file settings for PostgreSQL
- File: Makefile — no certificate management for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL certificates or CA trust.

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
- No PostgreSQL data-at-rest encryption or pgcrypto extension configuration is present in the application. The application does not store or manage PII or classified information in a PostgreSQL database.
- File: etc/atlas/config.yaml — no pgcrypto or data-at-rest encryption settings for PostgreSQL
- File: Makefile — no encryption configuration for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL data-at-rest encryption.

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
- No PostgreSQL pgcrypto extension or disk/filesystem encryption configuration is present in the application. The application does not store sensitive information in a PostgreSQL database or manage its encryption.
- File: etc/atlas/config.yaml — no pgcrypto or disk encryption settings for PostgreSQL
- File: Makefile — no encryption configuration for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL data-at-rest or disk encryption.

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
- No PostgreSQL SSL or data-in-transit protection configuration is present in the application. The application does not operate a PostgreSQL server or manage data transmission for a database.
- File: etc/atlas/config.yaml — no SSL or transmission protection for PostgreSQL
- File: Makefile — no SSL configuration for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL data transmission or confidentiality/integrity during transmission.

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
- No PostgreSQL SSL or data-in-transit protection configuration is present in the application. The application does not operate a PostgreSQL server or manage data reception for a database.
- File: etc/atlas/config.yaml — no SSL or reception protection for PostgreSQL
- File: Makefile — no SSL configuration for PostgreSQL
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL data reception or confidentiality/integrity during reception.

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
- No PostgreSQL error handling or input validation for SQL is present in the application. The application does not provide a SQL interface or manage PostgreSQL error logging.
- File: etc/atlas/config.yaml — no PostgreSQL error handling configuration
- File: Makefile — no SQL error handling or logging
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL input validation or error logging.

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
- No PostgreSQL package management or version control is present in the application. The application does not install, update, or remove PostgreSQL software components.
- File: etc/atlas/config.yaml — no PostgreSQL package management
- File: Makefile — no PostgreSQL installation or removal commands
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL software updates or component removal.

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
- No PostgreSQL version management or update policy is present in the application. The application does not install or update PostgreSQL software or track its security advisories.
- File: etc/atlas/config.yaml — no PostgreSQL version or update configuration
- File: Makefile — no PostgreSQL update commands
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL software updates or patching.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'shared_preload_libraries' or 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets logging for unsuccessful access attempts to security objects.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit or logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets logging for unsuccessful privilege/permission changes.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit or logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets logging for unsuccessful privilege/permission changes.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit or logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log_catalog' or 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets logging for unsuccessful security object modifications.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit or logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets logging for unsuccessful privilege/permission deletions.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit or logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit settings such as pgaudit. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'pgaudit.log'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no pgaudit configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'log_connections' or 'log_line_prefix'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database server and does not include any static configuration or management of PostgreSQL audit or logging settings. No postgresql.conf or SQL configuration files are present in the repository. No code or configuration manages or sets 'log_connections' or 'log_line_prefix'.
- File: [entire manifest] — no postgresql.conf, no SQL scripts, no logging configuration
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL DBMS; database audit configuration is outside the scope of this repository.

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
- This application is not a PostgreSQL database nor does it contain any embedded PostgreSQL configuration or management code.
- File: etc/atlas/config.yaml — No references to 'shared_preload_libraries', 'pgaudit', or direct PostgreSQL configuration present
- File: README.md — No mention of PostgreSQL database setup or management; focus is on AI code analysis and ingestion pipelines
- File: Makefile — No database setup or management targets; no SQL or PostgreSQL references
- Requirement: NOT APPLICABLE — This is an application codebase, not a PostgreSQL database server; control applies only to PostgreSQL DBMS configuration

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
- This application does not manage or configure PostgreSQL logging or auditing for privileged activity attempts.
- File: etc/atlas/config.yaml — No PostgreSQL log configuration or references to 'log_destination', 'pgaudit', or SQL auditing
- File: README.md — No mention of database audit or error logging configuration
- File: Makefile — No database or audit log management
- Requirement: NOT APPLICABLE — This is not a PostgreSQL database system; control applies to DBMS audit configuration

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
- No PostgreSQL database or logging configuration is present in the application.
- File: etc/atlas/config.yaml — No settings for 'log_connections', 'log_disconnections', or 'log_line_prefix'
- File: README.md — No instructions for database log configuration
- File: Makefile — No database log management
- Requirement: NOT APPLICABLE — This application does not run or configure a PostgreSQL database; control applies to DBMS logging

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
- No evidence of PostgreSQL database configuration or log management for concurrent logons/connections.
- File: etc/atlas/config.yaml — No 'log_connections', 'log_disconnections', or 'log_line_prefix' settings
- File: README.md — No mention of database log or session management
- File: Makefile — No database or session log management
- Requirement: NOT APPLICABLE — This is not a PostgreSQL DBMS; control applies to database server configuration

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
- No PostgreSQL audit configuration or pgaudit settings found in the application.
- File: etc/atlas/config.yaml — No 'pgaudit.log', 'shared_preload_libraries', or related audit settings
- File: README.md — No mention of database audit or object access logging
- File: Makefile — No database or audit log management
- Requirement: NOT APPLICABLE — This application does not manage or configure a PostgreSQL database; control applies to DBMS audit configuration

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
- No evidence of PostgreSQL audit or error logging for unsuccessful object access attempts.
- File: etc/atlas/config.yaml — No settings for PostgreSQL error/audit logging
- File: README.md — No mention of database error or audit log configuration
- File: Makefile — No database or audit log management
- Requirement: NOT APPLICABLE — This is not a PostgreSQL DBMS; control applies to database server configuration

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
- No PostgreSQL audit or connection logging configuration present in the application.
- File: etc/atlas/config.yaml — No 'pgaudit', 'log_connections', or 'log_disconnections' settings
- File: README.md — No mention of database audit or connection logging
- File: Makefile — No database or audit log management
- Requirement: NOT APPLICABLE — This application does not run or configure a PostgreSQL database; control applies to DBMS audit configuration

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
- No evidence of FIPS 140-2/140-3 cryptographic module configuration or enforcement for PostgreSQL or OpenSSL.
- File: etc/atlas/config.yaml — No references to FIPS, OpenSSL, or cryptographic module settings
- File: README.md — No mention of FIPS mode or cryptographic module configuration
- File: Makefile — No cryptographic or FIPS-related targets
- Requirement: NOT APPLICABLE — This application does not manage system cryptographic modules or PostgreSQL; control applies to system/DBMS configuration

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
- No evidence of FIPS 140-2/140-3 cryptographic module configuration or enforcement for PostgreSQL or OpenSSL.
- File: etc/atlas/config.yaml — No references to FIPS, OpenSSL, or cryptographic module settings
- File: README.md — No mention of FIPS mode or cryptographic module configuration
- File: Makefile — No cryptographic or FIPS-related targets
- Requirement: NOT APPLICABLE — This application does not manage system cryptographic modules or PostgreSQL; control applies to system/DBMS configuration

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
- No evidence of PostgreSQL syslog or log offloading configuration.
- File: etc/atlas/config.yaml — No 'log_destination', 'syslog_facility', or 'syslog_ident' settings
- File: README.md — No mention of syslog or audit log offloading
- File: Makefile — No syslog or log management targets
- Requirement: NOT APPLICABLE — This application does not manage or configure PostgreSQL logging; control applies to DBMS log management

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
- No PostgreSQL server or client is bundled, installed, or managed by this application.
- File: pyproject.toml — No PostgreSQL client or server dependencies (e.g., psycopg2, postgresql)
- File: README.md — No instructions for installing or managing PostgreSQL
- File: Makefile — No targets for database installation or version checks
- Requirement: NOT APPLICABLE — This application does not include or manage PostgreSQL; control applies to DBMS version management

Remediation:
Upgrade or install a version of the product supported by the vendor.

---
