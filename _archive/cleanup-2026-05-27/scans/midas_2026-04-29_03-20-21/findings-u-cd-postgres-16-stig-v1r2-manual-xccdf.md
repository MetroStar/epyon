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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database nor does it contain any PostgreSQL configuration files such as postgresql.conf or pg_hba.conf. No SQL, database connection, or session management code for PostgreSQL is present in the provided files (etc/atlas/config.yaml, core/project_resource.py, lib/vex.py, plugins/advice.py, security/__init__.py, Makefile, README.md, utils/midas-configure-vscode.py, tests/security/__init__.py). The application is an AI/knowledgebase orchestration and analysis platform, not a database server. - Requirement: NOT APPLICABLE — PostgreSQL session controls do not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL database or pg_hba.conf authentication configuration is present in the application. The application does not manage PostgreSQL user authentication or access. No references to PostgreSQL authentication methods (gss, sspi, ldap, cert) or pg_hba.conf are found in any provided file. - Requirement: NOT APPLICABLE — PostgreSQL authentication integration does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL database, roles, or access control configuration is present in the application. No SQL privilege management, role creation, or grant/revoke logic is found in the provided files. The application does not implement or manage PostgreSQL object access controls. - Requirement: NOT APPLICABLE — PostgreSQL access control enforcement does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL logging or audit configuration is present. No log_line_prefix or shared_preload_libraries settings are found in any configuration or code file. The application does not generate or manage PostgreSQL audit logs. - Requirement: NOT APPLICABLE — PostgreSQL audit repudiation controls do not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit log generation or pgaudit configuration is present. The application does not generate or manage PostgreSQL audit records for DOD-defined events. No references to pgaudit, audit logging, or SQL event auditing are found in the provided files. - Requirement: NOT APPLICABLE — PostgreSQL audit event generation does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit configuration or permissions are present. No PGDATA directory, postgresql.conf, or role management for audit selection is found. The application does not allow or restrict audit event selection for PostgreSQL. - Requirement: NOT APPLICABLE — PostgreSQL audit event selection controls do not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit logging or pgaudit configuration is present. The application does not generate audit records for privilege/permission retrieval in PostgreSQL. No references to pgaudit, log_catalog, or audit logging are found. - Requirement: NOT APPLICABLE — PostgreSQL privilege retrieval auditing does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit logging or pgaudit configuration is present. The application does not generate audit records for unsuccessful privilege/permission retrieval in PostgreSQL. No references to pgaudit, log_catalog, or audit logging are found. - Requirement: NOT APPLICABLE — PostgreSQL unsuccessful privilege retrieval auditing does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL session auditing or pgaudit configuration is present. The application does not initiate or manage PostgreSQL session auditing. No references to shared_preload_libraries, log_destination, or pgaudit are found. - Requirement: NOT APPLICABLE — PostgreSQL session auditing does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL log_line_prefix, log_connections, or log_disconnections settings are present. The application does not generate or manage PostgreSQL audit records with event type information. No references to these settings are found in any provided file. - Requirement: NOT APPLICABLE — PostgreSQL audit event type logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL log_line_prefix or timestamp logging configuration is present. The application does not generate or manage PostgreSQL audit records with timestamps. No references to log_line_prefix or %m are found. - Requirement: NOT APPLICABLE — PostgreSQL audit timestamp logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL log_line_prefix or location logging configuration is present. The application does not generate or manage PostgreSQL audit records with location information. No references to log_line_prefix or %m %u %d %s are found. - Requirement: NOT APPLICABLE — PostgreSQL audit location logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL log_line_prefix or log_hostname configuration is present. The application does not generate or manage PostgreSQL audit records with source/origin information. No references to log_line_prefix, log_hostname, or related settings are found. - Requirement: NOT APPLICABLE — PostgreSQL audit source/origin logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit logging or pgaudit configuration is present. The application does not generate or manage PostgreSQL audit records with event outcome information. No references to pgaudit, log_line_prefix, or error logging are found. - Requirement: NOT APPLICABLE — PostgreSQL audit outcome logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL log_line_prefix or user/process identity logging configuration is present. The application does not generate or manage PostgreSQL audit records with user/process identity information. No references to log_line_prefix, %u, %p, or related settings are found. - Requirement: NOT APPLICABLE — PostgreSQL audit user/process identity logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit configuration or organization-defined audit detail settings are present. The application does not generate or manage PostgreSQL audit records with additional organization-defined information. No references to pgaudit, postgresql.conf, or audit detail settings are found. - Requirement: NOT APPLICABLE — PostgreSQL organization-defined audit detail logging does not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit log management or shutdown-on-audit-failure configuration is present. The application does not generate or manage PostgreSQL audit logs or handle audit log storage exhaustion. No references to audit log monitoring, shutdown procedures, or log storage management are found. - Requirement: NOT APPLICABLE — PostgreSQL audit failure shutdown controls do not apply to this application type.

Remediation:
Modify PostgreSQL, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.

---

### 18. CD16-00-001800 | SV-261874r1043188

- Rule ID: SV-261874r1043188
- Severity: medium
- Rule Title: PostgreSQL must be configurable to overwrite audit log records, oldest first (first-in-first-out [FIFO]), in the event of unavailability of space for more audit log records.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit log rotation or FIFO overwrite configuration is present. The application does not generate or manage PostgreSQL audit logs or handle log rotation/overwriting. No references to log rotation, log management, or audit log storage are found. - Requirement: NOT APPLICABLE — PostgreSQL audit log FIFO overwrite controls do not apply to this application type.

Remediation:
Establish a process with accompanying tools for monitoring available disk space and ensuring that sufficient disk space is maintained to continue generating audit logs, overwriting the oldest existing records if necessary.

---

### 19. CD16-00-002000 | SV-261875r1000630

- Rule ID: SV-261875r1000630
- Severity: medium
- Rule Title: The audit information produced by PostgreSQL must be protected from unauthorized read access.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit log file or log_file_mode configuration is present. The application does not generate or manage PostgreSQL audit logs or control their file permissions. No references to log_file_mode, audit log file locations, or permission settings are found. - Requirement: NOT APPLICABLE — PostgreSQL audit log read access controls do not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit log file or log_file_mode configuration is present. The application does not generate or manage PostgreSQL audit logs or control their file permissions or ownership. No references to log_file_mode, audit log file locations, or permission settings are found. - Requirement: NOT APPLICABLE — PostgreSQL audit log modification controls do not apply to this application type.

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL audit log file permissions and ownership (e.g., log_file_mode = 0600 in postgresql.conf, file system permissions on log files). The provided application is a Python-based AI system (MIDAS) and does not bundle, configure, or manage a PostgreSQL database or its log files. No postgresql.conf, log_file_mode, or database log management is present in the application source, configuration, or deployment scripts.
- File: etc/atlas/config.yaml — no PostgreSQL log configuration present
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL log files or permissions
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its audit log configuration

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL audit feature protection (ownership of PGLOG, PGDATA, pgaudit extension, and superuser role assignments). The application is a Python-based system and does not include, deploy, or configure a PostgreSQL database or its audit features. No references to PGLOG, PGDATA, pgaudit, or database role management are present in the source, configuration, or deployment scripts.
- File: etc/atlas/config.yaml — no PostgreSQL audit configuration or role management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL audit features or user roles
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its audit configuration

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL audit configuration file protection (ownership and permissions of postgresql.conf, log_file_mode, etc.). The application is a Python-based system and does not include, deploy, or configure a PostgreSQL database or its configuration files. No postgresql.conf, log_file_mode, or related file permission settings are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL configuration file management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL configuration files or permissions
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its configuration files

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL audit feature removal protection (ownership and permissions of PGDATA, /usr/pgsql-*/bin, /usr/pgsql-*/lib, etc.). The application is a Python-based system and does not include, deploy, or configure a PostgreSQL database or its binaries/libraries. No references to PGDATA, /usr/pgsql-*, or related file system paths are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL data directory or binary management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL binaries or directories
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its binaries

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of privilege restrictions for modifying PostgreSQL software modules (ownership and permissions of configuration files, shared libraries, executables). The application is a Python-based system and does not include, deploy, or configure a PostgreSQL database or its modules. No references to PostgreSQL configuration files, shared libraries, or executables are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL module or file permission management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL modules or binaries
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its modules

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
- Static repository review completed on 2026-04-29.
- This control requires evidence of procedures for restricting and tracking use of the PostgreSQL software installation account(s). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its installation accounts. No references to PostgreSQL installation accounts or related procedures are present in the application source or documentation.
- File: etc/atlas/config.yaml — no PostgreSQL account management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL installation accounts
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its installation accounts

Remediation:
Develop, document, and implement procedures to restrict and track use of the PostgreSQL software installation account(s).

---

### 27. CD16-00-002800 | SV-261883r1000654

- Rule ID: SV-261883r1000654
- Severity: medium
- Rule Title: Database software, including PostgreSQL configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL software and configuration files are stored in dedicated directories, separate from the host OS and other applications. The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its directories. No references to PostgreSQL software directories or DASD pools are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL directory management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL software directories
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its directories

Remediation:
Install all applications on directories separate from the PostgreSQL software library directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL software library directory.

---

### 28. CD16-00-002900 | SV-261884r1000657

- Rule ID: SV-261884r1000657
- Severity: medium
- Rule Title: Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/PostgreSQL principals authorized for ownership.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- This control requires static evidence of database object ownership by authorized PostgreSQL principals. The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its objects. No references to database object ownership, roles, or principals are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL object ownership management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL database objects or ownership
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its database objects

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of privilege restrictions for modifying PostgreSQL database structure and logic modules. The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its roles/privileges. No references to database roles, privileges, or structure modification are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL privilege or role management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL roles or privileges
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its privileges

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of removal of unused PostgreSQL extensions and database components. The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its extensions. No references to PostgreSQL extensions or component management are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL extension management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL extensions
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its extensions

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of removal or disabling of unused PostgreSQL packages integrated with the DBMS. The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its packages. No references to PostgreSQL package management are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL package management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL packages
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its packages

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of restriction of access to external executables via PostgreSQL (e.g., COPY command, superuser role assignments, extension management). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its roles/extensions. No references to PostgreSQL superuser roles, COPY command, or extension management are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL superuser or extension management
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL roles or external executables
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its external executable access

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL configuration to prohibit or restrict use of organization-defined functions, ports, protocols, or services (e.g., postgresql.conf settings for port and listen_addresses). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its network configuration. No references to postgresql.conf, port, or listen_addresses are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL port or protocol configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL network settings
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its network configuration

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PostgreSQL user identification and authentication configuration (e.g., unique roles, pg_hba.conf settings). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its authentication configuration. No references to pg_hba.conf, database roles, or authentication settings are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL authentication configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL authentication
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its authentication

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL stores only hashed, salted representations of passwords (e.g., password_encryption = 'scram-sha-256' in postgresql.conf). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its password storage configuration. No references to password_encryption or password storage settings are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL password storage configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL password storage
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its password storage

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL transmits only encrypted representations of passwords (e.g., pg_hba.conf entries using scram-sha-256, not password or md5). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its authentication configuration. No references to pg_hba.conf or authentication methods are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL authentication method configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL authentication methods
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its authentication methods

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence of PKI-based authentication and RFC 5280-compliant certificate path validation in PostgreSQL (e.g., ssl_crl_file, pg_hba.conf hostssl entries). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its SSL/TLS configuration. No references to ssl_crl_file, certificates, or PKI authentication are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL SSL/TLS or PKI configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL certificate validation
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its PKI authentication

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL enforces authorized access to PKI private keys (e.g., ssl_key_file permissions, directory protection). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its SSL/TLS key files. No references to ssl_key_file or private key storage are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL SSL/TLS key configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL private key management
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its PKI private keys

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL maps PKI-authenticated identities to user accounts (e.g., certificate CN matching, pg_ident.conf mappings). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its PKI authentication/user mapping configuration. No references to certificate mapping or pg_ident.conf are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL PKI user mapping configuration
- File: Makefile, pyproject.toml, README.md — no references to PostgreSQL PKI user mapping
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its PKI user mapping

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
- Static repository review completed on 2026-04-29.
- This control requires static evidence that PostgreSQL uses NIST FIPS 140-2/140-3 validated cryptographic modules for cryptographic operations (e.g., OS FIPS mode, OpenSSL FIPS provider). The application is a Python-based system and does not include, deploy, or manage a PostgreSQL database or its cryptographic modules. No references to FIPS mode, OpenSSL, or cryptographic module configuration are present in the application source or configuration.
- File: etc/atlas/config.yaml — no PostgreSQL cryptographic module configuration
- File: Makefile, pyproject.toml, README.md — no references to FIPS or cryptographic modules
- Requirement: NOT APPLICABLE — Application does not include or manage a PostgreSQL instance or its cryptographic modules

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database nor does it contain any embedded PostgreSQL server or direct database role management code. It is a Python application for code analysis and AI tooling, with no static artifacts for PostgreSQL user/role management.
- No postgresql.conf, pg_hba.conf, or SQL role management scripts present in the repository
- No code for creating, listing, or authenticating PostgreSQL users/roles
- Requirement: NOT APPLICABLE — Application does not implement or manage PostgreSQL user authentication or roles

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not implement or manage database roles or permissions. There is no static artifact for PostgreSQL administrative/user separation.
- No postgresql.conf, pg_hba.conf, or SQL scripts for role/privilege assignment
- No code for granting/revoking PostgreSQL superuser, createdb, createrole, or bypassrls privileges
- Requirement: NOT APPLICABLE — Application does not implement or manage PostgreSQL administrative/user separation

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not manage PostgreSQL session identifiers or timeouts. No static configuration or code for PostgreSQL session management is present.
- No postgresql.conf, pg_hba.conf, or code for setting tcp_keepalives_idle, tcp_keepalives_interval, tcp_keepalives_count, or statement_timeout
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL sessions or session timeouts

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not configure PostgreSQL SSL settings. No static configuration or code for PostgreSQL SSL is present.
- No postgresql.conf, pg_hba.conf, or code for setting 'ssl = on'
- Requirement: NOT APPLICABLE — Application does not configure PostgreSQL SSL or session security

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not store or manage data at rest in a PostgreSQL instance. No static configuration or code for pgcrypto or disk encryption is present.
- No SQL code for 'CREATE EXTENSION pgcrypto', no references to pgcrypto, no disk encryption configuration
- Requirement: NOT APPLICABLE — Application does not store data in PostgreSQL or manage encryption at rest

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not define or manage PostgreSQL schemas, tables, or security objects. No static configuration or code for PostgreSQL schema/object separation is present.
- No SQL code for GRANT/REVOKE on pg_catalog or information_schema, no schema definitions
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL schemas or security object separation

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
- Static repository review completed on 2026-04-29.
- Control requires procedures/scripts for moving production data to dev/test to comply with data transfer policy and ensure no unprotected copies remain.
- File: scripts/example.sh — contains only: 'echo "example script ran"' (test fixture, not a data movement script)
- File: etc/cobol_queries.py — contains only static COBOL code search queries, not data movement
- No scripts or code for copying, exporting, or transferring production data to dev/test systems found in provided files
- No evidence of data transfer policy enforcement or secure deletion of production data copies
- Requirement: PARTIALLY SATISFIED — No evidence of noncompliance, but also no evidence of compliant data movement procedures or enforcement of data transfer policy. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.

---

### 48. CD16-00-005600 | SV-261904r1137658

- Rule ID: SV-261904r1137658
- Severity: medium
- Rule Title: Access to database files must be limited to relevant processes and to authorized, administrative users.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- This application does not include or manage PostgreSQL database files, log files, or backup files. It is a Python application and does not control OS-level file permissions for database artifacts.
- No database files, log files, or backup files present in the repository
- No code for setting file permissions or ownership on PostgreSQL files
- Requirement: NOT APPLICABLE — Application does not manage database files or their permissions

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
- Static repository review completed on 2026-04-29.
- Control requires input validation in database code and application code, including use of prepared statements for user input to PostgreSQL.
- No SQL code or database triggers/functions present in provided files
- Application code (e.g., lib/diviner.py, core/facet.py) does not interact with a database or accept direct user input for SQL queries
- No evidence of prepared statement usage or input validation for database operations (no database operations present)
- Requirement: PARTIALLY SATISFIED — No evidence of noncompliance, but also no evidence of input validation or prepared statement usage for database input. Full compliance cannot be confirmed from static artifacts alone.

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
- Static repository review completed on 2026-04-29.
- Control requires that dynamic code execution is only used when necessary and user input is handled via prepared statements.
- No evidence of dynamic code execution (e.g., eval, exec, dynamic SQL) in provided files
- No evidence of user input being executed as code
- No evidence of prepared statement usage (no database operations present)
- Requirement: PARTIALLY SATISFIED — No evidence of dynamic code execution or noncompliance, but also no evidence of explicit restriction or justification for dynamic execution. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so.

---

### 51. CD16-00-005900 | SV-261907r1000726

- Rule ID: SV-261907r1000726
- Severity: medium
- Rule Title: PostgreSQL and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.

Status: Open

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires that if dynamic code execution is used, input is scanned for invalid values to prevent code injection.
- No evidence of dynamic code execution (e.g., eval, exec, dynamic SQL) in provided files
- No evidence of input scanning or sanitization for code injection
- Requirement: PARTIALLY SATISFIED — No evidence of dynamic code execution or code injection risk, but also no evidence of input scanning for code injection. Full compliance cannot be confirmed from static artifacts alone.

Remediation:
Where dynamic code execution is used, modify the code to implement protections against code injection (i.e., prepared statements).

---

### 52. CD16-00-006000 | SV-261908r1000729

- Rule ID: SV-261908r1000729
- Severity: medium
- Rule Title: PostgreSQL must provide nonprivileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not expose PostgreSQL error messages or configure client_min_messages.
- No postgresql.conf, pg_hba.conf, or code for setting client_min_messages
- Requirement: NOT APPLICABLE — Application does not expose PostgreSQL error messages

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not expose PostgreSQL error messages or manage PostgreSQL log files.
- No postgresql.conf, pg_hba.conf, or code for setting client_min_messages or log_file_mode
- No PostgreSQL log files present
- Requirement: NOT APPLICABLE — Application does not expose PostgreSQL error messages or manage log file permissions

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not manage PostgreSQL user sessions or implement session termination logic.
- No code for ALTER ROLE ... NOLOGIN, pg_terminate_backend, or session management
- Requirement: NOT APPLICABLE — Application does not manage PostgreSQL user sessions

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not implement security labeling or row-level security (RLS) on database tables.
- No SQL code for RLS policies, no table definitions, no security labeling logic
- Requirement: NOT APPLICABLE — Application does not implement or require database security labeling

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not implement security labeling or row-level security (RLS) on information in process.
- No SQL code for RLS policies, no table definitions, no security labeling logic
- Requirement: NOT APPLICABLE — Application does not implement or require database security labeling

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not implement security labeling or row-level security (RLS) on information in transmission.
- No SQL code for RLS policies, no table definitions, no security labeling logic
- Requirement: NOT APPLICABLE — Application does not implement or require database security labeling

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not define or manage database objects, schemas, or discretionary access controls (DAC).
- No SQL code for GRANT/REVOKE, no schema or table definitions, no object ownership logic
- Requirement: NOT APPLICABLE — Application does not implement or manage PostgreSQL DAC policies

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not define or manage privileged functions, procedural languages, or database extensions (e.g., pl/Python, pl/R).
- No SQL code for CREATE FUNCTION ... SECURITY DEFINER, no extension management
- Requirement: NOT APPLICABLE — Application does not implement or manage PostgreSQL privileged functions or procedural language extensions

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database and does not define or manage SECURITY DEFINER functions or privilege elevation logic.
- No SQL code for CREATE FUNCTION ... SECURITY DEFINER, no privilege elevation logic
- Requirement: NOT APPLICABLE — Application does not implement or manage PostgreSQL privilege elevation

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL deployment and does not include any PostgreSQL server configuration or management code.
- No postgresql.conf, SQL, or database management artifacts are present in the repository.
- The application is a Python-based MCP tool server (see README.md and pyproject.toml) and does not manage or configure PostgreSQL logging or audit settings.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS, not for this application type.

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
- Static repository review completed on 2026-04-29.
- This application does not manage PostgreSQL audit log storage or database storage capacity.
- No evidence of PostgreSQL database management, storage allocation, or log file monitoring in any configuration or code files.
- The application is a Python MCP tool server, not a database server or log manager.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS storage, not for this application type.

Remediation:
Allocate sufficient audit file/table space to support peak demand.

---

### 63. CD16-00-007300 | SV-261919r1000762

- Rule ID: SV-261919r1000762
- Severity: medium
- Rule Title: PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- No scripts, tools, or configuration in the repository monitor PostgreSQL log directories or notify support staff about audit log storage utilization.
- No evidence of disk monitoring scripts, cron jobs, or alerting mechanisms for PostgreSQL log partitions.
- The application is not responsible for PostgreSQL log storage or alerting.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS log monitoring, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No configuration or code in the repository provides real-time alerting for PostgreSQL audit log failures.
- No log monitoring, alerting, or integration with PostgreSQL audit mechanisms is present.
- The application is not a database server and does not manage or monitor PostgreSQL audit logs.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS audit log alerting, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL cluster initialization, log_timezone configuration, or database log management is present in the repository.
- No postgresql.conf or SQL configuration for log_timezone found.
- The application is not a database server and does not generate or manage PostgreSQL audit records.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS log time zone configuration, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No evidence of PostgreSQL log_line_prefix configuration or audit log timestamp management in the repository.
- No postgresql.conf, SQL, or log configuration for timestamp granularity found.
- The application is not a database server and does not manage PostgreSQL audit logs.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS log timestamp configuration, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL user, role, or privilege management is present in the repository.
- No SQL, database schema, or access control logic for stored procedures, functions, triggers, or views.
- The application is not a database server and does not manage database logic modules or user privileges.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS privilege enforcement, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL role, database, or schema privilege management is present in the repository.
- No SQL, database configuration, or access control logic for SUPERUSER or CREATE/UPDATE privileges.
- The application is not a database server and does not manage database configuration access restrictions.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS access restriction enforcement, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL audit logging, configuration file ownership, or permission management is present in the repository.
- No postgresql.conf, SQL, or file permission logic for database configuration files.
- The application is not a database server and does not manage or audit database configuration changes.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS audit logging, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL port, protocol, or network service configuration is present in the repository.
- No postgresql.conf, SQL, or network configuration for database ports or services.
- The application is not a database server and does not manage database network functions.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS network configuration, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL session management, reauthentication logic, or backend termination SQL is present in the repository.
- No code or configuration for terminating database sessions or forcing user reauthentication.
- The application is not a database server and does not manage database user sessions.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS session reauthentication, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL SSL/TLS configuration, cryptography settings, or certificate management is present in the repository.
- No postgresql.conf, SQL, or cryptographic enforcement for database connections.
- The application is not a database server and does not manage database cryptography for classified information.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS cryptographic enforcement, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL SSL certificate configuration, CA management, or certificate validation logic is present in the repository.
- No postgresql.conf, SQL, or certificate authority enforcement for database connections.
- The application is not a database server and does not manage database certificate trust.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS certificate authority enforcement, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL data-at-rest encryption, pgcrypto extension usage, or disk encryption configuration is present in the repository.
- No SQL, database extension management, or cryptographic storage logic for database data.
- The application is not a database server and does not manage database data-at-rest encryption.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS data-at-rest cryptography, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL pgcrypto extension usage, data-at-rest encryption, or disk encryption configuration is present in the repository.
- No SQL, database extension management, or cryptographic storage logic for database data.
- The application is not a database server and does not manage database data-at-rest encryption.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS data-at-rest cryptography, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL SSL/TLS configuration, cryptographic transmission settings, or network encryption logic is present in the repository.
- No postgresql.conf, SQL, or cryptographic enforcement for data transmission.
- The application is not a database server and does not manage database data-in-transit confidentiality or integrity.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS data-in-transit cryptography, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL SSL/TLS configuration, cryptographic reception settings, or network encryption logic is present in the repository.
- No postgresql.conf, SQL, or cryptographic enforcement for data reception.
- The application is not a database server and does not manage database data-in-transit confidentiality or integrity.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS data-in-transit cryptography, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL input validation, error handling, or audit logging for invalid SQL inputs is present in the repository.
- No postgresql.conf, SQL, or error logging configuration for database input errors.
- The application is not a database server and does not manage database input validation or error logging.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS input validation and error logging, not for this application type.

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
- Static repository review completed on 2026-04-29.
- No PostgreSQL package management, version checking, or software update logic is present in the repository.
- No RPM, APT, or database version management code or scripts.
- The application is not a database server and does not manage PostgreSQL software installation or removal.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS software update management, not for this application type.

Remediation:
Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.

---

### 80. CD16-00-009200 | SV-261936r1137667

- Rule ID: SV-261936r1137667
- Severity: medium
- Rule Title: Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- No PostgreSQL version checking, package management, or security update logic is present in the repository.
- No code or scripts for checking or applying PostgreSQL security updates.
- The application is not a database server and does not manage PostgreSQL software updates.
- Requirement: NOT APPLICABLE — control is for PostgreSQL DBMS security update management, not for this application type.

Remediation:
Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.

---

### 81. CD16-00-009400 | SV-261938r1000819

- Rule ID: SV-261938r1000819
- Severity: medium
- Rule Title: PostgreSQL must be able to generate audit records when security objects are accessed.

Status: Not Applicable

Evidence:
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records for security object access.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is an AI code analysis/orchestration platform, not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful attempts to access security objects (via pgaudit and logging).
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when categories of information are accessed.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records for unsuccessful attempts to access categories of information.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when privileges/permissions are added.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful attempts to add privileges/permissions.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when privileges/permissions are modified.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful attempts to modify privileges/permissions.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when security objects are modified, including catalog access.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful attempts to modify security objects.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when categories of information are modified.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records for unsuccessful attempts to modify categories of information.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when privileges/permissions are deleted.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful attempts to delete privileges/permissions.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when security objects are deleted.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records for unsuccessful attempts to delete security objects.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records when categories of information are deleted.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL pgaudit configuration to generate audit records for unsuccessful attempts to delete categories of information.
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for successful logons or connections (log_connections = on).
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- Control requires PostgreSQL to generate audit records for unsuccessful logons or connection attempts (log_connections = on).
- Searched all provided files for any PostgreSQL configuration, pgaudit settings, or database integration.
- No evidence of any PostgreSQL configuration, pgaudit settings, or database access in application source, configuration, or documentation.
- Application is not a database or database-backed application.
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application; control is for database servers only.

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
- Static repository review completed on 2026-04-29.
- This application is not a PostgreSQL database server and does not include any embedded or managed PostgreSQL instance. No postgresql.conf, pgaudit configuration, or SQL DDL is present in the repository. The application is a Python-based MCP tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or pgaudit configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, pgaudit, or SQL DDL is present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or pgaudit configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, log_connections, or log_disconnections settings are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or log_connections/disconnections configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, log_connections, log_disconnections, or log_line_prefix settings are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or log_connections/disconnections/log_line_prefix configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, pgaudit, or log_connections settings are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or pgaudit configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, pgaudit, or SQL DDL is present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or pgaudit configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or configure PostgreSQL audit records. No postgresql.conf, pgaudit, log_connections, or log_disconnections settings are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or pgaudit configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not use or configure OpenSSL or FIPS cryptographic modules for PostgreSQL. The application does not run or manage a PostgreSQL database and does not perform cryptographic operations requiring FIPS validation at the database layer. The only cryptographic operations present are for JWT validation (PyJWT/cryptography) and are not subject to FIPS 140-2/3 requirements for database modules.
- File: pyproject.toml — cryptography>=46.0.7 (for JWT validation), not for database encryption
- File: etc/atlas/config.yaml — No reference to OpenSSL, FIPS, or PostgreSQL cryptographic modules
- Requirement: NOT APPLICABLE — No PostgreSQL database or FIPS cryptographic module configuration is present

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
- Static repository review completed on 2026-04-29.
- This application does not use or configure OpenSSL or FIPS cryptographic modules for PostgreSQL. The application does not run or manage a PostgreSQL database and does not perform cryptographic operations requiring FIPS validation at the database layer. The only cryptographic operations present are for JWT validation (PyJWT/cryptography) and are not subject to FIPS 140-2/3 requirements for database modules.
- File: pyproject.toml — cryptography>=46.0.7 (for JWT validation), not for database encryption
- File: etc/atlas/config.yaml — No reference to OpenSSL, FIPS, or PostgreSQL cryptographic modules
- Requirement: NOT APPLICABLE — No PostgreSQL database or FIPS cryptographic module configuration is present

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
- Static repository review completed on 2026-04-29.
- This application does not run or manage a PostgreSQL database and does not generate or offload PostgreSQL audit logs. No postgresql.conf, log_destination, or syslog_facility settings are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: etc/atlas/config.yaml — No PostgreSQL or syslog configuration present
- File: README.md — No mention of embedded or managed PostgreSQL; only references to SQLite and vectorstore for internal storage
- Requirement: NOT APPLICABLE — No PostgreSQL database is present or managed by this application

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
- Static repository review completed on 2026-04-29.
- This application does not include, install, or manage a PostgreSQL server or client package. No PostgreSQL binaries, version checks, or package management commands are present. The application is a Python-based tool server and code analysis platform, not a database system.
- File: pyproject.toml — No dependency on PostgreSQL or psycopg2
- File: etc/atlas/config.yaml — No reference to PostgreSQL version or package management
- File: README.md — No mention of PostgreSQL installation or versioning
- Requirement: NOT APPLICABLE — No PostgreSQL product is present or managed by this application

Remediation:
Upgrade or install a version of the product supported by the vendor.

---
