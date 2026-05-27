# iris STIG Findings Assessment

Total STIGs Assessed: 111

| Status | Count |
|---|---|
| Open | 109 |
| Not Reviewed | 2 |

### 1. CD16-00-000100 | SV-261857r1000976

- Rule ID: SV-261857r1000976
- Severity: medium
- Rule Title: PostgreSQL must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to limit concurrent sessions per user and globally (max_connections, rolconnlimit).
- No static artifact in provided files sets 'max_connections' or per-role 'rolconnlimit'.
- File: pointcloud-project/colmap_ingest.py — DatabaseConfig class and connection string, but no session or connection limit logic:
- 'host=localhost port=5432 dbname=pointcloud_db user=pcuser password=secure_password_here'
- File: deploy/aws/iris-stack.yaml — RDS instance is provisioned, but no parameter group or explicit max_connections/rolconnlimit settings are present in the CloudFormation template.
- No postgresql.conf or pg_hba.conf present in any provided file.
- Requirement: PARTIALLY SATISFIED — Database is provisioned, but no evidence of session limits in code or infrastructure-as-code. Manual review of RDS parameter group and/or postgresql.conf required.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to use organization-level authentication (e.g., LDAP, Kerberos, cert, gss, sspi) in pg_hba.conf.
- No pg_hba.conf or equivalent static artifact present in any provided file.
- File: deploy/aws/iris-stack.yaml — RDS instance is provisioned, but authentication method is not specified; no evidence of LDAP/Kerberos/cert integration.
- File: pointcloud-project/colmap_ingest.py — DatabaseConfig uses username/password authentication in connection string, no external auth integration.
- Requirement: NOT SATISFIED — No evidence of organization-level authentication configuration or pg_hba.conf with required auth-methods.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of approved authorizations for logical access (roles, privileges, pg_hba.conf).
- File: pointcloud-project/colmap_ingest.py — DatabaseConfig and PointCloudDatabase classes use hardcoded credentials and standard SQL connections, but no role/privilege management or enforcement logic is present.
- No static artifact for roles, grants, or revokes in any provided file.
- No pg_hba.conf or documentation of access control policies found.
- Requirement: NOT SATISFIED — No evidence of role-based access control or privilege enforcement in static code or configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix to contain at least '< %m %a %u %d %r %p >' and pgaudit enabled in shared_preload_libraries.
- No postgresql.conf or equivalent configuration present in any provided file.
- No evidence of log_line_prefix or shared_preload_libraries settings in infrastructure-as-code (deploy/aws/iris-stack.yaml) or application code.
- Requirement: NOT SATISFIED — No evidence of required logging/auditing configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit record generation for DOD-defined events (e.g., CREATE TABLE) via pgaudit.
- No evidence of pgaudit installation or configuration in any provided file.
- No postgresql.conf or audit log configuration present.
- Requirement: NOT SATISFIED — No evidence of audit record generation capability for DOD-defined events.

Remediation:
Configure PostgreSQL to generate audit records for at least the DOD minimum set of events.

Using "pgaudit", PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 6. CD16-00-000600 | SV-261862r1000591

- Rule ID: SV-261862r1000591
- Severity: medium
- Rule Title: PostgreSQL must allow only the information system security manager (ISSM), or individuals or roles appointed by the ISSM, to select which events are to be audited.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires only ISSM or appointed roles to select audit events (ownership/permissions on PGDATA, superuser roles).
- No evidence of file/directory permissions or role assignments in static artifacts.
- No postgresql.conf or OS-level permissions shown.
- File: deploy/aws/iris-stack.yaml — EC2 and RDS roles are defined, but no mapping to PostgreSQL superuser or audit configuration.
- Requirement: NOT SATISFIED — No evidence of restricted audit configuration permissions.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and configured to log privilege/permission retrieval (pgaudit.log_catalog, pgaudit.log='read').
- No postgresql.conf or pgaudit configuration present in any provided file.
- No evidence of pgaudit in shared_preload_libraries or log settings.
- Requirement: NOT SATISFIED — No evidence of audit logging for privilege/permission retrieval.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for unsuccessful attempts to retrieve privileges/permissions (denials logged).
- No postgresql.conf or logging configuration present in any provided file.
- No evidence of error/denial logging configuration.
- Requirement: NOT SATISFIED — No evidence of audit logging for unsuccessful privilege/permission retrieval.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access privileges occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 9. CD16-00-000900 | SV-261865r1000600

- Rule ID: SV-261865r1000600
- Severity: medium
- Rule Title: PostgreSQL must initiate session auditing upon startup.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled in shared_preload_libraries and log_destination set to stderr or syslog.
- No postgresql.conf or equivalent configuration present in any provided file.
- No evidence of pgaudit or log_destination settings.
- Requirement: NOT SATISFIED — No evidence of session auditing on startup.

Remediation:
Configure PostgreSQL to enable auditing.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

For session logging, using pgaudit is recommended. For instructions on how to setup pgaudit, refer to supplementary content APPENDIX-B.

---

### 10. CD16-00-001000 | SV-261866r1000603

- Rule ID: SV-261866r1000603
- Severity: medium
- Rule Title: PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix to include event type, and log_connections/log_disconnections to be on.
- No postgresql.conf or log_line_prefix/log_connections/log_disconnections settings present in any provided file.
- Requirement: NOT SATISFIED — No evidence of required audit record content configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix to contain '%m' (timestamp with milliseconds).
- No postgresql.conf or log_line_prefix setting present in any provided file.
- Requirement: NOT SATISFIED — No evidence of timestamp logging configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix to contain '%m %u %d %s' (timestamp, user, database, session start).
- No postgresql.conf or log_line_prefix setting present in any provided file.
- Requirement: NOT SATISFIED — No evidence of location information in audit records.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix and log_hostname to provide event source/origin information.
- No postgresql.conf or log_line_prefix/log_hostname setting present in any provided file.
- Requirement: NOT SATISFIED — No evidence of source/origin information in audit records.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records to show event outcome (success/failure), including errors and denials.
- No postgresql.conf or pgaudit configuration present in any provided file.
- No evidence of log_error_verbosity or pgaudit.log settings.
- Requirement: NOT SATISFIED — No evidence of outcome logging in audit records.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records to include user/process identity (%m, %u, %d, %p, %r, %a in log_line_prefix).
- No postgresql.conf or log_line_prefix setting present in any provided file.
- Requirement: NOT SATISFIED — No evidence of user/process identity in audit records.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records to include organization-defined additional information (as configured in postgresql.conf and audit logs).
- No postgresql.conf or organization-defined audit configuration present in any provided file.
- Requirement: NOT SATISFIED — No evidence of additional audit information configuration.

Remediation:
Configure PostgreSQL audit settings to include all organization-defined detailed information in the audit records for audit events identified by type, location, or subject.

Using pgaudit, PostgreSQL can be configured to audit these requests. Refer to supplementary content APPENDIX-B for documentation on installing pgaudit.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 17. CD16-00-001700 | SV-261873r1043188

- Rule ID: SV-261873r1043188
- Severity: medium
- Rule Title: PostgreSQL must, by default, shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires procedures or configuration to shut down or alert on audit failure (e.g., log disk full).
- No evidence of log monitoring, alerting, or shutdown procedures in any provided file.
- No postgresql.conf or OS-level log management configuration present.
- Requirement: NOT SATISFIED — No evidence of audit failure handling procedures.

Remediation:
Modify PostgreSQL, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.

---

### 18. CD16-00-001800 | SV-261874r1043188

- Rule ID: SV-261874r1043188
- Severity: medium
- Rule Title: PostgreSQL must be configurable to overwrite audit log records, oldest first (first-in-first-out [FIFO]), in the event of unavailability of space for more audit log records.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log rotation or FIFO overwrite for audit logs when space is low.
- No evidence of log rotation scripts, logrotate configuration, or PostgreSQL log management in any provided file.
- Requirement: NOT SATISFIED — No evidence of log rotation or FIFO overwrite configuration.

Remediation:
Establish a process with accompanying tools for monitoring available disk space and ensuring that sufficient disk space is maintained to continue generating audit logs, overwriting the oldest existing records if necessary.

---

### 19. CD16-00-002000 | SV-261875r1000630

- Rule ID: SV-261875r1000630
- Severity: medium
- Rule Title: The audit information produced by PostgreSQL must be protected from unauthorized read access.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs to be protected from unauthorized read access (log_file_mode=0600).
- No postgresql.conf or log_file_mode setting present in any provided file.
- No evidence of log file permissions or OS-level controls.
- Requirement: NOT SATISFIED — No evidence of audit log read protection.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs to be protected from unauthorized modification (log_file_mode=0600, ownership by postgres/root).
- No postgresql.conf or log_file_mode setting present in any provided file.
- No evidence of log file ownership or permissions.
- Requirement: NOT SATISFIED — No evidence of audit log modification protection.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL audit logs to be protected from unauthorized deletion, with log_file_mode=0600 and correct ownership.
- No postgresql.conf or explicit log_file_mode setting found in any provided file.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no evidence of log_file_mode or log directory permissions is present in the CloudFormation template.
- No Dockerfile or script configures PostgreSQL logging permissions or file modes.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of log file permissions/ownership is missing. Cannot confirm log_file_mode=0600 or log directory ownership from static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PGLOG and PGDATA to be owned by postgres, and pgaudit extension to be owned by root.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is created, but no static evidence of file/directory ownership for PGDATA or PGLOG is present.
- No evidence of pgaudit extension installation or its ownership in any provided file.
- No Dockerfile or script configures file/directory ownership for PostgreSQL data or log directories.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of directory/file ownership and pgaudit ownership is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires postgresql.conf to be owned by postgres with 0600 permissions, and log_file_mode=0600.
- No postgresql.conf or explicit log_file_mode setting found in any provided file.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no evidence of postgresql.conf permissions or ownership is present in the CloudFormation template.
- No Dockerfile or script configures postgresql.conf permissions.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of postgresql.conf permissions/ownership and log_file_mode is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PGDATA to be owned by postgres:postgres and system binaries to be owned by root:root.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no static evidence of PGDATA directory or system binary ownership is present.
- No Dockerfile or script configures file/directory ownership for PostgreSQL data or binaries.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of directory/file ownership is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires configuration files in PGDATA to be owned by postgres and shared libraries/executables to be owned by root.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no static evidence of configuration file or shared library ownership is present.
- No Dockerfile or script configures file/directory ownership for PostgreSQL configuration or binaries.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of configuration/shared object ownership is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires procedures to restrict and track use of the PostgreSQL software installation account(s).
- No documentation or code describing procedures for restricting or tracking use of the PostgreSQL installation account is present in any provided file.
- No evidence of such procedures in deploy/aws/iris-stack.yaml or any script.
- Requirement: NOT SATISFIED — No static evidence of procedures for restricting/tracking installation account use.

Remediation:
Develop, document, and implement procedures to restrict and track use of the PostgreSQL software installation account(s).

---

### 27. CD16-00-002800 | SV-261883r1000654

- Rule ID: SV-261883r1000654
- Severity: medium
- Rule Title: Database software, including PostgreSQL configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL software/configuration files to be stored in dedicated directories, separate from the host OS and other applications.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no static evidence of directory layout or separation from other applications is present.
- No Dockerfile or script configures PostgreSQL installation directories.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of directory separation is missing.

Remediation:
Install all applications on directories separate from the PostgreSQL software library directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL software library directory.

---

### 28. CD16-00-002900 | SV-261884r1000657

- Rule ID: SV-261884r1000657
- Severity: medium
- Rule Title: Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be owned by database/PostgreSQL principals authorized for ownership.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires database objects to be owned by authorized principals.
- No SQL, schema, or migration files are present in the provided context to show object ownership.
- No documentation or code lists authorized object owners.
- Requirement: NOT SATISFIED — No static evidence of database object ownership or authorized owner list.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires roles/groups with privileges to modify database structure/logic to be restricted to authorized users.
- No SQL, schema, or migration files are present in the provided context to show role/privilege assignments.
- No documentation or code lists authorized roles/groups.
- Requirement: NOT SATISFIED — No static evidence of role/group privilege assignments or restrictions.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires unused database components, extensions, and objects to be removed.
- No SQL, schema, or migration files are present in the provided context to show installed extensions or components.
- No documentation or code lists installed extensions.
- Requirement: NOT SATISFIED — No static evidence of installed or removed extensions/components.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires unused integrated database components/packages to be disabled or removed.
- No package list, Dockerfile, or OS-level configuration is present in the provided context to show installed PostgreSQL packages.
- No documentation or code lists installed packages.
- Requirement: NOT SATISFIED — No static evidence of installed or removed packages.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires access to external executables (e.g., via COPY command or extensions) to be restricted to superusers and only approved extensions installed.
- No SQL, schema, or migration files are present in the provided context to show role privileges or installed extensions.
- No documentation or code lists superuser roles or installed extensions.
- Requirement: NOT SATISFIED — No static evidence of superuser privilege assignments or extension restrictions.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to prohibit or restrict use of organization-defined functions, ports, protocols, and/or services.
- No postgresql.conf or explicit port/listen_addresses setting found in any provided file.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but no evidence of port or listen_addresses configuration is present.
- Requirement: PARTIALLY SATISFIED — RDS instance is provisioned, but static evidence of port/address restrictions is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires unique identification and authentication of organizational users, and unique authentication requirements in pg_hba.conf.
- No pg_hba.conf or user/role configuration is present in any provided file.
- No documentation or code lists user authentication settings.
- Requirement: NOT SATISFIED — No static evidence of unique user authentication or pg_hba.conf configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to store only hashed, salted representations of passwords (password_encryption = 'scram-sha-256').
- No postgresql.conf or explicit password_encryption setting found in any provided file.
- No SQL, schema, or migration files are present to show password storage format.
- Requirement: NOT SATISFIED — No static evidence of password_encryption setting or password storage format.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to transmit only encrypted representations of passwords (no 'password' or 'md5' in pg_hba.conf).
- No pg_hba.conf or authentication configuration is present in any provided file.
- Requirement: NOT SATISFIED — No static evidence of authentication method configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PKI-based authentication to validate certificates via RFC 5280-compliant path validation (ssl_crl_file set, hostssl/cert/clientcert=verify-ca in pg_hba.conf).
- No postgresql.conf or pg_hba.conf is present in any provided file.
- No documentation or code configures ssl_crl_file or client certificate validation.
- Requirement: NOT SATISFIED — No static evidence of PKI certificate validation configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL PKI private keys to be protected (ssl_key_file location and directory permissions).
- No postgresql.conf or evidence of ssl_key_file location or directory permissions is present in any provided file.
- Requirement: NOT SATISFIED — No static evidence of PKI private key storage or access controls.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires mapping PKI-authenticated identity (certificate CN) to a PostgreSQL user account (via direct match or pg_ident.conf mapping).
- No pg_hba.conf or pg_ident.conf is present in any provided file.
- No documentation or code configures user mapping for PKI authentication.
- Requirement: NOT SATISFIED — No static evidence of PKI user mapping configuration.

Remediation:
Configure PostgreSQL to map authenticated identities directly to PostgreSQL user accounts.

For information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 40. CD16-00-004400 | SV-261896r1193213

- Rule ID: SV-261896r1193213
- Severity: high
- Rule Title: PostgreSQL must use NIST FIPS 140-2/140-3 validated cryptographic modules for cryptographic operations.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires use of NIST FIPS 140-2/140-3 validated cryptographic modules (OS-level FIPS mode, FIPS OpenSSL provider).
- No OS configuration, Dockerfile, or script is present in any provided file to show FIPS mode enabled or FIPS OpenSSL provider in use.
- Requirement: NOT SATISFIED — No static evidence of FIPS mode or cryptographic module configuration.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).
- File: deploy/aws/create_databases.py — creates databases 'iris_data' and 'keycloak_data' but does not define or enumerate roles/users.
- File: pointcloud-project/colmap_ingest.py — defines a DatabaseConfig with user 'pcuser' and password 'secure_password_here', but does not enumerate all roles or show unique user assignment.
- No static artifact (SQL, config, or code) in provided files lists all PostgreSQL roles or demonstrates unique identification per user.
- Requirement: PARTIALLY SATISFIED — Application code uses named users for DB access, but there is no evidence of unique user identification for all users/roles in PostgreSQL. Full compliance requires review of actual database roles (\du) and organizational documentation.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must separate user functionality (including user interface services) from database management functionality.
- File: pointcloud-project/colmap_ingest.py — uses user 'pcuser' for point cloud ingestion, but does not show role attributes (e.g., SUPERUSER, CREATEDB, CREATEROLE, BYPASSRLS).
- File: deploy/aws/create_databases.py — connects as user 'iris' to create databases, but does not show role attributes or separation of admin/user roles.
- No static artifact (SQL, config, or code) in provided files lists all roles and their privileges or demonstrates separation of admin and user functionality.
- Requirement: PARTIALLY SATISFIED — Application code uses distinct users for different functions, but there is no evidence of role attribute assignments or enforcement of separation. Full compliance requires review of actual database roles and privileges.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must invalidate session identifiers upon user logout or other session termination, with tcp_keepalives_idle, tcp_keepalives_interval, tcp_keepalives_count, and statement_timeout set to non-zero values.
- No postgresql.conf or equivalent configuration file is present in the provided files.
- No code or script in the provided files sets or enforces these PostgreSQL parameters.
- Requirement: NOT SATISFIED — No evidence of session timeout or keepalive settings for PostgreSQL found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must have 'ssl = on' in postgresql.conf to guard against man-in-the-middle attacks.
- No postgresql.conf or equivalent configuration file is present in the provided files.
- No code or script in the provided files sets or enforces 'ssl = on' for PostgreSQL.
- Requirement: NOT SATISFIED — No evidence of SSL enforcement for PostgreSQL found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must protect the confidentiality and integrity of all information at rest, e.g., via pgcrypto or disk encryption.
- No evidence of pgcrypto extension installation or usage in provided files.
- No evidence of disk or filesystem encryption configuration in provided files.
- Requirement: NOT SATISFIED — No evidence of data-at-rest encryption controls for PostgreSQL found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Security functions must be isolated from nonsecurity functions, with access to pg_catalog and information_schema restricted to DBAs.
- No evidence in provided files of schema or object privilege assignments for pg_catalog or information_schema.
- No evidence of custom security-related objects or their isolation.
- Requirement: NOT SATISFIED — No evidence of isolation of security functions or privilege assignments found in static artifacts.

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
- Control requires: Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.
- File: pointcloud-project/colmap_ingest.py — provides ingestion and retrieval utilities for point cloud data, but does not reference or enforce any data transfer policy or removal of production data from unprotected locations.
- No scripts or code in provided files reference a data transfer policy or implement secure data movement procedures.
- Requirement: NOT SATISFIED — No evidence of enforcement of a data-transfer policy for database contents found in static artifacts.

Remediation:
Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.

---

### 48. CD16-00-005600 | SV-261904r1137658

- Rule ID: SV-261904r1137658
- Severity: medium
- Rule Title: Access to database files must be limited to relevant processes and to authorized, administrative users.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Access to database files must be limited to relevant processes and to authorized, administrative users.
- No file system permissions or ownership settings for PostgreSQL data files are present in the provided files.
- No code or script in provided files sets or checks file permissions for PostgreSQL data, log, or backup files.
- Requirement: NOT SATISFIED — No evidence of file system access controls for PostgreSQL data found in static artifacts.

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
- Control requires: PostgreSQL and application code must check the validity of all data inputs, use constraints, and use prepared statements for user input.
- File: pointcloud-project/colmap_ingest.py — uses psycopg2 and execute_batch for database inserts, but does not use parameterized/prepared statements for all queries (e.g., some queries use string interpolation).
- No evidence of input validation or constraints enforcement in the provided code for all database columns/fields.
- Requirement: PARTIALLY SATISFIED — Some use of parameterized queries via execute_batch, but not all queries are parameterized and no evidence of comprehensive input validation or constraints.

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
- Control requires: Dynamic code execution must be reserved for necessary cases only, and user input must be handled through prepared statements.
- File: pointcloud-project/colmap_ingest.py — does not use dynamic SQL execution (e.g., EXECUTE or string-based SQL from user input), but some queries use string interpolation for SQL statements (e.g., cur.execute(f"CREATE DATABASE {dbname}")).
- No evidence of dynamic code execution in stored procedures or triggers in provided files.
- Requirement: PARTIALLY SATISFIED — No unnecessary dynamic code execution found, but some queries use string interpolation which could be avoided.

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
- Control requires: If dynamic code execution is used, input data must be scanned for invalid values to prevent code injection.
- File: pointcloud-project/colmap_ingest.py — some queries use string interpolation (e.g., cur.execute(f"CREATE DATABASE {dbname}")), but dbname is controlled within the script and not directly from user input.
- No evidence of input sanitization for dynamically constructed SQL statements.
- Requirement: PARTIALLY SATISFIED — No direct evidence of code injection risk, but lack of input sanitization for interpolated SQL is a potential risk.

Remediation:
Where dynamic code execution is used, modify the code to implement protections against code injection (i.e., prepared statements).

---

### 52. CD16-00-006000 | SV-261908r1000729

- Rule ID: SV-261908r1000729
- Severity: medium
- Rule Title: PostgreSQL must provide nonprivileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must set client_min_messages = error to limit error detail to clients.
- No postgresql.conf or equivalent configuration file is present in the provided files.
- No code or script in provided files sets or enforces client_min_messages.
- Requirement: NOT SATISFIED — No evidence of client_min_messages setting found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must reveal detailed error messages only to authorized personnel, and log files must be owned by the DBA with 0600 permissions.
- No postgresql.conf or log file configuration is present in the provided files.
- No code or script in provided files sets or checks log_file_mode or log file permissions.
- Requirement: NOT SATISFIED — No evidence of error message restriction or log file permissions found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.
- No code, configuration, or documentation in provided files describes or implements automatic session termination for PostgreSQL.
- Requirement: NOT SATISFIED — No evidence of automatic session termination controls found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must associate organization-defined types of security labels with information in storage (e.g., via RLS policies).
- No evidence in provided files of row-level security (RLS) policies or security labeling implemented in PostgreSQL schemas or tables.
- Requirement: NOT SATISFIED — No evidence of security labeling for information in storage found in static artifacts.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 56. CD16-00-006500 | SV-261912r1138541

- Rule ID: SV-261912r1138541
- Severity: medium
- Rule Title: PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in process.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must associate organization-defined types of security labels with information in process (e.g., via RLS policies).
- No evidence in provided files of row-level security (RLS) policies or security labeling implemented in PostgreSQL schemas or tables.
- Requirement: NOT SATISFIED — No evidence of security labeling for information in process found in static artifacts.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 57. CD16-00-006600 | SV-261913r1138542

- Rule ID: SV-261913r1138542
- Severity: medium
- Rule Title: PostgreSQL must associate organization-defined types of security labels having organization-defined security label values with information in transmission.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must associate organization-defined types of security labels with information in transmission (e.g., via RLS policies).
- No evidence in provided files of row-level security (RLS) policies or security labeling implemented in PostgreSQL schemas or tables.
- Requirement: NOT SATISFIED — No evidence of security labeling for information in transmission found in static artifacts.

Remediation:
In addition to the SQL-standard privilege system available through GRANT, tables can have row security policies that restrict, on a per-user basis, which rows can be returned by normal queries or inserted, updated, or deleted by data modification commands. This feature is also known as Row-Level Security (RLS).

RLS policies can be very different depending on their use case. For one example of using RLS for Security Labels, refer to supplementary content APPENDIX-D.

---

### 58. CD16-00-006700 | SV-261914r1000747

- Rule ID: SV-261914r1000747
- Severity: medium
- Rule Title: PostgreSQL must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must enforce discretionary access control (DAC) policies as defined by the data owner.
- File: pointcloud-project/colmap_ingest.py — creates tables and inserts data, but does not show GRANT/REVOKE statements or evidence of DAC enforcement.
- No evidence in provided files of object ownership review or privilege assignments.
- Requirement: NOT SATISFIED — No evidence of discretionary access control enforcement found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must prevent nonprivileged users from executing privileged functions, and use of procedural languages (pl/Python, pl/R) must be AO-authorized.
- No evidence in provided files of privileged function definitions or procedural language usage.
- No evidence of privilege assignments or restrictions.
- Requirement: NOT SATISFIED — No evidence of privileged function restriction or procedural language authorization found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: Execution of software modules (stored procedures, functions, triggers) with elevated privileges must be restricted to necessary cases only.
- No evidence in provided files of SECURITY DEFINER functions or privilege elevation in PostgreSQL.
- Requirement: NOT SATISFIED — No evidence of privilege elevation or its restriction found in static artifacts.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL audit logs to be sent to a centralized log management system, typically via syslog (log_destination = 'syslog').
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL instance is provisioned, but there is no evidence of postgresql.conf settings for log_destination or syslog_facility.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- No evidence of syslog integration or centralized log forwarding for PostgreSQL audit logs.
- Requirement: NOT SATISFIED — No static evidence that PostgreSQL is configured to use syslog or any centralized audit log management.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires allocation of sufficient audit log storage for PostgreSQL.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL is provisioned with AllocatedStorage: 20 (GB), but this is for the entire DB, not specifically for audit logs.
- No evidence of log storage monitoring, log file retention policies, or dedicated audit log storage configuration.
- No scripts or settings for monitoring audit log space are present.
- Requirement: PARTIALLY SATISFIED — Database storage is allocated, but no evidence of audit log storage capacity planning or monitoring.

Remediation:
Allocate sufficient audit file/table space to support peak demand.

---

### 63. CD16-00-007300 | SV-261919r1000762

- Rule ID: SV-261919r1000762
- Severity: medium
- Rule Title: PostgreSQL must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires a script or tool to monitor PostgreSQL log directory storage and notify support staff at 75% utilization.
- No evidence of any monitoring script, cron job, or alerting mechanism for audit log storage in any provided file.
- File: deploy/aws/iris-stack.yaml — No user-data or EC2 bootstrap script includes log monitoring for PostgreSQL audit logs.
- Requirement: NOT SATISFIED — No static evidence of audit log storage monitoring or alerting at 75% threshold.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires real-time alerting to support staff on audit log failures.
- No evidence of any configuration, script, or third-party tool for real-time alerting on PostgreSQL audit log failures in any provided file.
- File: deploy/aws/iris-stack.yaml — No mention of audit log failure detection or alerting in EC2 user-data or RDS configuration.
- Requirement: NOT SATISFIED — No static evidence of real-time alerting for audit log failures.

Remediation:
Configure the system to provide an immediate real-time alert to appropriate support staff when an audit log failure occurs.

It is possible to create scripts or implement third-party tools to enable real-time alerting for audit failures in PostgreSQL.

---

### 65. CD16-00-007500 | SV-261921r1000994

- Rule ID: SV-261921r1000994
- Severity: medium
- Rule Title: PostgreSQL must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC), formerly Greenwich Mean Time (GMT).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL log_timezone to be set to UTC.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of log_timezone setting for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence that log_timezone is set to UTC.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_line_prefix to include %m for timestamp granularity of at least one second.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of log_line_prefix setting for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence that log_line_prefix includes %m.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires that only privileged users can create/alter logic modules (functions, triggers, etc.).
- No evidence of PostgreSQL GRANT/REVOKE statements, role definitions, or privilege management in any provided file.
- File: pointcloud-project/colmap_ingest.py — Uses psycopg2 to connect to PostgreSQL, but does not manage or restrict user privileges for logic modules.
- Requirement: NOT SATISFIED — No static evidence of privilege enforcement for logic module creation.

Remediation:
Document and obtain approval for any nonadministrative users who require the ability to create, alter, or replace logic modules.

Implement the approved permissions. Revoke any unapproved permissions.

---

### 68. CD16-00-007800 | SV-261924r1000777

- Rule ID: SV-261924r1000777
- Severity: medium
- Rule Title: PostgreSQL must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires enforcement of access restrictions for DBMS configuration changes (e.g., SUPERUSER, CREATE, UPDATE privileges).
- No evidence of ALTER ROLE, REVOKE, or explicit privilege management in any provided file.
- File: pointcloud-project/colmap_ingest.py — Connects as user 'pcuser', but does not manage or restrict configuration privileges.
- Requirement: NOT SATISFIED — No static evidence of access restriction enforcement for configuration changes.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit records for enforcement of access restrictions (e.g., logging denied configuration changes) and proper file permissions on postgresql.conf.
- No evidence of logging configuration or file permission management for postgresql.conf in any provided file.
- File: deploy/aws/iris-stack.yaml — No mention of postgresql.conf ownership or permissions.
- Requirement: NOT SATISFIED — No static evidence of audit logging for denied configuration changes or file permission enforcement.

Remediation:
Enable logging.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 70. CD16-00-008000 | SV-261926r1000783

- Rule ID: SV-261926r1000783
- Severity: medium
- Rule Title: PostgreSQL must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires disabling nonsecure network functions, ports, and protocols for PostgreSQL.
- File: deploy/aws/iris-stack.yaml — RDS PostgreSQL is provisioned with port 5432 open only to EC2 security group (RdsSecurityGroup), which is a secure default, but no evidence of disabling other ports or protocols.
- No evidence of postgresql.conf 'port' setting or explicit disabling of nonsecure protocols.
- Requirement: PARTIALLY SATISFIED — RDS security group restricts access, but no static evidence of protocol restrictions or port configuration in PostgreSQL.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires ability to force user reauthentication (e.g., via SELECT pg_terminate_backend(pid)).
- No evidence of any code, script, or documentation implementing or invoking pg_terminate_backend for reauthentication in any provided file.
- Requirement: NOT SATISFIED — No static evidence of reauthentication enforcement or mechanism.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to use NSA-approved cryptography (SSL) for classified information.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of 'ssl = on' or SSL enforcement for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence that SSL is enabled for PostgreSQL.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to accept only DOD PKI or DOD-approved CA certificates for SSL.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of 'ssl_ca_file' or 'ssl_cert_file' settings for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence of DOD PKI CA enforcement for PostgreSQL SSL.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires cryptographic mechanisms to prevent unauthorized modification of information at rest (e.g., pgcrypto, disk encryption).
- No evidence of pgcrypto extension installation or usage in any provided file.
- No evidence of disk or filesystem encryption for PostgreSQL data directory.
- File: pointcloud-project/colmap_ingest.py — Uses PostgreSQL for point cloud data, but no cryptographic protection is implemented or referenced.
- Requirement: NOT SATISFIED — No static evidence of cryptographic protection for data at rest.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires cryptographic mechanisms to prevent unauthorized disclosure of information at rest (e.g., pgcrypto, disk encryption).
- No evidence of pgcrypto extension installation or usage in any provided file.
- No evidence of disk or filesystem encryption for PostgreSQL data directory.
- Requirement: NOT SATISFIED — No static evidence of cryptographic protection for data at rest.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires confidentiality and integrity of information during preparation for transmission (e.g., SSL enabled for PostgreSQL).
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of 'ssl = on' or SSL enforcement for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence that SSL is enabled for PostgreSQL.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires confidentiality and integrity of information during reception (e.g., SSL enabled for PostgreSQL).
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- File: deploy/aws/iris-stack.yaml — No evidence of 'ssl = on' or SSL enforcement for PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence that SSL is enabled for PostgreSQL.

Remediation:
Implement protective measures against unauthorized disclosure and modification during reception.

To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G for instructions on enabling SSL.

---

### 78. CD16-00-009000 | SV-261934r1000807

- Rule ID: SV-261934r1000807
- Severity: medium
- Rule Title: When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires predictable and documented error handling for invalid inputs, with errors logged by PostgreSQL.
- No evidence of logging configuration for PostgreSQL errors (e.g., log_statement, log_min_error_statement) in any provided file.
- No postgresql.conf or RDS parameter group configuration is present.
- Requirement: NOT SATISFIED — No static evidence of error logging configuration for invalid SQL inputs.

Remediation:
Enable logging.

To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

All errors and denials are logged if logging is enabled.

---

### 79. CD16-00-009100 | SV-261935r1000810

- Rule ID: SV-261935r1000810
- Severity: medium
- Rule Title: When updates are applied to the PostgreSQL software, any software components that have been replaced or made unnecessary must be removed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires removal of unused or replaced PostgreSQL software components after updates.
- No evidence of package management scripts, uninstall procedures, or documentation for removing old PostgreSQL versions in any provided file.
- Requirement: NOT SATISFIED — No static evidence of unused software removal after updates.

Remediation:
Use package managers (RPM or apt-get) for installing PostgreSQL. Unused software is removed when updated.

---

### 80. CD16-00-009200 | SV-261936r1137667

- Rule ID: SV-261936r1137667
- Severity: medium
- Rule Title: Security-relevant software updates to PostgreSQL must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires timely installation of security-relevant PostgreSQL updates.
- No evidence of update policies, automation, or version checks for PostgreSQL in any provided file.
- File: deploy/aws/iris-stack.yaml — Installs postgresql via dnf in EC2 user-data, but no evidence of update cadence or version enforcement for RDS PostgreSQL.
- Requirement: NOT SATISFIED — No static evidence of security update management for PostgreSQL.

Remediation:
Institute and adhere to policies and procedures to ensure that patches are consistently applied to PostgreSQL within the time allowed.

---

### 81. CD16-00-009400 | SV-261938r1000819

- Rule ID: SV-261938r1000819
- Severity: medium
- Rule Title: PostgreSQL must be able to generate audit records when security objects are accessed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to have pgaudit enabled and configured to log 'role, read, write, ddl'.
- File: pointcloud-project/docker-compose.yml — service 'postgres' is defined, but no evidence of pgaudit configuration or postgresql.conf settings for 'shared_preload_libraries' or 'pgaudit.log'.
- File: pointcloud-project/colmap_ingest.py — connects to PostgreSQL but does not configure or check audit settings.
- File: deploy/aws/iris-stack.yaml — RDS instance 'PostgresDB' is created, but no UserData or configuration for pgaudit or audit logging is present.
- No postgresql.conf or pgaudit configuration found in any provided file.
- Requirement: PARTIALLY SATISFIED — PostgreSQL is present, but static evidence of pgaudit enablement and required audit settings is missing.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires PostgreSQL to log unsuccessful attempts to access security objects (denials/errors) via audit logs.
- File: pointcloud-project/docker-compose.yml — PostgreSQL service is present, but no log configuration or pgaudit settings are shown.
- File: deploy/aws/iris-stack.yaml — RDS instance is provisioned, but no evidence of log settings or pgaudit configuration.
- No postgresql.conf, pgaudit.log, or log_directory/logging configuration found in any static artifact.
- Requirement: PARTIALLY SATISFIED — PostgreSQL is deployed, but static evidence of audit logging for unsuccessful access attempts is missing.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access security objects occur.

All denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 83. CD16-00-009600 | SV-261940r1000825

- Rule ID: SV-261940r1000825
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are accessed.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit.log to include 'ddl, write, role'.
- File: pointcloud-project/docker-compose.yml — PostgreSQL service is present, but no pgaudit.log configuration is shown.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit.log configuration in RDS or EC2 bootstrap.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit.log including 'ddl, write, role'.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit.log to include 'ddl, write, role' for unsuccessful attempts to access categories of information.
- File: pointcloud-project/docker-compose.yml — No pgaudit.log configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit.log configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit.log including 'ddl, write, role'.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit.log to include 'role' for privilege/permission changes.
- File: pointcloud-project/docker-compose.yml — No pgaudit.log configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit.log configuration for 'role'.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit.log including 'role'.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs for unsuccessful attempts to add privileges/permissions.
- File: pointcloud-project/docker-compose.yml — No log or pgaudit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of audit log configuration for denials/errors.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of audit logging for unsuccessful privilege/permission additions.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to add privileges occur.

All denials are logged by default if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 87. CD16-00-010000 | SV-261944r1000837

- Rule ID: SV-261944r1000837
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when privileges/permissions are modified.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'role' for privilege/permission modifications.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including 'role'.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs for unsuccessful attempts to modify privileges/permissions.
- File: pointcloud-project/docker-compose.yml — No log or pgaudit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of audit log configuration for denials/errors.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of audit logging for unsuccessful privilege/permission modifications.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to modify privileges occur.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 89. CD16-00-010200 | SV-261946r1000843

- Rule ID: SV-261946r1000843
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when security objects are modified.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled, pgaudit.log including 'ddl, role, read, write', and pgaudit.log_catalog = 'on'.
- File: pointcloud-project/docker-compose.yml — No pgaudit or log_catalog configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or log_catalog configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled, pgaudit.log, or pgaudit.log_catalog.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs for unsuccessful attempts to modify security objects.
- File: pointcloud-project/docker-compose.yml — No log or pgaudit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of audit log configuration for denials/errors.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of audit logging for unsuccessful security object modifications.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to modify security objects occur.

Unsuccessful attempts to modify security objects can be logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 91. CD16-00-010400 | SV-261948r1000849

- Rule ID: SV-261948r1000849
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when categories of information (e.g., classification levels/security levels) are modified.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'ddl, role, read, write' for category modifications.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'ddl, role, read, write' for unsuccessful category modifications.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'role, read, write, ddl' for privilege/permission deletions.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs for unsuccessful attempts to delete privileges/permissions.
- File: pointcloud-project/docker-compose.yml — No log or pgaudit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of audit log configuration for denials/errors.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of audit logging for unsuccessful privilege/permission deletions.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to delete privileges occur.

All denials are logged if logging is enabled. To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

---

### 95. CD16-00-010800 | SV-261952r1000861

- Rule ID: SV-261952r1000861
- Severity: medium
- Rule Title: PostgreSQL must generate audit records when security objects are deleted.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires audit logs for security object deletions (e.g., DROP POLICY, ALTER TABLE DISABLE ROW LEVEL SECURITY).
- File: pointcloud-project/docker-compose.yml — No log or pgaudit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of audit log configuration for DDL events.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of audit logging for security object deletions.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'ddl, role, read, write' for unsuccessful security object deletions.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'ddl, role, read, write' for category deletions.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires pgaudit enabled and pgaudit.log including 'ddl, role, read, write' for unsuccessful category deletions.
- File: pointcloud-project/docker-compose.yml — No pgaudit or audit configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of pgaudit or audit configuration.
- No postgresql.conf or pgaudit settings found in any static file.
- Requirement: NOT SATISFIED — No static evidence of pgaudit enabled or pgaudit.log including required categories.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_connections = on and log_line_prefix including %m %u %d %c for successful logons/connections.
- File: pointcloud-project/docker-compose.yml — No log_connections or log_line_prefix configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of log_connections or log_line_prefix configuration in RDS or EC2 bootstrap.
- No postgresql.conf or logging configuration found in any static file.
- Requirement: NOT SATISFIED — No static evidence of log_connections or log_line_prefix settings.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires log_connections = on and log_line_prefix including %m %u %c for unsuccessful logons/connections.
- File: pointcloud-project/docker-compose.yml — No log_connections or log_line_prefix configuration present.
- File: deploy/aws/iris-stack.yaml — No evidence of log_connections or log_line_prefix configuration in RDS or EC2 bootstrap.
- No postgresql.conf or logging configuration found in any static file.
- Requirement: NOT SATISFIED — No static evidence of log_connections or log_line_prefix settings.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must have pgaudit enabled and configured to log 'role, read, write, ddl'.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- No evidence of 'shared_preload_libraries = 'pgaudit'' or 'pgaudit.log = 'ddl, role, read, write'' in any static configuration.
- The only references to PostgreSQL are in infrastructure-as-code (deploy/aws/iris-stack.yaml) and in application code (pointcloud-project/colmap_ingest.py, api/app/process/router.py), but these do not configure auditing.
- No evidence of pgaudit installation or configuration in bootstrap scripts or CloudFormation templates.
- Requirement: PARTIALLY SATISFIED — PostgreSQL is provisioned (see deploy/aws/iris-stack.yaml, resource 'PostgresDB'), but there is no static evidence that pgaudit is enabled or configured as required.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must generate audit records for unsuccessful privileged activity attempts (e.g., failed CREATE ROLE, etc.), which is typically satisfied by logging denials/errors.
- No postgresql.conf or RDS parameter group configuration is present in any provided file.
- No evidence of 'log_statement', 'log_min_error_statement', or similar logging configuration in static files.
- No evidence of log file review or error logging configuration in application or infrastructure code.
- Application code (pointcloud-project/colmap_ingest.py, api/app/process/router.py) interacts with PostgreSQL but does not configure logging/auditing.
- Requirement: PARTIALLY SATISFIED — PostgreSQL is present, but there is no static evidence that error/denial logging is enabled to capture unsuccessful privileged activity attempts.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to execute privileged SQL.

All denials are logged by default if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 103. CD16-00-011600 | SV-261960r1000885

- Rule ID: SV-261960r1000885
- Severity: medium
- Rule Title: PostgreSQL must generate audit records showing starting and ending time for user access to the database(s).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must log connection and disconnection events, including time, username, and session ID (log_connections=on, log_disconnections=on, log_line_prefix with %m %u %c).
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of 'log_connections', 'log_disconnections', or 'log_line_prefix' settings in static configuration or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that connection/disconnection logging is enabled or that log_line_prefix includes required fields.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must log concurrent logons/connections by the same user from different workstations (log_connections=on, log_disconnections=on, log_line_prefix with %m %u %d %c).
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of 'log_connections', 'log_disconnections', or 'log_line_prefix' settings in static configuration or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that concurrent connection logging is enabled or that log_line_prefix includes required fields.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must generate audit records for successful accesses to objects (pgaudit enabled, pgaudit.log includes 'read, write').
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of 'shared_preload_libraries = 'pgaudit'' or 'pgaudit.log = 'read, write'' in static configuration or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that pgaudit is enabled or that successful object access is audited.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must generate audit records for unsuccessful accesses to objects (errors/denials must be logged).
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of error/denial logging configuration in static files or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that unsuccessful object access attempts are logged.

Remediation:
Configure PostgreSQL to produce audit records when unsuccessful attempts to access objects occur.

All errors and denials are logged if logging is enabled. To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

---

### 107. CD16-00-012000 | SV-261964r1000897

- Rule ID: SV-261964r1000897
- Severity: medium
- Rule Title: PostgreSQL must generate audit records for all direct access to the database(s).

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must generate audit records for all direct access (pgaudit enabled, log_connections=on, log_disconnections=on).
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of 'shared_preload_libraries = 'pgaudit'', 'log_connections=on', or 'log_disconnections=on' in static configuration or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that direct access auditing is enabled.

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

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: System-wide FIPS mode must be enabled (cat /proc/sys/crypto/fips_enabled == 1).
- This is a runtime OS-level setting and cannot be confirmed from static application or infrastructure code.
- No static artifact in the repository can indicate the FIPS mode status of the deployed system.
- Requirement: NOT REVIEWED — FIPS mode status is only verifiable at runtime.

Remediation:
Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, refer to the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 109. CD16-00-012300 | SV-261966r1137664

- Rule ID: SV-261966r1137664
- Severity: medium
- Rule Title: PostgreSQL must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners' requirements.

Status: Not Reviewed

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: System-wide FIPS mode must be enabled (cat /proc/sys/crypto/fips_enabled == 1) for cryptographic protection of unclassified information.
- This is a runtime OS-level setting and cannot be confirmed from static application or infrastructure code.
- No static artifact in the repository can indicate the FIPS mode status of the deployed system.
- Requirement: NOT REVIEWED — FIPS mode status is only verifiable at runtime.

Remediation:
Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS 140-2 compliant, refer to the official RHEL Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies.

For more information on configuring PostgreSQL to use SSL, refer to supplementary content APPENDIX-G.

---

### 110. CD16-00-012400 | SV-261967r1000906

- Rule ID: SV-261967r1000906
- Severity: medium
- Rule Title: PostgreSQL must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for standalone systems.

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must offload audit data to syslog (log_destination = 'syslog') and configure syslog_facility.
- No postgresql.conf or equivalent configuration is present in any provided file.
- No evidence of 'log_destination = 'syslog'' or 'syslog_facility' in static configuration or infrastructure code.
- Application code does not configure or enforce these settings.
- Requirement: NOT SATISFIED — No static evidence that PostgreSQL audit logs are offloaded to syslog.

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

Status: Open

Evidence:
- Static repository review completed on 2026-04-30.
- Control requires: PostgreSQL must be a vendor-supported version.
- PostgreSQL is provisioned via AWS RDS in deploy/aws/iris-stack.yaml:
- File: deploy/aws/iris-stack.yaml — resource 'PostgresDB', property 'Engine: postgres'
- No explicit version is specified (defaults to AWS RDS default, which may not be latest/supported).
- No evidence of version pinning or enforcement in infrastructure code.
- No evidence of version checks or upgrade automation in CI/CD workflows.
- Requirement: PARTIALLY SATISFIED — PostgreSQL is provisioned, but the version is not statically pinned or checked for vendor support.

Remediation:
Upgrade or install a version of the product supported by the vendor.

---
