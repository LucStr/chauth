-- Upstream objects chauth needs, for the databases core and otel and the read-only database system.
-- The tests run this file as is, so the admin's grants here are the complete set chauth relies on.

-- One read and one write role per database in instances[].databases (roleTemplate chauth_{database}_{level}).
CREATE ROLE chauth_core_read;
GRANT SHOW, SELECT ON core.* TO chauth_core_read;
CREATE ROLE chauth_core_write;
GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE ON core.* TO chauth_core_write;
CREATE ROLE chauth_otel_read;
GRANT SHOW, SELECT ON otel.* TO chauth_otel_read;
CREATE ROLE chauth_otel_write;
GRANT SHOW, SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE ON otel.* TO chauth_otel_write;

-- A database in instances[].readOnlyDatabases needs only its read role.
CREATE ROLE chauth_system_read;
GRANT SELECT ON system.parts TO chauth_system_read;
GRANT SELECT ON system.settings_changes TO chauth_system_read;

-- A role granted by name (instances[].roles), granted verbatim: REMOTE and CLUSTER reach beyond the
-- per-database model (as would URL or FILE), so bind a role like this to administrators only.
CREATE ROLE chauth_querylog_read;
GRANT SELECT ON system.query_log TO chauth_querylog_read;
GRANT CLUSTER ON *.* TO chauth_querylog_read;
GRANT REMOTE ON *.* TO chauth_querylog_read;

-- The admin login of credentialsFile. In production add HOST IP '<network chauth connects from>'.
-- No ALTER USER: ALTER USER <prefix>x RENAME TO y passes the prefix check and leaves the prefix.
CREATE USER chauth_admin IDENTIFIED WITH sha256_password BY 'Admin-secret-1';
GRANT CREATE USER, DROP USER ON chauth_tmp_* TO chauth_admin;
GRANT chauth_core_read, chauth_core_write, chauth_otel_read, chauth_otel_write, chauth_system_read, chauth_querylog_read TO chauth_admin WITH ADMIN OPTION;
GRANT SELECT(name, valid_until) ON system.users TO chauth_admin;
-- Run tokens get table privileges directly, only those the binding's role holds: every verb on each
-- writable database, and on a read-only one SELECT on each table its read role names.
GRANT SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON core.* TO chauth_admin WITH GRANT OPTION;
GRANT SELECT, INSERT, ALTER UPDATE, ALTER DELETE ON otel.* TO chauth_admin WITH GRANT OPTION;
GRANT SELECT ON system.parts TO chauth_admin WITH GRANT OPTION;
GRANT SELECT ON system.settings_changes TO chauth_admin WITH GRANT OPTION;
-- What each role holds and the row estimates of GET /v1/tables.
GRANT SELECT(role_name, access_type, database, table, column, is_partial_revoke) ON system.grants TO chauth_admin;
GRANT SELECT(database, table, rows, active) ON system.parts TO chauth_admin;
-- Row policies per database; a database without this line (system on ClickHouse Cloud) gets no run tokens.
GRANT SELECT(database) ON system.row_policies TO chauth_admin;
GRANT SHOW ROW POLICIES ON core.* TO chauth_admin;
GRANT SHOW ROW POLICIES ON otel.* TO chauth_admin;
