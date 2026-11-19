# chauth

Scoped access to ClickHouse: who may read or write which database, decided by the proxy from role bindings and enforced by ClickHouse through temp users.

## Language

**chauth**:
The proxy that accepts a database token as a ClickHouse password (native) or bearer token (HTTPS) and connects as a temp user.
_Avoid_: clickhouse proxy, ch-gate, gateway

**Database token**:
A short-lived OIDC access token for chauth's audience that proves who the holder is (user and groups) and carries a database scope; it lists no grants.
_Avoid_: JWT, credential

**Database scope**:
The OAuth scope `clickhouse:read` or `clickhouse:write` a token was issued with; chauth caps the access from role bindings by it.
_Avoid_: agent ceiling, agent limit

**Database grant**:
A `ChRole` grant `{instance, database, level}` that gives read or write on one database, or on every database of an instance with `database: "*"`.
_Avoid_: permission, access right, ACL

**Named-role grant**:
A `ChRole` grant `{instance, role, level}` that gives one upstream role from the instance's allowlist, instead of a database.
_Avoid_: custom role, direct grant

**Built-in role**:
A `ChRole` chauth provides without YAML: `<instance>.<db>.read|write` for every configured database. There is no admin or reader role.
_Avoid_: default role, system role

**Authorization details**:
The token's `authorization_details` rows that narrow what its bindings give: consent rows per database (read or write) and run rows naming tables and verbs.
_Avoid_: token grants, permissions claim

**Table grant**:
One verb (select, insert, update, delete) on one table, granted to a temp user directly from a run row; never DDL.
_Avoid_: table role

**Role binding**:
A `ChRoleBinding` that gives one `ChRole`'s grants to users and groups named in the token.
_Avoid_: assignment, membership

**Upstream role**:
A ClickHouse role defined outside chauth (`chauth_<db>_read|write` from `roleTemplate`, or an allowlisted named role) that a temp user is granted.
_Avoid_: db role, group role

**Read-only database**:
A database in `instances[].readOnlyDatabases`; every grant on it, write included, gives only its read role.
_Avoid_: system database (it need not be `system`)

**Temp user**:
A ClickHouse user chauth creates for one holder, level and role set, and drops after its last use.
_Avoid_: temporary role, ephemeral user, dynamic credential

**Admin login**:
The ClickHouse user chauth manages temp users with; it may create and drop only users with the temp-user prefix and has no `ALTER USER`.
_Avoid_: service account, root user

**Gate check**:
The moment access is decided: when a native connection opens, or for each HTTP request. An open native connection is not re-checked; it is cut at `maxConnectionAge`.
_Avoid_: session check, re-validation

**Instance**:
One ClickHouse service chauth can reach. Database names are only unique within an instance.
_Avoid_: server, cluster, host

**Connector**:
The local program a person or agent runs (`chauth connect`) that gets tokens and lets any ClickHouse client reach chauth through `localhost`.
_Avoid_: helper, CLI, local proxy

**Environment**:
One chauth deployment a connector reaches, such as prod or test, with its own servers and token source. It is the first segment of a database address.
_Avoid_: profile, context, cluster

**Database address**:
The database name a client asks the connector for: `<env>/<db>` or `<env>/<instance>/<db>`. Only a bound listener has a default environment.
_Avoid_: DSN, connection name
