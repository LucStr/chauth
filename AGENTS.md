# chauth

Provider-agnostic ClickHouse proxy: OIDC access token as password → access from `ChRole` / `ChRoleBinding` YAML, capped by scope → temporary ClickHouse user with exactly those roles → spliced connection, native and HTTPS. Read `GLOSSARY.md` for the terms and `docs/adr/` before changing behaviour; `docs/config.md` is the config reference.

- `cmd/chauth` CLI · `internal/chconfig` serve config · `internal/chwire` native Hello/Exception codec · `internal/rbac` rules parsing, lint and reload · `internal/token` JWT verification · `internal/chconnect` connector (native and HTTP listeners, `ls`) · `internal/connect` connect.yaml, browser login, keychain, token file, service install · `internal/config` shared config blocks · `internal/telemetry` OTel traces/metrics/logs and the stdout+OTLP logger.
- Nothing deployment-specific in code, tests or examples (ADR 0003): issuer, audience, claims, scopes, role names and allowlists are config; examples use `example.com`.
- Token verification, rules and connector code are copied from pgauth (ADR 0006): a fix there may be needed here, and the other way round.
- Tests are table-driven. Anything that talks to ClickHouse runs against a real `clickhouse/clickhouse-server` container (testcontainers); no mocks of ClickHouse. `go test ./...` needs Docker once such tests exist.
- Comments: at most two lines, and only where a reader without it would write a bug. No references to tickets, chats or how the code got here.
- Commits and PR titles are conventional commits (`feat(serve): …`, `fix(connect): …`). `gofmt`, `go vet` and `go test -race` gate CI. Releases are tags `vX.Y.Z`; tags are never moved.
- Never log or trace query text or tokens. Never rely on `VALID UNTIL` to end access; dropping the temp user does.
