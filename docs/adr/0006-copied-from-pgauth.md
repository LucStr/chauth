# Shared code is copied from pgauth, not imported

chauth started as a second binary of [pgauth](https://github.com/LucStr/pgauth), the same proxy for Postgres, and became its own repository. Token verification, the rules format with its loader and lint, the connector's browser login, keychain, token file and service install, and the telemetry setup were copied here and trimmed to what ClickHouse needs, instead of being imported from pgauth or split into a shared module.

One repository per product keeps each one's API, releases and reviews independent, and neither carries the other's protocol. The cost: the copied code exists twice. A fix to it, above all a security fix in token verification, rule evaluation or the connector, must be made in both repositories, and a reviewer of one should ask whether the other needs it. The copy is recorded in `NOTICE`.
