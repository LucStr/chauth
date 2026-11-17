# Changelog

## Unreleased

- Initial release. `chauth serve` proxies ClickHouse's native and HTTPS protocols with an OIDC access token as the credential and connects as a temporary user holding exactly the upstream roles of the holder's `ChRole` / `ChRoleBinding` rules (`chauth.dev/v1alpha1`), capped by the token's scope. `chauth lint` checks the rules offline; `chauth connect`, `ls`, `login`, `logout` and `service` are the connector. Per-instance `readOnlyDatabases` give only the read role for every grant.
