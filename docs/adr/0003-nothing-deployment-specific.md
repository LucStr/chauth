# Nothing deployment-specific in code

chauth trusts any OIDC issuer: issuer, audience, claim names, the group prefix, scopes, the client allowlist, role names and the access-help text are configuration, and access comes from the rules files ([0002](0002-authorization-as-code.md)). No organisation, identity provider, host name or person appears in code, tests or examples; examples use `example.com`. Deciding who belongs to which group stays in the identity provider, and anything one deployment needs that another would not is a config key, not a branch.
