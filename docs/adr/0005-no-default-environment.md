# The database name is the address, with no default environment except on bound listeners

A client picks the environment in the database name: `<env>/<db>` or `<env>/<instance>/<db>`. The connector strips `<env>/` and forwards the rest. On the main ports there is no default environment, so a bare name fails and lists the environments: whoever reads a connection string, a log line or an agent's query sees which deployment it touches, and nothing reaches prod by accident.

The exception is opt-in: a listener bound to an environment (`listeners: [{listen, listenHTTP, env}]`) treats a name without a known `<env>/` prefix, the empty one included, as in that environment, and still accepts another environment's explicit `<env>/<db>`. `clickhouse-client --query` sends no database and tools browse by bare name, so such a port must accept both. The environment is still explicit, in the port the client points at.
