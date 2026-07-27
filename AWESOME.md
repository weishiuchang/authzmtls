Huge kudos to apps/libs used (as examples, docs, apps, or libs) in authzmtls.

- [Docker: Access authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/) - the official spec authzmtls implements (`/Plugin.Activate`, `AuthZReq`/`AuthZRes`).
- [open-policy-agent/opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) - a Rego-policy-driven authz plugin; a useful reference for a declarative-policy alternative to authzmtls's Go rule chain.
- [go-ldap/ldap](https://github.com/go-ldap/ldap) - the LDAP client library authzmtls's `internal/datasources/ldap` is built on.
- [alecthomas/kong](https://github.com/alecthomas/kong) - CLI flag parsing (`cmd/authzmtls`).
- [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru) - the size-bounded LRU behind `internal/datasources`' cache.
- [uber-go/automaxprocs](https://github.com/uber-go/automaxprocs) - sets `GOMAXPROCS` from the container's CPU quota at startup.
- [open-telemetry/opentelemetry-go](https://github.com/open-telemetry/opentelemetry-go) - the metrics SDK behind `internal/telemetry`.
