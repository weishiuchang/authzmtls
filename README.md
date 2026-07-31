# authzmtls

Running docker on workstations across your enterprise is scary enough.  This
docker authz service helps manage the risks you are willing to tolerate in your
mTLS environment by checking all docker mount commands against an allow list.

[authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/)

## How it works

```
 docker CLI  --mTLS-->  dockerd[:2376]  -->  authzmtls[:443]
```

1. Docker CLI users authenticate to `dockerd` via mutual TLS (standard
   `dockerd` config)
2. `dockerd` then restfully call authzmtls with
   `/AuthZPlugin.AuthZReq`/`AuthZRes` before and after each API request for
   allow/deny responses.

### Docker TLS

Docker CLI users will need to enable TLS:

```bash
export DOCKER_HOST=tcp://127.0.0.1:2376
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=$HOME/certs

$ ls -1 $HOME/certs/
ca.pem
certs.pem
key.pem
```

This works with docker compose as well.

### Docker plugin

On the docker daemon add a `/etc/docker/plugins/authzmtls.json`:

```json
{
  "Name": "authzmtls",
  "Addr": "https://authzmtls.internal:443",
  "TLSConfig": { "CAFile": "/etc/docker/certs.d/authzmtls/ca.pem" }
}
```

and enable it in `/etc/docker/daemon.json`:

```json
{
    "authorization-plugins": ["authzmtls"]
}
```

## Enforcement

Six built-in rules (`internal/rules`):

| Rule | Triggers on | Config | Default |
|---|---|---|---|
| Mount allowlist | `HostConfig.Binds`/`Mounts` on `/containers/create` | `allowlist` | deny outside allowlist |
| Volume bind mount | `local`-driver `o=bind` opts on `/volumes/create` | `allowlist` (same list) | deny outside allowlist |
| Host networking | `HostConfig.NetworkMode: "host"` | `checks.host_network` | allow |
| Privileged mode | `HostConfig.Privileged: true` | `checks.privileged` | allow |
| `docker cp` | `GET`/`PUT .../containers/{id}/archive` | `checks.docker_cp` | allow |
| `docker exec` | `POST .../containers/{id}/exec` | `checks.docker_exec` | allow |

**Volume bind mount** prevents a specific bypass: the `local` volume driver's
`type=none`/`o=bind`/`device=<path>` opts alias a host path as a named
volume, skipping `HostConfig.Binds`/`Mounts` entirely - this rule re-checks
`device` against the same allowlist at volume-**creation** time, though not
retroactively for a bind-style volume created earlier and later referenced by
name.

The last four are simple global on/off gates. This is here so you can make an
informed decision on your environment and risk tolerance. Unlike volume
requests, docker does **not** send user information in `AuthZReq` when someone
does a `docker cp` or `docker exec`, which means authzmtls cannot determine if
that person is trying to copy a file from someone elses running container, or
exec into another user's container. But if you decide to disable this, then you
would have restricted a very useful and common conop. Ultimately that is
a decision you will have to have for your enterprise.

In the future I might extend authzmtls service with a database to solve the
docker `cp`/`exec` problem by recording the `create`/`run` request and then
checking for the same user on subsequent `cp`/`exec` commands.

### Admins: `admin_users` / `admin_groups`

```yaml
admin_users: []
admin_groups: []
```

A resolved `$USER`/`$GROUP` value (same lookup as "Allowlist matching" below)
listed in either one bypasses **every** rule above outright - all six, not
just the mount allowlist - so an admin's `docker cp`/`exec`/`--privileged`/
`--network host`/anything is always allowed. This check runs first, before
any other rule, and unlike the mount allowlist it applies to every request,
not just ones that mount something. Empty (the default) means the feature
is unused and no datasource is ever queried for it.

## Allowlist matching

Path entries can use variables that is automatically populated from a data
source lookup from the identity sent in `AuthZReq`.

Note: The allow list is component-aware (`/data/app1` does **not** match
`/data/app12`):

```yaml
allowlist:
  - /data/app1   # allows /data/app1 and everything under it
  - /home/$USER
  - /remote/$GROUP
  - /remote/shared
```

1. Docker sends `AuthZReq` with `identity` information along with mounts
2. authmtls uses that `identity` with data sources to look up `$USER`/`$GROUP`
3. `$USER`/`$GROUP` is used in the allowlist paths to return allow/deny back to docker

### LDAP provider

```yaml
datasources:
  - name: ad01
    type: ldap
    url: ldaps://activedirectory01.example.com
    bind_dn: readonly_acct
    bind_pw: readonly_pwd
    cache_ttl: 10m
    pool_size: 8

    user_search:
      base_dn: "dc=example,dc=com"
      # $IDENTITY is RDN-reversed + RFC 4515-escaped first; userAccountControl
      # clauses exclude disabled/locked accounts.
      filter: "(&(objectCategory=person)(objectClass=user)(altSecurityIdentities=X509:<S>$IDENTITY)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=16)))"
      attribute: sAMAccountName   # -> $USER, verbatim

    group_search:
      base_dn: "ou=groups,dc=example,dc=com"
      filter: "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=$IDENTITY_DN))" # matching-rule-in-chain OID resolves nested membership
      attribute: cn
```

- Both `user_search` and `group_search` are required if you use
  `$USER`/`$GROUP`. `user_search` matching more than one account is valid.
  Every matched account contributes to `$USER`, and its own
  `group_search` results are unioned into `$GROUP` across every match. Only
  zero matches means "unresolved."
- Multiple configured datasources are queried concurrently and unioned (not
  first-match-wins), so a second AD server is redundancy, not just a
  fallback - the same union applies within one datasource across multiple
  matched accounts.
- **Something else has to populate `altSecurityIdentities`** (a cert-issuance
  pipeline or AD sync job, kept in sync with cert rotation) - our ldap data
  source only searches it.

## Configuration

```
/etc/authzmtls/config.yaml
/etc/authzmtls/conf.d/
```

**Precedence** (highest wins): CLI flags > env vars (`AUTHZ_*`) > `config.yaml`
+ `conf.d/*.yaml` (`allowlist`/`datasources`/`admin_users`/`admin_groups`
unioned instead of replace). `allowlist`, `datasources`, `checks.*`,
`admin_users`, and `admin_groups` are not allowed from CLI flags or env.

`SIGHUP` reloads config, rotates TLS certs if configured, and unconditionally
flushes the datasource cache.

```yaml
logging_level: info
server:
  listen_addr: ":80"
  server_cert: /etc/authzmtls/tls/server.crt  # optional
  server_key: /etc/authzmtls/tls/server.key
  metrics_path: /metrics
  decision_timeout: 2s
```

Environment variables are named the same as the config variables, but
uppercase and with `AUTHZ_` prefixes, ie. `AUTHZ_LISTEN_ADDR`. CLI
flags replace `_` with `-`, ie. `--listen-addr`.

## Logging

`logging_level` defaults to `info`, standard threshold semantics. Each level
has one job:

| Level | Default? | Contains |
|---|---|---|
| `TRACE` | off | Full `AuthZReq`/`AuthZRes` JSON, every call - *everything*, including `docker run -e` env vars. |
| `DEBUG` | off | Allow decisions, plus the configured allowlist at startup/reload. |
| `INFO` | **on** | Deny decisions, `STARTING`, `SIGHUP` received, `SHUTTING DOWN`. Nothing else. |
| `WARN` | on | A live datasource failure, an ignored unrecognized config field, or a request failing identity sanitization (possible-attack signal). |
| `ERROR` | on | Conditions that crash the process - bad config, bad TLS certs, failure to bind the listen address. |

`TRACE` logs structured JSON fields with raw request bodies from docker.

## Performance & concurrency

- Each `dockerd` request runs on its own goroutine; config is read via a
  lock-free `atomic.Pointer`, swapped only on `SIGHUP`.
- Each datasource caches `$IDENTITY` -> resolved variables (`cache_ttl`,
  default `10m`) with request coalescing.
  **Stale-while-revalidate**: a failed refresh keeps serving the last good
  value (negative-cached if there was never one).
- `server.decision_timeout` (default `2s`) limits a live datasource call;
  expiry counts as a lookup failure.
- Multiple mounts in one request, and multiple datasources on a cache miss,
  are checked/queried concurrently. `GOMAXPROCS` respects the container's CPU
  quota (`go.uber.org/automaxprocs`).
- Metrics via [OpenTelemetry](https://opentelemetry.io/), scraped as
  Prometheus at `server.metrics_path` - see `METRICS.md`.

## Kubernetes deployment (Helm)

```
helm install authzmtls deploy/helm --values my-values.yaml
```

## Releases

authzmtls containers are available at ghcr.io/weishiuchang/authzmtls:`version`

authzmtls helm charts are available at oci://ghcr.io/weishiuchang/charts/authzmtls:`version`

## Contributing

Pull requests with code are always welcome.

I am especially looking for additional data sources.

`$IDENTITY` is pulled from the incoming user docker request and provided to the data source plugin.
The data source plugin is then expected to produce any variables for matching in allow list paths.
The included ldap plugin produces `$USER` and `$GROUP`, for example.

## Security notes

- Docker's plugin framework fails closed if this service is unreachable, so
  every `docker` command needing a check fails fleet-wide - run at least 2
  replicas (the Helm default) for HA.
- Mount paths are canonicalized (symlinks resolved, `..` rejected) before
  matching, to block traversal-based bypasses.
- `allowlist`, `datasources`, `checks.*`, `admin_users`, and `admin_groups`
  are config-file only by design, with no env/CLI override, and LDAP filters
  are RFC 4515-escaped before substitution rather than raw string
  concatenation.
- `admin_users`/`admin_groups` bypass every check - keep both lists as short
  as possible and treat them with the same care as the datasource
  credentials below.
- Datasource credentials (e.g. `bind_pw`) are plaintext in the config file -
  restrict file permissions or mount as a Kubernetes Secret.
