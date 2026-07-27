                          ┌──────────────────┐
                          │  cmd/authzmtls   │
                          └──────────────────┘
                       /      |      |      \      \
                      /       |      |       \      \
                     v        v      v        v      v
             ┌──────────┐ ┌───────┐ ┌──────────────┐ ┌───────────┐
             │  server  │ │ rules │ │ datasources/ │ │  config   │
             │          │ │       │ │     ldap     │ │           │
             └──────────┘ └───────┘ └──────────────┘ └───────────┘
               |   |   |     |  |  |        |               |
               |   |   |     |  |  |        v               v
               |   |   |     |  |  |  ┌──────────────┐ ┌──────────┐
               |   |   |     |  |  +->│ datasources  │ │ logging  │
               |   |   |     |  |     └──────────────┘ └──────────┘
               |   |   |     |  |            |
               |   |   |     |  +------------+
               |   |   |     |               |
               |   |   |     v               v
               |   |   |  ┌──────────┐  ┌───────────┐
               |   |   +->│ dockerapi│  │ telemetry │
               |   |      └──────────┘  └───────────┘
               |   |         |    |
               |   +---------+    +----> internal/logging
               |                          internal/telemetry
               +--------------------------------------------+
               (server -> config, datasources, dockerapi, rules)

  Leaves (no internal deps): logging, telemetry

  Rough layering, top (entrypoint) to bottom (leaves):

  cmd/authzmtls
        │
        ▼
     server ──────► rules ──────► datasources/ldap
        │              │                │
        │              │                ▼
        ├──► config    ├──► dockerapi   datasources
        │      │       │       │            │
        │      ▼       │       ▼            │
        │   logging    │   logging          │
        │              │       │            │
        └──► datasources     telemetry ◄────┘
                │
                ▼
            telemetry
