# Chihiro

Chihiro is a Go web application that watches Kubernetes Cluster API (CAPI)
custom resources and exposes a dashboard to create, edit, and delete workload
clusters. Auth is OIDC, sessions live in Redis, and the UI updates in real time
over WebSockets.

## Configuration

Settings are read from `config.yaml` and can be overridden with environment
variables using the `CHIHIRO_` prefix. The env var name maps to the config path
with dots replaced by underscores (e.g. `oidc.issuer_url` →
`CHIHIRO_OIDC_ISSUER_URL`). Secrets (client secret, session key, redis password)
must come from environment variables only.

### Server

| Key              | Env var                    | Type   | Default     | Description                                                  |
| ---------------- | -------------------------- | ------ | ----------- | ------------------------------------------------------------ |
| `host`           | `CHIHIRO_HOST`             | string | `0.0.0.0`   | Address the HTTP server binds to.                            |
| `port`           | `CHIHIRO_PORT`             | int    | `8080`      | Port the HTTP server listens on.                             |
| `docs_url`       | `CHIHIRO_DOCS_URL`         | string | —           | External docs link shown in the UI.                          |
| `allowed_origins`| `CHIHIRO_ALLOWED_ORIGINS`  | string | —           | Comma-separated list of trusted origins for OAuth redirect host detection and WebSocket origin checks. Exact match only, no wildcards. |

```yaml
host: "0.0.0.0"
port: 8080
docs_url: "https://docs.example.io/"
allowed_origins: "https://dashboard.example.io,https://admin.example.io"
```

### OIDC

| Key                 | Env var                       | Type   | Description                                              |
| ------------------- | ----------------------------- | ------ | ------------------------------------------------------- |
| `oidc.issuer_url`   | `CHIHIRO_OIDC_ISSUER_URL`     | string | OIDC provider issuer URL.                               |
| `oidc.client_id`    | `CHIHIRO_OIDC_CLIENT_ID`      | string | OIDC client ID.                                         |
| `oidc.client_secret`| `CHIHIRO_OIDC_CLIENT_SECRET`  | string | OIDC client secret. **Env only** — never in config.     |
| `oidc.redirect_url` | `CHIHIRO_OIDC_REDIRECT_URL`   | string | OAuth callback URL. HTTPS auto-enables secure cookies.  |
| `session_key`       | `CHIHIRO_SESSION_KEY`         | string | Session encryption key, **min 32 bytes**. **Env only**. |

```yaml
oidc:
  issuer_url: "https://your-issuer.com"
  client_id: "your-client-id"
  redirect_url: "http://localhost:8080/auth/callback"
```

```sh
export CHIHIRO_OIDC_CLIENT_SECRET="..."
export CHIHIRO_SESSION_KEY="$(openssl rand -base64 32)"
```

### Redis / sessions

| Key                 | Env var                    | Type   | Default      | Description                                  |
| ------------------- | -------------------------- | ------ | ------------ | -------------------------------------------- |
| `redis.addr`        | `CHIHIRO_REDIS_ADDR`       | string | `localhost:6379` | Redis address for session storage.       |
| `redis.username`    | `CHIHIRO_REDIS_USERNAME`   | string | `""`         | Redis username (optional).                   |
| `redis.password`    | `CHIHIRO_REDIS_PASSWORD`   | string | `""`         | Redis password. **Env only**.                |
| `redis.session_ttl` | `CHIHIRO_SESSION_TTL`      | int    | `3600`       | Session lifetime in seconds.                 |
| `session.secure`    | `CHIHIRO_SESSION_SECURE`   | bool   | auto         | Force the cookie `Secure` flag. Auto-enabled when redirect URL is HTTPS. |

```yaml
redis:
  addr: "127.0.0.1:6379"
  username: ""
  session_ttl: 7200
```

### Cluster

| Key                         | Env var                        | Type     | Description                                            |
| --------------------------- | ------------------------------ | -------- | ----------------------------------------------------- |
| `cluster.domain`            | `CHIHIRO_CLUSTER_DOMAIN`       | string   | Base domain used for generated clusters.              |
| `cluster.port`              | `CHIHIRO_CLUSTER_PORT`         | int      | API server port for generated kubeconfigs.            |
| `cluster.available_versions`| `CHIHIRO_AVAILABLE_VERSIONS`   | []string | Selectable Kubernetes versions (comma-sep in env).    |
| `cluster.admin_groups`      | `CHIHIRO_ADMIN_GROUPS`         | []string | OIDC groups with full access to all clusters/fields.  |
| `cluster.creator_groups`    | `CHIHIRO_CREATOR_GROUPS`       | []string | OIDC groups allowed to create/edit/delete clusters.   |
| `cluster.limits.max_clusters`   | `CHIHIRO_MAX_CLUSTERS`     | int      | Max number of clusters.                               |
| `cluster.limits.max_total_nodes`| `CHIHIRO_MAX_TOTAL_NODES`  | int      | Max total worker nodes across clusters.               |
| `cluster.limits.max_total_cp`   | `CHIHIRO_MAX_TOTAL_CP`     | int      | Max total control plane replicas across clusters.     |

```yaml
cluster:
  domain: "mgmt.example.lan"
  port: 443
  available_versions: ["v1.36.1", "v1.35.4"]
  admin_groups: [kube-admin]
  creator_groups: [kube-admin, cluster-creators]
  limits:
    max_clusters: 5
    max_total_nodes: 10
    max_total_cp: 9
```

## Cluster templating

`cluster.template` is the CAPI `Cluster` YAML rendered on creation. It contains
`{{ chihiro.<key> }}` placeholders that are filled from **parameters** (user
inputs) and **injections** (built-in fields). Worker groups have their own
schema and template.

### `cluster.parameters`

Each placeholder `{{ chihiro.<key> }}` in the template maps to a parameter that
becomes a form input.

| Field           | Type     | Description                                                        |
| --------------- | -------- | ------------------------------------------------------------------ |
| `label`         | string   | UI label (defaults to a humanized key).                            |
| `description`   | string   | Help text shown under the input.                                   |
| `type`          | string   | `string` \| `number` \| `select` \| `boolean`.                     |
| `default`       | scalar   | Pre-filled value. May reference other params, e.g. `{{ chihiro.version }}`. |
| `options`       | list     | Choices for `select`. Plain strings, or `{value, label, constrain}`. |
| `required`      | bool     | Field must be non-empty.                                           |
| `min` / `max`   | int      | Numeric bounds for `number`.                                       |
| `true_value` / `false_value` | string | Strings substituted for a `boolean` when on/off (default `true`/`false`). |
| `editable`      | bool     | Expose a post-creation edit button. Requires `path`.              |
| `path`          | string   | YAML path on the live `Cluster` to write edits to.                |
| `visible_groups`| []string | Restrict who can see/edit. Empty = everyone. Admins always see.   |
| `recompute_on`  | []string | List of fields whose change should re-resolve this parameter. Useful when a parameter depends on another but the dependency can't be inferred from `constrain` metadata. |
| `implies`       | list     | Declares fields this parameter sets when edited. Each entry is `{field, source}` where `field` is the target field and `source` is a map of allowed values to the value to push. |

```yaml
parameters:
  podCIDR:
    label: "Pod CIDR"
    type: string
    default: "10.207.0.0/16"
  cilium:
    label: "Cilium CNI"
    type: boolean
    default: true
    true_value: enabled
    false_value: disabled
    editable: true
    path: "metadata.labels.'sveltos.argus.rpcu.io/cilium'"
    visible_groups: [kube-admin]
```

`select` options can be **constrained** to certain values of another field
(any built-in injection or another parameter) via `constrain: { <field>:
[values] }`. An option is only valid while every constrained field holds one of
the listed values. This works in both directions:

- When the constrained field changes, this parameter is recomputed to the first
  compatible option (no `recompute_on` needed).
- When an option that pins a field to a single value is selected, that value is
  pushed back to the field.

```yaml
  imageName:
    type: select
    options:
      - value: "kaas-25.11-{{ chihiro.version }}"
        label: "25.11"
        constrain:
          version: ["v1.35.4"]
      - value: "kaas-26.05-{{ chihiro.version }}"
        label: "26.05"
        constrain:
          version: ["v1.36.1"]
    editable: true
    path: "spec.topology.variables[2].value"
```

Constraints are generic — you can constrain one parameter to another, e.g. a
driver valid only in certain regions:

```yaml
  region:
    type: select
    options: [eu, us]
    default: eu
  driver:
    type: select
    options:
      - value: "eu-driver"
        constrain: { region: [eu] }
      - value: "us-driver"
        constrain: { region: [us] }
    editable: true
    path: "spec.topology.variables[3].value"
```

When `constrain` metadata is enough to express the dependency, Chihiro
auto-detects it. For cases where the dependency cannot be inferred from the
option constraints, use `recompute_on` to declare it explicitly:

```yaml
  customImage:
    type: select
    options: [img-a, img-b]
    recompute_on: [version]
    editable: true
    path: "spec.topology.variables[4].value"
```

The `implies` field lets a parameter push values to other fields when edited.
Each entry maps a target field to a set of allowed source values and the value
to write:

```yaml
  region:
    type: select
    options: [eu, us]
    implies:
      - field: driver
        source:
          eu: "eu-driver"
          us: "us-driver"
    editable: true
    path: "spec.topology.variables[0].value"
```

### `cluster.injections`

Built-in cluster fields written at a given YAML path after the template is
parsed. Keys are well-known: `name`, `version`, `serviceDomain`, `groups`,
`workerGroups`, `controlPlaneReplicas`.

| Field           | Type     | Description                                                       |
| --------------- | -------- | --------------------------------------------------------------- |
| `path`          | string   | YAML path the value is written to (`groups` has none).         |
| `label`         | string   | UI label.                                                       |
| `editable`      | bool     | Expose a post-creation edit button.                            |
| `min` / `max`   | int      | Numeric bounds (e.g. control plane replicas).                  |
| `visible_groups`| []string | Restrict who can edit. Empty = everyone with modify rights.    |

```yaml
injections:
  version:
    path: spec.topology.version
    label: "Kubernetes Version"
    editable: true
  controlPlaneReplicas:
    path: spec.topology.controlPlane.replicas
    label: "Control Plane Replicas"
    editable: true
    min: 1
    max: 9
    visible_groups: [kube-admin]
```

### Worker groups

`cluster.worker_group_fields` defines the per-group inputs; the value of each
field lands wherever `worker_group_template` references it as
`{{ chihiro.field.<key> }}`. Fields = what the user types, template = the YAML
shape. The template is rendered once per group and appended to
`spec.topology.workers.machineDeployments`.

| Field           | Type     | Description                                            |
| --------------- | -------- | ----------------------------------------------------- |
| `label`         | string   | UI label.                                             |
| `type`          | string   | `string` \| `number` \| `select`.                     |
| `options`       | []string | Choices for `select`.                                 |
| `default`       | string   | Pre-filled value.                                     |
| `required`      | bool     | Field must be non-empty.                              |
| `min` / `max`   | int      | Numeric bounds for `number`.                          |
| `order`         | int      | Left-to-right display order (ties broken by key).     |
| `visible_groups`| []string | Restrict who can see/edit.                            |

```yaml
worker_group_fields:
  name:
    label: "Group name"
    type: string
    required: true
    order: 0
  flavor:
    label: "Flavor"
    type: select
    options: [small, medium, large]
    default: medium
    order: 1
  replicas:
    label: "Replicas"
    type: number
    default: "1"
    min: 1
    max: 10
    order: 2
worker_group_template: |
  name: {{ chihiro.field.name }}
  replicas: {{ chihiro.field.replicas }}
  variables:
    overrides:
      - name: workerFlavor
        value: {{ chihiro.field.flavor }}
```

## Examples

- `config.yaml` — full local/dev example.
- `manifests/configmap.yaml` — Kubernetes ConfigMap example.
- `manifests/secret-example.yaml` — secrets template (client secret, session key, redis password).
