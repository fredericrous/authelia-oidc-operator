# Authelia OIDC Operator

A Kubernetes operator that manages OIDC client configurations for Authelia. It watches `OIDCClient`, `ClaimsPolicy`, and `UserAttribute` custom resources and automatically assembles the Authelia configuration.

## Features

- **Declarative OIDC Client Management**: Define OIDC clients as Kubernetes resources
- **Claims Policies**: Define which claims to include in tokens via `ClaimsPolicy` CRDs
- **User Attributes**: Define custom user attributes with CEL expressions via `UserAttribute` CRDs
- **Automatic Configuration Assembly**: Aggregates all resources into Authelia's configuration with deep merge
- **ExternalSecrets Integration**: Works seamlessly with ExternalSecrets/Vault for secret management
- **Instant Updates**: Reacts immediately to changes (no polling delays)
- **Secure**: Hashes client secrets using PBKDF2-SHA512 with deterministic salts
- **Namespace-Scoped References**: ClaimsPolicy and UserAttribute must be in the same namespace as the OIDCClient

## Installation

### Prerequisites

- Kubernetes cluster 1.28+
- Authelia deployed in the cluster
- ExternalSecrets operator (recommended for secret management)
- The OIDCClient CRD installed

### Install the CRDs

```bash
kubectl apply -f config/crd/bases/
```

### Deploy the Operator

```bash
kubectl apply -k kubernetes/homelab/security/authelia-oidc-operator/
```

## Usage

### OIDCClient with Secret Reference

Confidential clients require a `secretRef` pointing to a Kubernetes Secret containing the client secret. Use ExternalSecrets to manage the secret lifecycle.

```yaml
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: myapp
  namespace: myapp
spec:
  clientId: myapp
  clientName: My Application
  secretRef:
    name: myapp-oidc-secret
    key: client_secret
  redirectUris:
    - https://myapp.example.com/callback
```

### Public Client (No Secret Required)

```yaml
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: spa-app
  namespace: frontend
spec:
  clientId: spa-app
  clientName: Single Page Application
  public: true
  redirectUris:
    - https://spa.example.com/callback
  requirePkce: true
```

### ClaimsPolicy Example

Define which claims to include in tokens:

```yaml
apiVersion: security.homelab.io/v1alpha1
kind: ClaimsPolicy
metadata:
  name: grafana
  namespace: monitoring
spec:
  # policyName defaults to 'grafana' (metadata.name)
  idToken:
    - email
    - name
    - groups
    - preferred_username
```

### UserAttribute with ClaimsPolicy Example

Define custom user attributes and use them in claims policies:

```yaml
# First, define the user attribute
apiVersion: security.homelab.io/v1alpha1
kind: UserAttribute
metadata:
  name: is-nextcloud-admin
  namespace: nextcloud
spec:
  attributeName: is_nextcloud_admin  # Explicit Authelia name (snake_case)
  expression: '"lldap_admin" in groups'
---
# Then, reference it in a ClaimsPolicy
apiVersion: security.homelab.io/v1alpha1
kind: ClaimsPolicy
metadata:
  name: nextcloud-userinfo
  namespace: nextcloud
spec:
  policyName: nextcloud_userinfo
  customClaims:
    - is_nextcloud_admin  # Must exist as UserAttribute in same namespace
  customScope:
    scopeName: nextcloud_userinfo
    claims:
      - is_nextcloud_admin
---
# OIDCClient referencing the claims policy
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: nextcloud
  namespace: nextcloud
spec:
  clientId: nextcloud
  clientName: Nextcloud
  secretRef:
    name: oidc-nextcloud-client
    key: client_secret
  redirectUris:
    - https://drive.example.com/apps/oidc_login/oidc
  extraScopes:
    - nextcloud_userinfo
  claimsPolicy: nextcloud_userinfo  # Must exist as ClaimsPolicy in same namespace
```

### Full Example with ExternalSecrets

```yaml
# Password generator
apiVersion: generators.external-secrets.io/v1alpha1
kind: Password
metadata:
  name: myapp-oidc-password
  namespace: myapp
spec:
  length: 64
  digits: 10
  symbols: 0
---
# Generate secret
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: myapp-oidc-generated
  namespace: myapp
spec:
  refreshInterval: "0"
  target:
    name: myapp-oidc-secret
    creationPolicy: Owner
    template:
      data:
        client_secret: "{{ .password }}"
  dataFrom:
  - sourceRef:
      generatorRef:
        apiVersion: generators.external-secrets.io/v1alpha1
        kind: Password
        name: myapp-oidc-password
---
# OIDCClient referencing the secret
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: myapp
  namespace: myapp
spec:
  clientId: myapp
  clientName: My Application
  secretRef:
    name: myapp-oidc-secret
    key: client_secret
  redirectUris:
    - https://myapp.example.com/callback
```

## Configuration

The operator accepts the following flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--authelia-namespace` | `authelia` | Namespace where Authelia is deployed |
| `--authelia-configmap` | `authelia-config` | Name of the Authelia ConfigMap |
| `--authelia-configmap-base` | `authelia-config-base` | Name of the base Authelia ConfigMap |
| `--oidc-secrets` | `authelia-oidc-secrets` | Name of the OIDC secrets (for JWKS) |
| `--max-concurrent-reconciles` | `3` | Maximum concurrent reconciles |
| `--metrics-bind-address` | `:8080` | Metrics endpoint address |
| `--health-probe-bind-address` | `:8081` | Health probe address |
| `--leader-elect` | `false` | Enable leader election |

## How It Works

1. **Watch**: The operator watches `OIDCClient`, `ClaimsPolicy`, `UserAttribute` resources cluster-wide, plus the base ConfigMap
2. **Collect**: When any resource changes, it collects all resources
3. **Validate**: Validates references (ClaimsPolicy→UserAttribute, OIDCClient→ClaimsPolicy) are in the same namespace
4. **Resolve Secrets**: For each confidential client, fetches the secret from `secretRef`
5. **Hash**: Hashes secrets using PBKDF2-SHA512 with a deterministic salt derived from the clientId
6. **Assemble**: Builds the complete OIDC configuration
7. **Deep Merge**: Merges assembled config into the base ConfigMap, preserving non-managed fields
8. **Update**: Updates the Authelia ConfigMap (only if changed)
9. **Reload**: Reloader (or similar) restarts Authelia to pick up changes

### Deep Merge Strategy

The operator performs a deep merge at the `identity_providers.oidc` level:
- Preserves all base config fields (`cors`, `lifespans`, `enforce_pkce`, etc.)
- Merges `clients` (base + CRD-managed)
- Merges `claims_policies` from ClaimsPolicy CRDs
- Merges `scopes` from ClaimsPolicy CRDs with customScope
- Merges `definitions.user_attributes` from UserAttribute CRDs
- Adds JWKS if secrets are available

## Development

### Build

```bash
make build
```

### Run Locally

```bash
make run
```

### Run Tests

```bash
make test
```

### Build Docker Image

```bash
make docker-build
make docker-push
```

## License

MIT
