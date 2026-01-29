# Authelia OIDC Operator

A Kubernetes operator that manages OIDC client configurations for Authelia. It watches `OIDCClient` custom resources and automatically assembles the Authelia configuration.

## Features

- **Declarative OIDC Client Management**: Define OIDC clients as Kubernetes resources
- **Automatic Configuration Assembly**: Aggregates all OIDCClient resources into Authelia's configuration
- **ExternalSecrets Integration**: Works seamlessly with ExternalSecrets/Vault for secret management
- **Instant Updates**: Reacts immediately to changes (no polling delays)
- **Secure**: Hashes client secrets using PBKDF2-SHA512 with deterministic salts

## Installation

### Prerequisites

- Kubernetes cluster 1.28+
- Authelia deployed in the cluster
- ExternalSecrets operator (recommended for secret management)
- The OIDCClient CRD installed

### Install the CRD

```bash
kubectl apply -f config/crd/bases/security.homelab.io_oidcclients.yaml
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

1. **Watch**: The operator watches all `OIDCClient` resources cluster-wide
2. **Collect**: When any OIDCClient changes, it collects all OIDCClients
3. **Resolve Secrets**: For each confidential client, fetches the secret from `secretRef`
4. **Hash**: Hashes secrets using PBKDF2-SHA512 with a deterministic salt derived from the clientId
5. **Assemble**: Builds the complete OIDC configuration
6. **Update**: Merges the OIDC config into the Authelia ConfigMap (only if changed)
7. **Reload**: Reloader (or similar) restarts Authelia to pick up changes

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
