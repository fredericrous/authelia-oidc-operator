# Authelia OIDC Operator

A Kubernetes operator that manages OIDC client configurations for Authelia. It watches `OIDCClient` custom resources and automatically assembles the Authelia configuration.

## Features

- **Declarative OIDC Client Management**: Define OIDC clients as Kubernetes resources
- **Automatic Configuration Assembly**: Aggregates all OIDCClient resources into Authelia's configuration
- **Secret Management**: Supports both referenced secrets and auto-generated secrets
- **Instant Updates**: Reacts immediately to changes (no polling delays)
- **Secure**: Hashes client secrets using PBKDF2-SHA512

## Installation

### Prerequisites

- Kubernetes cluster 1.28+
- Authelia deployed in the cluster
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

### Basic OIDCClient with Generated Secret

```yaml
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: myapp
  namespace: myapp
spec:
  clientId: myapp
  clientName: My Application
  redirectUris:
    - https://myapp.example.com/callback
  generateSecret: true
```

### OIDCClient with External Secret Reference

```yaml
apiVersion: security.homelab.io/v1alpha1
kind: OIDCClient
metadata:
  name: vault
  namespace: vault
spec:
  clientId: vault
  clientName: HashiCorp Vault
  secretRef:
    name: vault-oidc-client-secret
    namespace: vault
    key: client_secret
  redirectUris:
    - https://vault.example.com/oidc/callback
  tokenEndpointAuthMethod: client_secret_basic
```

## Configuration

The operator accepts the following flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--authelia-namespace` | `authelia` | Namespace where Authelia is deployed |
| `--authelia-configmap` | `authelia-config` | Name of the Authelia ConfigMap |
| `--authelia-configmap-base` | `authelia-config-base` | Name of the base Authelia ConfigMap |
| `--oidc-secrets` | `authelia-oidc-secrets` | Name of the OIDC secrets (for JWKS) |
| `--metrics-bind-address` | `:8080` | Metrics endpoint address |
| `--health-probe-bind-address` | `:8081` | Health probe address |
| `--leader-elect` | `false` | Enable leader election |

## How It Works

1. **Watch**: The operator watches all `OIDCClient` resources cluster-wide
2. **Collect**: When any OIDCClient changes, it collects all OIDCClients
3. **Resolve Secrets**: For each client, it either:
   - Fetches the referenced secret (if `secretRef` is specified)
   - Generates a new random secret (if `generateSecret: true`)
4. **Assemble**: Builds the complete OIDC configuration with hashed secrets
5. **Update**: Merges the OIDC config into the Authelia ConfigMap
6. **Reload**: Reloader (or similar) restarts Authelia to pick up changes

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
