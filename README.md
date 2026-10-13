# aznet

Cross-platform (Linux / macOS / Windows) Rust CLI for Azure network chores.

## `get-next-subnet`

Finds the next free, correctly aligned subnet of a given size in a VNet — across every
subscription your identity can see — and advises on what *is* left when the size
you asked for doesn't fit.

```bash
az login                     # or azd auth login, or a service principal / OIDC (see Authentication)
aznet get-next-subnet --vnet vnet-hub --resource-group rg-network --prefix 27
aznet get-next-subnet -n vnet-hub -g rg-network -p 28 -s "sub-prod" -s "sub-dev"
aznet get-next-subnet -n vnet-hub -g rg-network -p 27 -o json | jq '.results[].next_available'
```

### How it works

1. Resolves a credential (below) and acquires an ARM token up front, so missing auth fails before any API work.
2. Lists subscriptions in the token's tenant (`--tenant` to switch).
3. **One** Azure Resource Graph query locates the VNet by name + RG in all of them (chunked at 1000 subs).
4. Each match is re-read from ARM (Resource Graph lags ARM; allocation decisions need fresh data).
5. First-fit, alignment-aware allocation across the VNet's IPv4 address spaces, in declared order.

When nothing fits, it reports the largest free block and all free blocks ≥ /29 (Azure's minimum).

## Authentication

No Azure CLI required. `--auth` (env `AZNET_AUTH`) picks the source; the default `auto` selects
deterministically:

| Condition | Credential |
|-----------|------------|
| `AZURE_CLIENT_SECRET` set | Service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` required, else hard error) |
| `AZURE_FEDERATED_TOKEN_FILE` set | Workload identity: AKS, GitHub Actions / ADO OIDC |
| otherwise | Azure CLI login, then Azure Developer CLI (`azd`) login |

Managed identity is never auto-selected (probing IMDS stalls on laptops, and on a VM it would
silently pick the machine's identity over yours): use `--auth managed-identity`
[`--managed-identity-client-id <id>`] for user-assigned.

A half-configured service principal fails loudly rather than falling back to whoever is logged
into `az`. Token acquisition times out after 25 s with a network/proxy hint. `HTTPS_PROXY` and the
OS certificate store are honoured.

GitHub Actions (OIDC, no secrets):

```yaml
permissions: { id-token: write }
steps:
  - uses: azure/login@v2
    with: { client-id: ..., tenant-id: ..., subscription-id: ... }
  - run: aznet get-next-subnet -n vnet-hub -g rg-network -p 27 -o json
```

(`azure/login` leaves an az CLI session, which `auto` picks up.)

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | Every matched VNet has a free block of the requested size |
| 1 | Error (auth, API, bad input) |
| 2 | At least one VNet is exhausted or could not be read |
| 3 | No VNet matched |

### Limitations

- IPv4 only; IPv6 prefixes are ignored.
- Read-only: there's no reservation, so two concurrent callers can be told the same CIDR.
- Client-certificate service principals aren't supported yet (needs OpenSSL in the SDK).
- Git Bash users: pass `-p 27`, not `-p /27` (MSYS path rewriting).

## Build

```bash
cargo build --release   # binary at target/release/aznet
cargo test
```

CI follows gitflow (`feature/*`/`bugfix/*` → `develop` → `release/*`/`hotfix/*` → `main`). Every push
builds packages for Linux (x64 + arm64, `.tar.gz` + `.deb`), macOS (x64 + arm64, `.tar.gz`) and
Windows (x64, `.zip`) as workflow artifacts. Merging a version bump into `main` (or pushing a `v*`
tag that matches `Cargo.toml`) publishes a GitHub Release with those packages and `SHA256SUMS`.
