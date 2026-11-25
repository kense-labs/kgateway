# Deploy kgateway with kstack

Run kgateway, kstack and the control plane as separate services. The Compose bundle publishes the public TLS listener and binds the two operator interfaces to loopback. The Node API and MaaS listener use the private platform network.

## Prepare the configuration

From this directory, create the runtime directories and copy the templates.

```sh
mkdir -p runtime/{gateway,kstack,control}/tls
cp gateway.acl runtime/gateway/gateway.acl
cat gateway.acl services.acl > runtime/control/gateway-snapshot.acl
cp server.yaml runtime/kstack/server.yaml
cp control.json runtime/control/control.json
```

Provision certificates with these names and file locations. The private keys need to be readable by their service container. The provided images run kgateway as UID 10001, the control plane as UID 10002 and kstack as UID 10003.

| Directory | Files |
| --- | --- |
| `runtime/gateway/tls` | `edge.crt` and `edge.key` for the public hostname. `node.crt` and `node.key` for the DNS name `kgateway`. `node-client-ca.pem` trusts the control-plane client certificate. `platform-ca.pem` trusts kstack and the control plane. `maas-client.pem` contains the client certificate and private key for the MaaS listener. `service-signing.key` contains the Ed25519 signing key in PKCS#8 PEM. |
| `runtime/kstack/tls` | `maas.crt` and `maas.key` for the DNS name `kstack`. `gateway-client-ca.pem` trusts the gateway's MaaS client certificate. `gateway-1.pem` contains the Ed25519 public key. `platform-ca.pem` trusts the control plane. |
| `runtime/control/tls` | `control.crt` and `control.key` for the DNS name `control-plane` and the local operator hostname. `platform-ca.pem` trusts the gateway Node API. `node-client.crt` and `node-client.key` are the control plane's client identity for the Node API. |

Assign a unique replica UUID in the two ACL files and in `runtime/control/control.json`. Set the signer key ID and validity in that same file and configure the corresponding public key in kstack. Set `budget_window_seconds` before first startup. Set distinct node, gateway usage, MaaS usage, operator and auditor tokens with at least 32 bytes each.

The control plane allocates the next window's replica leases during the final 30 seconds of the current window. A replica can use a prepared lease from its `starts_at` time while the rest of its admission policy remains fresh. An updated budget cap applies from the first window whose allowances have yet to be allocated. During an upgrade, update all gateway replicas to the matched release before starting the control plane that publishes `starts_at`.

Each budget applies to one registered operation. Add `project` for a project budget and add both `project` and `env` for an environment budget. Each scoped budget requires its parent in the same tenant and operation. Assign each replica its exclusive request allowance. A replica with no share of a configured project or environment budget denies requests for that scope. Gateways charge all applicable budgets in one durable debit. Usage and sensitive admission records carry the tenant `lease_id` and the charged `scope_lease_ids` in project-to-environment order.

The sample Node API allowlists the control plane at `172.29.249.10`. To use a different platform subnet, set `KGATEWAY_PLATFORM_SUBNET` and `KGATEWAY_CONTROL_INTERNAL_IP`, then update `management.allowed_ips` in both runtime ACL files.

## Start the paired images

Set `KGATEWAY_IMAGE`, `KSTACK_IMAGE` and `KGATEWAY_CONTROL_IMAGE` to the chosen image references. Record the three digests together for release and rollback. The kstack Dockerfile packages a prebuilt Linux `cmd/gpuworks` executable named `kstack`, and the control-plane Dockerfile is in `../../control-plane`.

```sh
docker compose config --quiet
docker compose up -d
docker compose logs kgateway kstack control-plane
```

The sample enables `GET /v1/models` for `tenant-example`. Create an operator-authorized Key with `POST /v1/keys` using `tenant`, `project`, `env`, `org`, `ttl_seconds` and the grant `{"maas.models.list":["urn:plat:maas:models"]}`. Use the returned Key as the public request's bearer credential.

To register a model, read `maas_revision` from the authenticated kstack deployment detail `GET /api/v1/deployments/{id}`. Add the deployment ID, revision and weight under the model alias in `resource.targets`. Add the same alias to the Key's model-list grant. To offer chat, register `POST /v1/chat/completions` with operation `maas.chat.create` and assign a separate allowance and grant. Restart the control plane to load changes to the registered routes and aliases. Use the release API to change the targets or weights of an existing alias while the control plane serves requests.

Give stable and candidate deployments distinct kstack `served_name` values. The private MaaS listener selects the deployment named by the signed ID and revision. It uses the public alias for the model catalogue and for inference replies. A batch keeps the deployment revision reserved when it was created.

### Migrate existing kstack clients

The supplied `server.yaml` closes the legacy `/v1` entry on all of kstack's main listeners. Existing installations can keep `disable_legacy_gateway: false` during migration. Keep kstack's anonymous inference access disabled. Inventory the legacy API key prefixes and outstanding Files and Batches by tenant, then move one group of clients at a time.

1. Publish the tenant's model aliases and grant the matching operations to its new Kense Keys. Change the client's base URL to kgateway and verify model listing, inference, and usage settlement for that tenant.
2. Stop submitting work through the old entry. Let outstanding streams and batches finish, and download any results and files that must be retained. Legacy assets are tied to the original kstack key. New uploads and batches use the owning Kense Key.
3. Revoke the migrated keys by prefix through the kstack console or `DELETE /api/v1/apikeys/{prefix}`. Check that the pilot keys receive `401` at the old entry and that clients in later groups can still use their own keys. To return a client to the old entry during the migration, issue a replacement key with the approved deployment scope.
4. When all groups have moved, set `disable_legacy_gateway: true`, restart kstack, and retire the old `/v1` route at the reverse proxy or firewall. Verify `/v1` returns `404` on the main listeners, signed MaaS requests through kgateway still work, and kstack management and node connections are healthy.

### Publish and roll back model weights

Send these requests to the private control plane with the configured operator bearer token.

| Request | Input and result |
| --- | --- |
| `GET /v1/releases/maas` | Returns the desired release `revision`, default `targets` by route, any `tenant_targets` by route, tenant and alias, and the last confirmed snapshot identity per replica. A fresh installation starts at revision `0`. |
| `POST /v1/releases/maas` | Accepts `expected_revision`, `alias`, `targets` and an optional `tenant`. Each target has `deployment.id`, `deployment.version` and a positive `weight` from 1 to 65,535. The transaction updates all kstack MaaS routes that expose the alias and returns the new release revision. |
| `GET /v1/releases/maas?revision=0` | Reads a historical target manifest and its change record. The first publication saves the bootstrap targets as revision `0`. |
| `POST /v1/releases/maas/rollback` | Accepts `expected_revision`, `alias`, `rollback_revision` and an optional `tenant`. Restores the alias for that scope from the earlier revision and creates a new, higher revision. |

Supply `tenant` to roll out the alias only for that tenant. The gateway selects the tenant from the verified Kense Key. The override applies to discovery, online inference, and batch admission and preserves existing grants. Other tenants use their own override or the default weights. Rolling back to a revision without an override for the selected tenant and alias resumes the current default weights. Changing or rolling back the default weights preserves active tenant overrides. A route can carry overrides for up to 64 tenants.

Check candidate health and its deployment revision in kstack before publishing. Both write endpoints return `409` if `expected_revision` has changed. Read the current release again before deciding whether to retry. A rollback also returns `409` if the historical revision lacks the alias on one of its current routes. Release manifests and operator change records persist in the control-plane database. When a release exists, its targets take precedence over bootstrap weights for matching routes and aliases. New registrations use their configured targets until a release records them.

Wait until each replica's reported `release_revision` equals the desired revision. Verify its reported `revision` and `snapshot_digest` via the exact Node API readiness check below. These publication records represent the latest confirmed application, and the Node API reports live readiness.

During a paired upgrade, start the compatible kstack release before switching kgateway to the release that emits the `model_aliases` claim for discovery. The private MaaS listener also accepts earlier discovery credentials that omit the alias map. [Service-token contract](../../contracts/service-token-v1.schema.json)

Upgrade all gateway replicas to a version that understands `tenant_targets` before the first scoped rollout. Restore the default routing for all active overrides and verify replica readiness before reverting gateways to a version that predates tenant overrides. [Platform policy contract](../../contracts/platform-policy-v1.schema.json)

Use the paired CI artifact `paired-revisions.txt` to identify the tested source revisions and contract digests. Compare `docker compose config --images` with the corresponding three immutable image references in the deployment record before rollout.

From the allowlisted control-plane network, send an mTLS request with the replica's Node API token to `GET /api/gateway/snapshots/status`. Confirm the `applied` snapshot matches the intended revision and digest. Query the same endpoint with `gateway_id`, `revision` and `snapshot_digest` set to that snapshot's identity and require `ready: true` before moving traffic to the replica.

Preserve the snapshot, budget, usage and control-plane volumes across restart. After a rollback, verify readiness for the new snapshot on each replica. Keep the candidate deployment active until its admitted streams and batches finish or are cancelled.

## Export the registered API and clients

Each registration names the exact HTTP method and path, the operation and resource URNs, and its `routing.service` and `routing.entrypoints`. Its `contract` declares the protocol, metering units, quota dimensions and SLO. Add request and response media types and schemas using `request_body` and `responses`. Sensitive routes use `requires_audit_receipt` in the registration. The publisher reads bootstrap and upstream services from the snapshot ACL and inserts the registered routers.

```sh
python3 ../../control-plane/registry.py --config runtime/control/control.json --output runtime/registry
```

The export includes `openapi.json`, `client.rs`, `client.go`, `routers.acl` and a `manifest.json` with their SHA-256 digests. The operator can also retrieve the OpenAPI document at `GET /v1/registry/openapi.json` using `CONTROL_ADMIN_TOKEN`. [Sample contract](../../contracts/openapi.json) · [OpenAPI 3.1 specification](https://spec.openapis.org/oas/v3.1.0)

The Rust client uses `reqwest` 0.12. The Go client uses the Go 1.20+ standard library. Both expose request builders named by operation and preserve the response body for JSON, SSE and file content. Configure the client with the public gateway origin and a Kense credential. Each client embeds the OpenAPI digest from its export.

## Files and batches

Register the operations you want to expose under the MaaS service with audience `urn:plat:maas:kstack`. Use `resource.kind = "maas-asset"` and `{id}` for the detail path parameter. The publisher generates exact method and path rules for collection and detail operations.

| Method and path | Operation | Resource URN |
| --- | --- | --- |
| `GET /v1/files` | `maas.files.list` | `urn:plat:maas:files` |
| `POST /v1/files` | `maas.files.create` | `urn:plat:maas:files` |
| `GET /v1/files/{id}` | `maas.files.get` | `urn:plat:maas:files` |
| `GET /v1/files/{id}/content` | `maas.files.content` | `urn:plat:maas:files` |
| `DELETE /v1/files/{id}` | `maas.files.delete` | `urn:plat:maas:files` |
| `GET /v1/batches` | `maas.batches.list` | `urn:plat:maas:batches` |
| `POST /v1/batches` | `maas.batches.create` | `urn:plat:maas:batches` |
| `GET /v1/batches/{id}` | `maas.batches.get` | `urn:plat:maas:batches` |
| `POST /v1/batches/{id}/cancel` | `maas.batches.cancel` | `urn:plat:maas:batches` |

For batch creation, set `resource.batch_max_requests` to the maximum number of input lines per submission. Add the model aliases and pinned deployment revisions to `resource.targets`. Grant the Key both `urn:plat:maas:batches` and the allowed model URNs under `maas.batches.create`. Budget at least `batch_max_requests` units per submission on the receiving replica. The full cap is reserved on admission for the current budget window, including submissions rejected later during file validation. Other HTTP operations consume one request unit each.

The submitting Key owns the input file, batch, and result files within its org, tenant, project, and environment. kstack records authoritative token usage for each batch line. Once an attempt is recorded, a restart can reconcile its outcome without resubmitting the same line. A line with an uncertain outcome can appear in the error file. Keep the kstack batch data and MaaS journal on persistent storage. [MaaS usage contract](../../contracts/maas-usage-v1.schema.json)

kstack sends durable status changes and a heartbeat for an idle active batch approximately every 30 seconds. The terminal report reconciles admitted attempts and unused request units against the original reservation in the control plane. Replica quota accounting retains the reserved cap through the budget window. [Batch report contract](../../contracts/maas-batch-report-v1.schema.json)

## MCP and audit

An MCP POST route uses a `resource.kind = "rpc"` policy with `protocol = "mcp"`. Register each allowed method and each tool's URN and input schema. Separate GET and DELETE routers on the same path can use `resource.kind = "mcp-session"`. Use the same audience and stable upstream for all three routes. For stateful servers, provision a dedicated 32-byte random file as `managed.platform.mcp_session_key_file` on the participating replicas.

The separate `CONTROL_AUDITOR_TOKEN` can read a tenant's audit chain at `GET /v1/audit/{tenant}?after=0&limit=128`. Each page request records its own audit event and returns its sequence and digest.

Set `requires_audit_receipt` on sensitive routes in the control-plane registry. The gateway obtains a durable, request-bound receipt from the configured control plane before forwarding the operation.

To require a second durable copy, run `python /app/witness.py --config /path/to/witness.json` from the control-plane image on separate storage in the audit fault domain. The witness configuration supplies `bind`, `port`, `state_file`, `tls.cert`, `tls.key`, `signing_key_file`, `append_token_env`, and `audit_token_env`. Give the witness its own TLS identity, Ed25519 key and separate append and recovery credentials.

Set `audit_witness` in the main control configuration with the HTTPS `endpoint` ending in `/v1/anchors`, `token_env`, `ca_file`, and the witness's public `verification_key`. The optional `interval_seconds` controls periodic tenant-chain anchors and defaults to 60. Sensitive admission requires a verified witness signature when configured. Vault redemption then also requires the corresponding witness acknowledgement. The witness auditor can independently recover signed records at `/v1/anchors/{tenant}?after=0` and receives a signed read receipt.

### Handoff and restore the control plane

Prepare a replacement using the same release pair, replica identities, signing authorization, route policy, budgets and bootstrap ACL contents. Keep the independent audit witness running. Install `age` in the operator environment. The source needs only the recipients file, while the replacement uses the private decryption identity from separate custody. The checkpoint holds the SQLite state. Preserve runtime configuration, certificates, key material, gateway ledgers and kstack storage through their respective recovery procedures. [age](https://github.com/FiloSottile/age/releases/tag/v1.3.2) · [SQLite Backup API](https://www.sqlite.org/backup.html)

Stop the old controller and keep its process stopped. Run `handoff` with its configured witness writer credential. The command checks that the writer lock is idle, synchronizes the audit heads, publishes an encrypted archive under a fresh name, and durably fences the old state. The independent witness signs the archive, policy and audit-head digests. Store the archive on separate storage. Retrying after a lost witness response uses the same archive path and the same fenced source.

```sh
python control-plane/recovery.py handoff \
  --config /secure/primary/control.json \
  --archive /backup/control-2026-11-25.age \
  --recipients /secure/recipients.txt
```

Restore into a fresh state path with the configured writer credential and a separate witness reader credential in `RECOVERY_WITNESS_READER`. The tool verifies a fresh signed checkpoint, verifies the archive and SQLite integrity, and claims the checkpoint for one destination at the witness. The local `.restore` marker preserves the destination identity across an interrupted invocation. Retry there with the same inputs. On successful restore the marker is cleared and the normal control-plane startup can use the database.

```sh
python control-plane/recovery.py restore \
  --config /secure/replacement/control.json \
  --archive /backup/control-2026-11-25.age \
  --identity /secure/recovery.agekey \
  --witness-reader-env RECOVERY_WITNESS_READER
```

After startup, check exact snapshot readiness and revocation cursors for every replica. Confirm backlog reconciliation using event IDs and usage receipts. The paired `--release-rollout --recovery` drill exercises this fenced handoff with separate storage paths, two live gateways and an independent witness. Production RPO and regional failover still require an infrastructure-level recovery drill.

## Vault for credential-consuming services

To enable Vault on the private control plane, set `vault_operator_token_env` and `vault_consumers` in the control configuration and pass the named environment variables into the container. `vault_consumers` maps each service audience to its own bearer-token environment variable. Use `vault_provider` and `requires_audit_receipt` together on the service's registry entry. The native kstack inference listener uses its deployment identity and mTLS for local model traffic.

The Vault operator submits an externally sealed Base64 envelope to `POST /v1/api/__local/vault/materialize`. The request names `tenant`, `org`, `project`, `env`, `provider`, `audience`, `secret_ref`, `key_id`, `ciphertext`, `expires_at`, and the current `expected_aggregate_version`. Start the aggregate at zero for a new scope and provider. Submit the same scope and reference with `version` and the current aggregate to `apply` or `revoke`. Applying a newer version revokes the previous active version for that scope and provider in the same transaction.

The signed service credential contains only `secret_ref` and `version` under `vault_binding`. A consumer verifies the service credential and calls `POST /v1/api/__local/vault/redeem` on the private control plane with its consumer token, `request_id`, `secret_ref`, and `version`. The control plane verifies the audience and active binding against its admission record. The consumer receives the encrypted envelope and can unwrap it using its own KMS access. Redemption expires after four minutes and stops immediately at key revocation, credential expiry or rotation. Audit entries record references, versions and outcomes. [Service-token contract](../../contracts/service-token-v1.schema.json) · [Vault envelope contract](../../contracts/vault-envelope-v1.schema.json)

### OpenBao Transit integration

Use a named Transit key restricted to the consuming workload. Grant the sealing operator `update` on the key's `transit/encrypt` path and the workload `update` on its `transit/decrypt` path. Use a separate credential for key rotation. The gateway and control plane only need their existing Vault and service credentials. [OpenBao Transit](https://openbao.org/docs/secrets/transit/)

For a derived Transit key, the paired test binds encryption to the UTF-8 JSON object containing `tenant`, `org`, `project`, `env`, `provider`, and `secret_ref`. Sort the keys and omit whitespace, then Base64-encode that JSON as the Transit `context`. Seal the upstream credential with OpenBao and store the Base64-encoded `vault:vN:…` result as the control-plane `ciphertext`. Use `openbao/transit/keys/<name>` as the `key_id` for this profile. The consumer verifies the `key_id` against its configured key and derives the same context from the verified identity, provider, and binding before decrypting the envelope. [Transit API](https://openbao.org/docs/api/secret/transit/)

Pass `--openbao` to `tests/kstack_maas_transport.py` to exercise the pinned OpenBao image and a separate decrypt-only workload over TLS. The test uses disposable keys and storage. It covers denied KMS operations, a sealed KMS, credential rotation, and retirement of the old key version. Verify recovery and rotation against the target KMS as part of environment acceptance.

## A2A

Register each agent's JSON-RPC methods under one audience and set `resource.policy.task_public_key` to that agent's Ed25519 public key. The agent returns a signed task receipt as the task ID. It signs the receipt with `alg=EdDSA` and `typ=kgateway-a2a-task`. The gateway validates the receipt against the current tenant, project, environment, subject and agent audience before forwarding task operations with the internal task identifier. [Task receipt claims](../../contracts/a2a-task-receipt-v1.schema.json)

Enable workload delegation with a separate `delegation.signing_key_file` on the control plane and the matching `delegation_verification_key_file` in each gateway's `managed.platform` bootstrap. Map service audiences to separate workload credential variables under `delegation.client_token_env`. Register exact downstream `operation`, `action`, and `urn` grants in the source's `delegate_to` and set `accept_delegation` on destination routes. These routes require audit receipts and the originating Key's scope for the requested capability.

An agent uses its workload credential on the private `POST /v1/delegations/exchange` endpoint with the currently received `parent_request_id` and a registered `target`. The result is a bearer ticket for one invocation. The gateway consumes it across replicas and signs a separate service credential with the remaining lifetime, `on_behalf_of`, and `delegation_chain`. Later hops inherit the original lifetime limit and a smaller capability set. [Delegation ticket claims](../../contracts/a2a-delegation-v1.schema.json)

## Verify a release pair

For public repositories, run **Paired MaaS conformance** on the kgateway candidate and supply the kstack repository and its full commit SHA. For a private kstack repository, call the same reusable workflow from the private repository and supply `gateway_repository`, `gateway_revision`, `kstack_repository`, and `kstack_revision`. Pin the workflow call and both checkouts by full SHA. The Actions logs and artifacts stay in the caller's repository, and its built-in token can read its own checkout. The workflow exercises weighted rollout, rollback and recovery with `--release-rollout --recovery`, and the Vault path with `--openbao`. A successful run records both commits and the contract digests in `paired-maas-revisions`. [Paired workflow](../../.github/workflows/paired-maas.yml)
