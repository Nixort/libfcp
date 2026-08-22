# FCP Fabric secret rotation

FCP Fabric reads every runtime secret from the restricted systemd `EnvironmentFile` at `/etc/fcp-fabric/fcp-fabric.env`. It accepts neither database URLs, raw secret values nor cloud credentials as command-line arguments. The file must be owned by `root`, mode `0600` or stricter, and be readable by the `fcp-fabric` service only through systemd’s explicit `EnvironmentFile` load. Run `deploy/secrets/scripts/validate_fcp_fabric_env.sh` before every restart; it validates file permissions, all-or-nothing groups, Base64url width and distinct digest-key domains without echoing values.

| Secret / reference | Rotation effect | Safe operational sequence |
|---|---|---|
| AWS KMS wrapping CMK | KMS-managed key-material rotation preserves `Decrypt` for old ciphertext under the same KMS key ID. | Enable/verify the KMS rotation policy, retain decrypt permission for historical material, test a historic envelope in a non-production drill, and do not delete or disable the key. |
| TOTP active data-key envelope | **Forward-only** rotation: new enrollments use the new envelope; existing factors retain historic references. | Run the provisioning CLI, save only its opaque reference, set `FABRIC_TOTP_ACTIVE_KEY_REFERENCE`, validate the environment, restart one instance, verify an old and a newly enrolled factor, then roll the remaining instances. |
| Login transaction/binding digest keys | Deliberately invalidates outstanding login transactions and bindings. | Announce a short login interruption, deploy both new values atomically, restart all instances, and verify stale login cookies are denied. |
| Session digest key | Deliberately invalidates all access and refresh credentials. There is no dual-key verifier in this release. | Treat as emergency/maintenance global sign-out: deploy a new independent key, restart all instances, verify existing cookies are denied, and require re-authentication. |
| Step-up digest key | Invalidates outstanding privileged grants only. | Deploy the new key atomically and restart; repeat any affected privileged operation after fresh TOTP. |
| WebAuthn ceremony/binding digest keys | Invalidates incomplete passkey ceremonies only. Registered credentials remain intact. | Deploy both new keys atomically and restart; users restart interrupted ceremonies. |
| Password dummy verifier | Changes unknown-account timing equalization only. | Generate a valid Argon2id verifier through a trusted offline procedure, deploy atomically, restart, and run generic-denial checks. |
| Database connection material | Depends on the selected provider; use short-lived workload/IAM authentication where available. | Stage a new secret/version, validate a new connection from a canary, roll instances, revoke the old credential only after all healthy instances use the new version. |
| Cloudflare Tunnel credential | Rotating it interrupts the connector until its new credential is installed. | Create/revoke through the Cloudflare control plane, replace the local protected credential file, restart only `fcp-fabric-cloudflared`, and verify the public HTTPS probe. |

## KMS TOTP data-key rotation

Build and run the intentionally narrow provisioning binary with the AWS feature. It only accepts the literal subcommand and reads `FCP_DATABASE_URL`, `FABRIC_TOTP_KMS_WRAPPING_KEY_REFERENCE`, AWS Region and AWS credentials from the environment/workload identity. It prints one non-secret opaque key reference. It does not accept a database URL, KMS identifier, credential or plaintext key argument.

```bash
cargo +stable run -p fcp-fabric-service --features aws-kms \
  --bin fcp-fabric-kms -- provision-totp-data-key
```

The operator records that reference in the protected environment file as `FABRIC_TOTP_ACTIVE_KEY_REFERENCE`, validates the file, then rolls the service. Historic encrypted factors keep their original reference, so their KMS envelope rows and KMS decrypt permissions must remain available until every factor that uses them has been migrated or retired. A production acceptance test must cover both an old reference and the new active reference.

> A process restart does not by itself prove key rotation. The acceptance evidence is: the new envelope row contains ciphertext only; KMS can decrypt old and new envelopes with their exact contexts; existing TOTP factors authenticate; and new enrollment persists the new opaque reference.

## Digest-key rotation boundary

The current opaque-token storage schema has a single digest per record and carries no verifier-key version. Therefore replacing a digest key intentionally invalidates credentials or ceremonies in the table above. This is fail-closed and avoids an unsafe heuristic verifier fallback, but it is **not zero-downtime key rotation**. Schedule normal rotation in a maintenance window; reserve immediate replacement for compromise response. Do not reuse a value across login, session, step-up, passkey or recovery-code domains.

## Required evidence

For each rotation, retain a redacted change record containing the secret-manager version identifier, deployment time window, instance rollout identifiers, probe results, identity-flow verification result, rollback decision and approving operator. Do not store plaintext secrets, token values, provisioning URIs, AWS credentials, session cookies or database URLs in the record.
