# FCP Fabric PostgreSQL HA, backup and restore

`aws-rds/main.tf` provisions a private **Multi-AZ** PostgreSQL instance with an encrypted KMS-backed volume, a 35-day point-in-time recovery window, deletion protection, private subnets, and a security group that accepts port 5432 only from the Fabric application security group. It exports PostgreSQL and upgrade logs to CloudWatch. The Terraform state backend must itself be encrypted, access-controlled and isolated from application runtime identities.

The RDS encryption KMS key must be distinct from the TOTP data-key wrapping key. The database KMS key encrypts storage and snapshots; the TOTP KMS key wraps application-level AES-256 data keys. Do not allow an application workload role to administer either KMS key or alter RDS backup/deletion settings.

> Automated backups are useful only when restoration is periodically proved. Perform a documented point-in-time restore drill at least quarterly and after material schema or backup-policy changes; a successful backup job alone is not evidence of recoverability.

## Apply and operating boundaries

Supply Terraform variables through a protected CI workspace or encrypted variable store; never commit `master_password`, KMS key ARNs, remote-state credentials or production endpoints. Apply only after a separate plan review. The application should receive a scoped runtime database role, not the RDS master user.

`deploy/postgres/scripts/restore_drill_aws.sh` is intentionally guarded. It requires an explicit time, a missing disposable target whose name contains `drill` or `restore-test`, a private DB subnet group and a security group. It never deletes an instance automatically. After the AWS wait completes, the operator must use an independently issued read-only database credential to verify the Fabric schema migration version, tenant/account count, audit-event continuity and a representative read-only application query. Delete the drill instance only after the recovery record has been retained.

## Local contract validation

`../../scripts/test_postgres_deploy_contract.sh` checks the version-controlled privacy, encryption, retention, deletion-protection and drill-guard constraints. It is not a substitute for an AWS restore drill.

## References

[1]: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html "Amazon RDS Multi-AZ deployments"
[2]: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html "Amazon RDS point-in-time restore"
[3]: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html "Amazon RDS encryption"
