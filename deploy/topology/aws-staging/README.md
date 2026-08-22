# FCP Fabric isolated AWS staging topology

This module builds the **recommended external-acceptance environment** for FCP Fabric: a separate AWS VPC, two private service instances, two-AZ encrypted PostgreSQL, customer-managed KMS keys, private Systems Manager administration, Secrets Manager metadata, CloudWatch logs and the deployment boundary for a Cloudflare named Tunnel. It is a **staging-only** module. Its resources are intentionally expensive and can have security consequences; do not apply it to an existing production VPC or reuse a production KMS key, RDS instance, Tunnel or secret.

> The module creates infrastructure but intentionally does not create secret values, enable services or run a database failover. Runtime/Tunnel secret values are supplied after apply through an approved secure operator path. This prevents plaintext database credentials, digest keys, Tunnel credential JSON and TOTP material from entering Terraform configuration, Terraform state, shell history or the repository.

## Topology

| Layer | Implemented control |
|---|---|
| Network | Dedicated VPC; two private service/database subnets; two egress subnets with one NAT gateway per availability zone. Service instances receive no public IP and no SSH ingress rule. |
| Host management | EC2 instance profile with SSM; private VPC endpoints for SSM, SSM Messages, EC2 Messages, KMS, Secrets Manager and CloudWatch Logs; an S3 gateway endpoint for immutable artifact retrieval. |
| Service | Two private IMDSv2-only EC2 instances. Their bootstrap accepts only pinned S3 object versions and keeps Fabric bound to `127.0.0.1:8080`. |
| Edge | Existing Cloudflare named Tunnel units and canonical Host configuration. The connector is outbound from the private instances; Cloudflare is the only intended public TLS/WAF boundary. |
| Database | Private PostgreSQL 16 RDS Multi-AZ instance; 35-day PITR, 100–500 GiB encrypted gp3 storage, RDS-managed master secret, IAM DB authentication, CloudWatch PostgreSQL/upgrade exports and deletion protection. |
| Keys and secrets | Separate customer-managed KMS keys for RDS storage, TOTP data-key envelopes and Secrets Manager. Runtime/Tunnel secret values are injected after apply; the service role can read only those two secrets, the RDS master secret and its exact KMS keys. |
| Evidence | Encrypted CloudWatch service log group; bounded RDS CPU, free-storage, freeable-memory and connection alarms; existing private Prometheus/Blackbox templates; and the incident/recovery runbooks. |

The two NAT gateways are deliberate: a named Cloudflare Tunnel must establish outbound connectivity to Cloudflare, including TCP/UDP port `7844` for Tunnel transport and HTTPS where required. AWS PrivateLink covers AWS management/control-plane traffic, but it cannot replace this Cloudflare egress path. Private service instances remain unreachable directly from the internet.

## Required pre-apply controls

| Requirement | Why it is required |
|---|---|
| A dedicated AWS account or isolated staging account/OU, a non-production change ticket and a Region with two chosen availability zones. | This prevents the acceptance drill from sharing resources or evidence with production. |
| A Terraform remote state backend with encryption, locking and least-privilege access. | Do not use local state for identity/security infrastructure. Backend configuration is operator-supplied and is never committed. |
| An approved immutable ARM64 Amazon Linux AMI containing AWS CLI v2, `jq` and the SSM Agent. | The module deliberately does not select a mutable latest AMI or allow boot-time unauthenticated package installation. |
| A versioned private S3 artifact bucket. | Both the Fabric archive and `cloudflared` binary are downloaded by explicit object VersionId. |
| A Cloudflare staging zone, dedicated named Tunnel and canonical hostname. | The existing `deploy/edge/cloudflare` policy applies the host allowlist and route rate limits after the topology exists. |
| A human-reviewed budget decision. | Two NAT gateways, interface endpoints, EC2, RDS Multi-AZ, KMS and CloudWatch create recurring charges. |
| A non-production SNS or incident-routing destination in `alarm_actions`. | Infrastructure alarms need a tested owner and delivery path; an empty default is suitable only before external acceptance. |

AWS documents that Systems Manager can manage private instances over interface endpoints and that Session Manager needs no inbound firewall rule; the relevant endpoints include Systems Manager, SSM Messages and EC2 Messages.[1] A PITR operation creates a separate DB instance without modifying the source DB instance, which is why the restore drill remains disposable and read-only until explicit cleanup.[2]

## Terraform preparation

Create a private working directory outside this repository and copy the example variables file. Do **not** put secret values into it.

```bash
cd deploy/topology/aws-staging
cp terraform.tfvars.example terraform.tfvars
chmod 0600 terraform.tfvars

# The backend is an operator-managed encrypted/locked state store.
terraform init -backend-config=/secure/path/fcp-fabric-staging-backend.hcl
terraform fmt -check
terraform validate
terraform plan -out=fcp-fabric-staging.plan
```

Review the plan with the security and platform owners. A future apply is a material cloud operation: verify the AWS account ID, Region, VPC CIDRs, AMI ID, S3 VersionIds, exact Cloudflare staging domain, database identifier and change ticket before any apply. Apply only after the change is approved.

```bash
terraform apply fcp-fabric-staging.plan
```

## Artifact contract

The `service_artifact_s3_uri` object must be a compressed tar archive containing these executable files at its archive root:

```text
fcp-fabric
fcp-fabric-kms
fcp-fabric-service
```

`fcp-fabric-kms` must have been compiled with `--features aws-kms`. The `cloudflared_artifact_s3_uri` object is a single reviewed ARM64 executable. Record artifact digest, S3 bucket/key/VersionId, build revision and approval in the change record. The bootstrap refuses a missing required command and does not fetch mutable `latest` URLs.

## Secret injection after apply

Terraform creates only two **empty secret metadata objects**: `runtime` and `cloudflare-tunnel`. Place values in a secure administrator directory outside the repository, then write them using a file path rather than a shell literal. Never send secret values in chat, command arguments, Terraform variables, user data or commit history.

The runtime secret is a JSON object with these required string fields. The initial active TOTP key reference is set after the one-time KMS envelope provisioning step below.

```text
FABRIC_PASSWORD_DUMMY_VERIFIER
FABRIC_LOGIN_TRANSACTION_DIGEST_KEY
FABRIC_LOGIN_BINDING_DIGEST_KEY
FABRIC_TOTP_ACTIVE_KEY_REFERENCE
FABRIC_TOTP_ISSUER
FABRIC_SESSION_DIGEST_KEY
FABRIC_STEP_UP_DIGEST_KEY
FABRIC_WEBAUTHN_CEREMONY_DIGEST_KEY
FABRIC_WEBAUTHN_BINDING_DIGEST_KEY
```

The `cloudflare-tunnel` secret must contain the credential JSON issued for the dedicated staging named Tunnel. The renderer validates that both values are JSON objects, writes root-/service-restricted files below `/etc`, and never prints their values. It derives `FCP_DATABASE_URL` locally from the AWS-managed RDS master secret and the private RDS endpoint.

## Bootstrap and first TOTP data-key envelope

After the instances pass SSM registration, use an approved SSM session or Run Command against **one** instance. First run the embedded migration command with `FCP_DATABASE_URL` constructed locally from the RDS master secret. Then provision the TOTP data-key envelope with the AWS KMS wrapping-key ARN from the Terraform output:

```bash
FCP_DATABASE_URL='read securely on the instance only' \
FABRIC_TOTP_KMS_WRAPPING_KEY_REFERENCE='arn:aws:kms:…:key/…' \
/usr/local/bin/fcp-fabric-kms provision-totp-data-key
```

The command prints an opaque reference only. Insert that value into the secure runtime-secret file as `FABRIC_TOTP_ACTIVE_KEY_REFERENCE`, upload the revised JSON secret through the approved operator path, then on each instance run the root-only renderer and enable the services:

```bash
sudo systemctl start fcp-fabric-secrets.service
sudo systemctl enable --now fcp-fabric.service fcp-fabric-cloudflared.service
```

The service unit itself forces `FABRIC_BIND=127.0.0.1:8080`; do not alter it. Verify that `curl` with the canonical Host header returns the expected loopback health result before directing public DNS traffic to the Tunnel.

## Cloudflare edge

Provision the dedicated named Tunnel and canonical staging hostname in the separate Cloudflare account/zone. Store the Tunnel credential JSON only in the Terraform-created secret. Apply the existing edge policy from [`../../edge/cloudflare/main.tf`](../../edge/cloudflare/main.tf) using the staging zone ID and `fabric_public_domain`. Enable managed WAF in observe/log mode first, inspect events, and only then turn a compatible rule into a blocking control.

A Cloudflare account/API connection is required for this operation. The current session has no enabled Cloudflare integration or token, so applying the edge policy is intentionally deferred until the operator connects an account and approves the change.

## RDS observability baseline

The module alerts on sustained CPU pressure, free storage below 15 GiB for its initial 100 GiB allocation, freeable memory below the configured safety floor and database connections above a baseline-tuned threshold. Before external acceptance, configure a non-production `alarm_actions` destination, verify delivery, and tune memory/connection thresholds from observed workload evidence rather than copying the example values unchanged. AWS recommends monitoring CPU, memory, storage and connections, establishing a workload baseline, and testing failover/reconnection behaviour.[6]

## Acceptance sequence

Do not claim production acceptance from `terraform apply` alone. Execute the following only after the public staging hostname, Cloudflare Tunnel, service, KMS provider and monitoring route are verified.

| Acceptance drill | Existing procedure |
|---|---|
| KMS active envelope and forward rotation | [`../../secrets/README.md`](../../secrets/README.md) |
| Edge canonical-host, WAF and rate-limit policy | [`../../edge/README.md`](../../edge/README.md) |
| PostgreSQL PITR recovery to disposable target | [`../../postgres/README.md`](../../postgres/README.md) and `restore_drill_aws.sh` |
| Private probes and alert delivery | [`../../observability/README.md`](../../observability/README.md) |
| Service/Tunnel/RDS controlled disruption | [`../../operations/load-and-chaos.md`](../../operations/load-and-chaos.md) |
| Evidence preservation and escalation | [`../../operations/incident-response.md`](../../operations/incident-response.md) |

No RDS failover, PITR restore, DNS change, WAF blocking change or high-rate load test is triggered by this module. These actions require a separate approved change step.

## References

[1] [AWS Systems Manager — Improve the security of EC2 instances by using VPC endpoints for Systems Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-create-vpc.html)

[2] [Amazon RDS — Restoring a DB instance to a specified time](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html)

[3] [AWS Secrets Manager — Secret encryption and decryption](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html)

[4] [Cloudflare — Deploy Tunnels with Terraform](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/deployment-guides/terraform/)

[5] [Cloudflare — Origin parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)

[6] [Amazon RDS — Best practices for Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.html)
