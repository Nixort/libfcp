# FCP Fabric managed edge deployment

This deployment boundary keeps `fcp-fabric-service` on `127.0.0.1:8080`. A managed Cloudflare Tunnel is the only public ingress path. Public TLS, DDoS controls, WAF and rate limiting run at Cloudflare; the connector makes an outbound connection to the private origin. The service independently enforces the canonical Host and rejects a public bind.

> Do not use Cloudflare Quick Tunnels for a release. They are explicitly a development feature. Create a named production tunnel with a scoped token and at least two connector replicas on separate failure domains.[1]

## Deployment sequence

Install the compiled Fabric binary as `/usr/local/bin/fcp-fabric-service`. Create a dedicated `fcp-fabric` Unix account, an `/etc/fcp-fabric` directory owned by that account with mode `0700`, and an environment file with mode `0600`. Install `deploy/systemd/fcp-fabric.service`; its explicit `FABRIC_BIND=127.0.0.1:8080` setting takes precedence over the environment file.

Create a named Cloudflare Tunnel in the target account. The provisioning token needs only the documented Tunnel connector and DNS permissions; do not reuse an account-wide administrator token.[1] Copy `cloudflare/config.yml.template` to `/etc/cloudflared/fcp-fabric.yml`, replace its placeholders with the tunnel identifier and canonical public domain, and restrict the credential file to the `cloudflared` account. The final `http_status:404` ingress rule is mandatory.

Apply `cloudflare/main.tf` using a dedicated Terraform state backend and an API token scoped to **Zone WAF Write**. Import any pre-existing zone entry-point rulesets before applying because Terraform assumes ownership of the configured ruleset phase.[2] Enable the provider's managed WAF ruleset in simulate/log mode, review events for valid WebAuthn and federation requests, then promote only reviewed rules to block.[3]

The rate-limit policy deliberately uses source-IP and Cloudflare colo characteristics. It reduces abusive browser traffic but does not replace in-service password timing equalization, opaque transactions or server-side session enforcement. Cloudflare documents that edge counters can lag by seconds, so the Fabric origin must remain fail-closed under bursts.[4]

## Acceptance checks

Run `scripts/test_edge_contract.sh` in the repository before deployment. In the target environment, verify that `ss -ltnp` shows Fabric only on `127.0.0.1:8080`, `systemctl is-active fcp-fabric fcp-fabric-cloudflared` returns `active`, and a request with an unexpected public Host receives an edge block or origin denial. Confirm the public endpoint serves TLS and that a burst beyond the configured threshold emits Cloudflare rate-limit events while valid test tenants still complete the login flow.

## References

[1]: https://developers.cloudflare.com/tunnel/setup/ "Cloudflare Tunnel setup"
[2]: https://developers.cloudflare.com/terraform/additional-configurations/rate-limiting-rules/ "Cloudflare Terraform rate limiting"
[3]: https://developers.cloudflare.com/waf/managed-rules/ "Cloudflare Managed Rules"
[4]: https://developers.cloudflare.com/waf/rate-limiting-rules/ "Cloudflare rate limiting rules"
