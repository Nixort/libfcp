# Security policy

## Supported release line

Security fixes are developed against the current `main` release-candidate line.
`v1.0.0-rc.1` is an integration and independent-review candidate, not a promise
of stable API or wire compatibility.

## Report privately

Do not report suspected vulnerabilities in a public GitHub issue. Send a concise
private report to **nixort@proton.me** with affected package/version,
reproduction steps or a minimal proof of concept, impact assessment and any
proposed mitigation. Include encrypted contact details if the report contains
sensitive material.

The most relevant reports include signature-validation bypass, parser
allocation/panic behavior, replay or state confusion, configuration authority
confusion, CFR payload mutation, endpoint binding confusion, queue-loss behavior
or concrete adapter behavior that permits unauthenticated SDP/ICE application.

## Scope boundary

FCP does not operate a hosted signaling service, TURN deployment, KMS/HSM,
identity provider or public federation directory. Report vulnerabilities in FCP
package code and supplied workflows here. Report product-specific deployment
configuration and third-party infrastructure issues to the operator that owns
them.
