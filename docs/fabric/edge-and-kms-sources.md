# Edge and KMS implementation sources

This record supports the active production deployment assets. It is not a historical delivery log.

## AWS KMS envelope encryption

AWS `GenerateDataKey` returns a plaintext data key for immediate local use and a KMS-encrypted ciphertext blob for durable storage. AWS requires the identical, case-sensitive encryption context on `Decrypt` when one was set on generation. The response supports `AES_256` data keys, and AWS recommends erasing plaintext key material after local use.[1]

`Decrypt` should explicitly identify the intended KMS key where possible, and requires `kms:Decrypt`; `GenerateDataKey` requires `kms:GenerateDataKey`. Encryption context is non-secret additional authenticated data and must not carry secret material.[1][2]

KMS wrapping-key rotation does not re-encrypt existing data keys. The provider keeps previous KMS key material available to decrypt ciphertext originally protected with it, so Fabric must preserve old envelope references until all dependent factors have been retired or re-encrypted.[3]

## Cloudflare edge boundary

A managed Cloudflare Tunnel publishes a hostname to a locally reachable origin and requires a final catch-all ingress rule. The origin can remain private, while the connector establishes outbound connectivity to Cloudflare. Tunnel configuration exposes `httpHostHeader`, TLS verification controls, connection timeout and keepalive parameters; the implementation must not disable origin TLS verification.[4][5]

Cloudflare rate-limiting rules combine an expression, request characteristics, period, threshold, mitigation duration and action. They protect authentication endpoints but are not an exact origin request quota because enforcement counter updates can lag by seconds.[6] Managed WAF rulesets are plan-dependent and execute after custom and rate-limit phases, so edge policy must document rule ordering and monitor false positives.[7]

## References

[1]: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html "AWS KMS GenerateDataKey"
[2]: https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html "AWS KMS Decrypt"
[3]: https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html "AWS KMS key rotation"
[4]: https://developers.cloudflare.com/tunnel/setup/ "Cloudflare Tunnel setup"
[5]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/ "Cloudflare Tunnel origin parameters"
[6]: https://developers.cloudflare.com/waf/rate-limiting-rules/ "Cloudflare rate limiting rules"
[7]: https://developers.cloudflare.com/waf/managed-rules/ "Cloudflare Managed Rules"
