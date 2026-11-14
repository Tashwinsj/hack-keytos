# Three-minute demo

0:00 — Entra CBA is a login method where the certificate is the credential. Get the binding and the trust store wrong and that certificate is a skeleton key. This is the surface Keytos lives on.

0:25 — Run ESCloud read-only on the lab dump. It names CESC-1 (low-affinity PrincipalName binding), CESC-2 (single-factor default), and CESC-3 (unscoped non-public CA), then one combined finding: full tenant takeover. It lists the Global Administrator by UPN. Open the attack-path graph: forged certificate, rogue CA, binding, Global Admin.

1:10 — Lab only. Pass `--i-own-this-tenant` with this tenant's id. ESCloud forges a leaf whose SAN PrincipalName is that Global Admin, signed by the CA already in the trust store, and posts it to the certauth endpoint.

1:50 — `GET /me` returns that Global Admin. No password. No MFA prompt.

2:20 — The report shows the PATCH and the Graph PowerShell. The offline re-scan, or a live re-scan after the fix, drops criticals to zero. Say explicitly that removing a classic trusted CA is delete-and-recreate, not a PATCH.

2:45 — Swap the rogue CA for a scoped EZCA CA. `ezca check` on the exported public certificate fails the forge: the signing key is HSM-held and was never in the file. The attack CA and the remediation CA are different on purpose.

If the network fails, stay on `fixtures/vulnerable-dump.json`, the report, and a recording. Do not point the exploit at any tenant other than the lab.
