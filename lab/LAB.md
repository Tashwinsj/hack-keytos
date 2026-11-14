# Lab setup

This file is the human checklist. The code does not provision a tenant.

## Still required before a live demo

- [ ] Reply to Aaron Crawfis and request the EZCA demo account. Provisioning has lead time.
- [ ] Confirm the Microsoft 365 E5 developer sandbox is live, Intune is included, and the signing account is **Global Administrator**. The classic CBA trust-store read fails for Global Reader.
- [ ] Register a public client app and grant delegated consent for:
  - `Policy.Read.AuthenticationMethod`
  - `Organization.Read.All`
  - `AppCertTrustConfiguration.Read.All`
  - `DeviceManagementConfiguration.Read.All`
  - `RoleManagement.Read.Directory`
  - `Directory.Read.All`
  - For `remediate --apply` only: `Policy.ReadWrite.AuthenticationMethod`
- [ ] Enable device-code flow on that app registration.
- [ ] Clone [Semperis/EntraGoat](https://github.com/Semperis/EntraGoat/) and run Scenario 6 (CBA — Root Access Granted). Keep the cleanup script.
- [ ] Write the lab tenant id, and only that id, into `lab/lab-tenant.id` or `ESCLOUD_LAB_TENANT`. ESCloud then refuses any other tenant.
- [ ] Run one throwaway `exploit` against that tenant, confirm `GET /me` is the Global Admin, then delete the forged certificate from the keychain.

## Suggested order once the tenant exists

1. `scan --tenant ... --client-id ... --device-code --output artifacts/live-dump.json`
2. `analyze --input artifacts/live-dump.json --output artifacts/live-findings.json`
3. `exploit --i-own-this-tenant <same-id> --tenant <same-id> --target-upn <ga-upn> --ca <entra-goat-ca.pfx>`
4. `remediate --dump artifacts/live-dump.json` to print the PATCH and the offline after-state.
5. Apply the binding, mode, and CRL changes in the portal or with `--apply` after you have read them.
6. Remove the rogue CA by deleting and recreating `certificateBasedAuthConfiguration` (fixed id `29728ade-6ae4-4ee9-9103-412912537da5`). Do not send `issuer` or `issuerSki`; those are read-only. ESCloud does not send this delete.
7. `ezca check --ca ezca-root.cer --group <cba-users-group>` and add that public CA with the printed scope.
8. `scan` again. Criticals should be gone, and a forge against the EZCA file should fail because the key is not in the file.

## If Intune is not licensed

CESC-1 through CESC-4 still come from the live CBA policy and trust store. CESC-5 and CESC-6 stay on `fixtures/vulnerable-dump.json`. Say that on stage.

## If the classic trust store read is forbidden

You are not Global Administrator. CESC-1, CESC-2, and CESC-4 still come from the authentication-method policy. CESC-3 needs the trust store or the PKI-based CA configuration.
