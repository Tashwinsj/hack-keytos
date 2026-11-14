# ESCloud

Certipy, but for the cloud. ESCloud is a read-only scanner for Microsoft Entra certificate-based authentication and Intune certificate profiles. It classifies misconfigurations as **CESC-1** through **CESC-6**, shows which administrators a weak binding can impersonate, and — only in a tenant you declare — forges a certificate and runs the certauth login so you can prove it. Then it prints the Graph fix and re-scans.

Built for the Keytos "Secure the future" hackathon. The stack is C# / .NET 8.

## Ethics and scope

- The scanner is read-only. `scan` and `analyze` do not modify the tenant.
- `exploit` refuses to run unless you pass `--i-own-this-tenant` with the same tenant id you are contacting. If `ESCLOUD_LAB_TENANT` or `lab/lab-tenant.id` is set, that pin must match too.
- `remediate --apply` is the same gate, and it only PATCHes the CBA authentication-method policy. It does not delete the classic trust store. That store is delete-and-recreate; the command prints the steps instead of sending them.
- `ezca` never signs a certificate. It checks that an exported EZCA CA is a public certificate with no private key.
- Run this against a lab you control. Clean up an EntraGoat scenario with the cleanup script that ships with that lab.

## What a finding means

| ID | Severity | What is wrong |
|---|---|---|
| CESC-1 | Critical | `PrincipalName` or `RFC822Name` maps to a UPN, and a high-affinity `certificateUserIds` binding is not evaluated first |
| CESC-2 | Critical | CBA default mode is single-factor, and no per-issuer rule forces MFA |
| CESC-3 | Critical | A trusted CA has no `certificateAuthorityScopes` entry that limits it to a specific group. A non-public issuer is the higher-risk case |
| CESC-4 | High | CRL validation is disabled, or a CA is exempted |
| CESC-5 | High | An Intune SCEP/PKCS subject or SAN uses `{{DeviceName}}`, `{{FullyQualifiedDomainName}}`, `{{SerialNumber}}`, or `{{IMEI}}` without SID strong mapping |
| CESC-TAKEOVER | Critical | CESC-1, CESC-2, and CESC-3 together: a forged CBA certificate can sign in as a Global Administrator |

## Layout

`dump.json` and `findings.json` are the API. Schemas live in `ESCloud.Contracts`. The analyzer is a pure function of the dump.

| Project | Role |
|---|---|
| `ESCloud.Contracts` | Frozen models and JSON schemas |
| `ESCloud.Collector` | Graph read, plus `--input` for an offline dump |
| `ESCloud.Analyzer` | CESC-1..6, blast radius, combined chain |
| `ESCloud.Exploit` | Lab-gated leaf forge and certauth login |
| `ESCloud.Remediation` | PATCH bodies, PowerShell, offline re-scan |
| `ESCloud.Ezca` | Isolated "forge fails against EZCA" check |
| `ESCloud.Report` | Blazor Server report and attack-path graph |
| `ESCloud.Cli` | `scan`, `analyze`, `report`, `exploit`, `remediate`, `ezca`, `all` |

## Build

.NET 8 SDK. If `dotnet` is not on your PATH:

```bash
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$DOTNET_ROOT:$PATH"
```

```bash
cd keytos-project
dotnet test ESCloud.sln
```

## Offline demo (no tenant)

```bash
dotnet run --project src/ESCloud.Cli -- all \
  --input fixtures/vulnerable-dump.json \
  --output-dir artifacts/rehearsal

dotnet run --project src/ESCloud.Cli -- report \
  --input artifacts/rehearsal/findings.json \
  --after artifacts/rehearsal/fixed-findings.json
```

The vulnerable fixture trips every rule and the takeover chain. The clean fixture trips none. `all` writes a remediated dump and a second findings file with zero criticals. Nothing is sent to Graph.

`tools/rehearse.sh` runs the tests and that offline pipeline.

## Live lab

See `lab/LAB.md`. The signing account for the classic trust-store read has to be a Global Administrator. Global Reader is not enough for `GET /organization/{id}/certificateBasedAuthConfiguration`.

```bash
dotnet run --project src/ESCloud.Cli -- scan \
  --tenant <lab-tenant-id> \
  --client-id <app-id> \
  --device-code \
  --output artifacts/live-dump.json

dotnet run --project src/ESCloud.Cli -- analyze \
  --input artifacts/live-dump.json \
  --output artifacts/live-findings.json
```

The exploit, only after you own the tenant and hold the lab CA key:

```bash
dotnet run --project src/ESCloud.Cli -- exploit \
  --i-own-this-tenant <lab-tenant-id> \
  --tenant <lab-tenant-id> \
  --target-upn ga@lab.onmicrosoft.com \
  --ca ./lab-ca.pfx \
  --ca-password <password>
```

If certauth is flaky on stage, re-run with `--browser-fallback`. The forged PFX is still written (password `escloud-lab`) so you can pick it in the browser.

EZCA, after you export the public CA certificate:

```bash
dotnet run --project src/ESCloud.Cli -- ezca check --ca ./ezca-root.cer --group <group-object-id>
```

## Out of scope

RADIUS and EZRADIUS are future work. They are not in this build.
