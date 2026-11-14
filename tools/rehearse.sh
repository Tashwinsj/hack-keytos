#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1

cd "$ROOT"
dotnet test ESCloud.sln --nologo
dotnet run --project src/ESCloud.Cli -- all \
  --input fixtures/vulnerable-dump.json \
  --output-dir artifacts/rehearsal

echo
echo "Offline rehearsal is in artifacts/rehearsal."
echo "Criticals on the vulnerable dump should be 4. After remediation they should be 0."
echo
echo "Open the report:"
echo "  dotnet run --project src/ESCloud.Cli -- report --input artifacts/rehearsal/findings.json --after artifacts/rehearsal/fixed-findings.json"
echo
echo "Narration is in lab/DEMO.md. A live tenant still has to be stood up from lab/LAB.md."
