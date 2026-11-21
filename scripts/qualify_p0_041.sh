#!/usr/bin/env bash
# Exact shared local/Actions lane. All generated evidence stays outside Tools.
set -euo pipefail
if [[ $# != 5 ]]; then
  echo "usage: $0 CANONICAL OVAL RI SOURCE NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
canonical=$(realpath "$1")
oval=$(realpath "$2")
ri=$(realpath "$3")
source_root=$(realpath "$4")
output=$(realpath -m "$5")
tools_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$tools_root"
[[ ! -e "$output" ]] || { echo 'output exists' >&2; exit 2; }
case "$output/" in "$tools_root/"*) echo 'output must be outside Tools' >&2; exit 2;; esac
[[ $(git -C "$ri" rev-parse HEAD) == 4b8335b924a9aa163b8a09e9592335def59a276d ]] || { echo 'RI must be the reviewed merged main commit' >&2; exit 2; }
mkdir -p "$output"
export SCAP_NG_SCHEMA_ROOT="$canonical/schema" SCAP_NG_OVAL_ROOT="$oval"
for iteration in one two; do
  python scripts/generate_v04_semantic_pack.py --schema-root "$canonical" --oval-root "$oval" \
    --ri-root "$ri" --output "$output/semantic-$iteration.json" --pin-output "$output/pins-$iteration.json"
  cmp "$output/semantic-$iteration.json" src/scap_ng_tools/converter/_v04_semantic/contracts-0.4.1.json
  cmp "$output/pins-$iteration.json" canonical-schema-pin.json
done
python -m unittest discover -s tests -v 2>&1 | tee "$output/converter-tests.txt"
python scripts/qualify_windows_relation_witness.py --source-root "$source_root" \
  --schema-root "$canonical/schema" --output "$output/windows-relations.json" | tee "$output/windows-relations.txt"
# The existing RI lane builds once and independently compares complete Definitions.
"$ri/tools/run_p0_validation.sh" "$canonical" "$tools_root" "$source_root" "$output/ri" 2>&1 | tee "$output/ri-lane.txt"
