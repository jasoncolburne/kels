#!/usr/bin/env bash
# Walks all .terminology-forbidden files in the tree. Each file's patterns
# apply to its own subtree. Deeper files replace shallower ones — when a
# file is covered by multiple forbid files, only the closest one applies.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Collect forbid files, deepest-first.
deep_first=()
while IFS= read -r f; do
    deep_first+=("$f")
done < <(
    git ls-files \
        | grep -E '(^|/)\.terminology-forbidden$' \
        | awk -F/ '{print NF, $0}' \
        | sort -rn \
        | cut -d' ' -f2-
)

if [ ${#deep_first[@]} -eq 0 ]; then
    exit 0
fi

# All tracked files we'll potentially scan.
all_files=()
while IFS= read -r f; do
    all_files+=("$f")
done < <(git ls-files \
    ':!:Makefile' \
    ':!:.terminology-forbidden' \
    ':!:**/.terminology-forbidden' \
    ':!:scripts/lint-terminology.sh')

# Track which files have been claimed by a deeper forbid file.
claimed_marker=$(mktemp)
trap 'rm -f "$claimed_marker"' EXIT

is_claimed() {
    grep -qxF "$1" "$claimed_marker" 2>/dev/null
}

mark_claimed() {
    printf '%s\n' "$1" >> "$claimed_marker"
}

exit_code=0

for forbid in "${deep_first[@]}"; do
    dir=$(dirname "$forbid")
    if [ "$dir" = "." ]; then
        prefix=""
    else
        prefix="$dir/"
    fi

    scope=()
    for f in "${all_files[@]}"; do
        if [ -n "$prefix" ]; then
            case "$f" in
                "$prefix"*) ;;
                *) continue ;;
            esac
        fi
        if is_claimed "$f"; then
            continue
        fi
        scope+=("$f")
        mark_claimed "$f"
    done

    if [ ${#scope[@]} -eq 0 ]; then
        continue
    fi

    pattern_file=$(mktemp)
    grep -vE '^(#|$)' "$forbid" > "$pattern_file" || true

    if [ -s "$pattern_file" ]; then
        if printf '%s\n' "${scope[@]}" | xargs grep -nE -f "$pattern_file"; then
            echo "ERROR: forbidden terminology found (rules: $forbid)"
            exit_code=1
        fi
    fi

    rm -f "$pattern_file"
done

exit $exit_code
