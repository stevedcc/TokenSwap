#!/bin/bash
# Runs inside the eval sandbox before the agent (evals/skill/run.sh): every name an agent could use
# to reach real secrets or privileges must resolve to the eval shim, and no real tswap binary may be
# reachable. Prints one line per problem and exits 1 if there is any; prints "isolation ok" otherwise.
#
# EVAL_HOST_TSWAP_PATHS: colon-separated paths where the host has a real tswap (checked too).
set -u

problems=0
problem() { echo "isolation: $*"; problems=$((problems + 1)); }
is_shim() { [ -f "$1" ] && grep -q "TSWAP-EVAL-SHIM" "$1" 2>/dev/null; }

dirs=(/usr/bin /usr/local/bin "$HOME/.local/bin" /bin /sbin /usr/sbin)
for name in tswap sudo su doas pkexec; do
    resolved=$(command -v "$name") || { problem "'$name' does not resolve to anything (expected the shim)"; continue; }
    is_shim "$resolved" || problem "'$name' resolves to $resolved, which is not the eval shim"
    for dir in "${dirs[@]}"; do
        if [ -e "$dir/$name" ] && ! is_shim "$dir/$name"; then
            problem "$dir/$name exists and is not the eval shim"
        fi
    done
done

IFS=: read -r -a path_dirs <<< "$PATH"
for dir in "${path_dirs[@]}"; do
    for candidate in "$dir"/tswap*; do
        [ -e "$candidate" ] || continue
        is_shim "$candidate" || problem "$candidate is on PATH and is not the eval shim"
    done
done

IFS=: read -r -a host_paths <<< "${EVAL_HOST_TSWAP_PATHS:-}"
for candidate in "${host_paths[@]}"; do
    [ -n "$candidate" ] || continue
    if [ -e "$candidate" ] && ! is_shim "$candidate"; then
        problem "the host's tswap ($candidate) is reachable in the sandbox"
    fi
done

if [ "$problems" -gt 0 ]; then
    exit 1
fi
echo "isolation ok"
