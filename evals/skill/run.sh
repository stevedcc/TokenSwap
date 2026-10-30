#!/usr/bin/env bash
# Repeatable eval of the tswap skill (`tswap prompt`): does an agent following it behave correctly?
#
#   evals/skill/run.sh --agent <claude|opencode|fake> --model <id> --skill <on|off>
#                      [--scenario <name>] [--agent-home <dir>]
#                      [--judge-agent <claude|opencode> --judge-model <id>]
#                      [--fake-variant <name|all>] [--tswap <binary>] [--pass-env <NAME>]... [--keep]
#
# Each scenario (scenarios/*.json) runs in a bubblewrap sandbox (Linux only): /usr read-only, a fresh
# HOME, the scenario folder as /work and /tmp the only writable paths besides the shims' state, and
# tswap, sudo, su, doas and pkexec bind-mounted over by shims (shims/shim.py) wherever they exist
# (plus cat, jq, base64, kubectl, helm and psql, which log and pass through or answer canned). The
# runner first checks, inside the sandbox, that each of those names resolves to the shim and that no
# real tswap is reachable, and aborts (exit 2) otherwise. Secret values are inert markers
# (TSWAP-EVAL-MARKER-<name>). The judge (lib/judge.py) reads the shims' log and scans the scenario
# folder and /tmp for markers in files; it never reads the agent's own report, except that `says`
# rules give the final message to an LLM judge (--judge-agent/--judge-model, a different model from
# the agent; marked as such in the output).
#
#   --agent-home  a folder holding the agent's login only, copied into the sandbox's fresh HOME, so no
#                 global CLAUDE.md or AGENTS.md leaks in and --skill off really is off.
#   --skill on    the skill text goes in through Claude Code's --append-system-prompt, or as
#                 OpenCode's AGENTS.md in the scenario folder. Off: nothing.
#   --agent fake  runs scripts generated from each scenario's own rules (lib/fake_agent.py): the
#                 "pass" variant does the must sequence; every other variant breaks one rule. Used by
#                 the unit tests (SkillEvalTests); never needs a model.
#
# What the eval cannot see (shell builtins, interpreters, the network, ...): README.md here.
#
# Output: one line per scenario (PASS, or FAIL with the first rule broken), then a summary.
# Exit: 0 all passed, 1 some failed, 2 the isolation check aborted the run.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec /usr/bin/python3 -I -B "$here/lib/runner.py" "$@"
