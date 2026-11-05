# Design: docs restructure (v0.3.0, issue #244)

Date: 2026-11-05. From issue #244 (owner, 2026-11-04) and the owner's go to start it now, in parallel with the YubiKey
SDK work (2026-11-05). Decisions marked **(owner)** are the owner's, **(my call)** mine, open to change. The inventory
this is planned from (section maps, inbound links, drift) is `2026-11-05-docs-inventory.md` beside this file; its
findings that shape the design are repeated here.

## Why

The README is 1,453 lines in 58 sections: install, setup, the vault password and agent, multi-machine use, the
broker, security notes and the command reference in one file. Beside it, `MULTI_MACHINE_KEYING.md` (801 lines) and
`HARDWARE_BACKENDS.md` (936) mix design records with how-tos, and `docs/BROKER.md` (1,305) is the broker guide, its
threat model and its v0.2.0 change list in one. The same topics are explained in several files: the vault password
and agent in five, record format 3, fleet enrolment and one-key-per-slot in three each. A new user can't find the
path they need (install, guided `tswap init`, first secret), and tswap is meant to be showcase quality (owner).

## Goals

- **D1. A short README** (owner: "a few hundred lines"): what tswap is and why; install (release download, the macOS
  quarantine note, `installscript`); the guided `tswap init`; the first secret and `tswap run`; links onward.
- **D2. User guides under `docs/`**, one home per topic (owner's list, my page split):
  | Page | Takes |
  |---|---|
  | `docs/install.md` | per-OS install detail, Windows notes, prerequisites, building from source |
  | `docs/setup.md` | the guided `init` in full, per-backend setup (YubiKey keyring, several keys plugged in, TPM, Secure Enclave), **one section "Preparing a YubiKey"**, the recovery key, limits |
  | `docs/multi-machine.md` | sharing a vault, joining, remote enrolment step by step, the guide's commands, synced folders and sync transports, record format 3 and `vault reindex` (short; the format itself stays a design record) |
  | `docs/vault-password-and-agent.md` | the vault password and the agent, its socket and containers |
  | `docs/BROKER.md` | the broker user guide: setup, routes and sockets, systemd, SELinux, command templates (how-to parts), platforms, limits, costs |
  | `docs/broker-threat-model.md` | the broker's threat model: redaction, timing, identity check limits, root-equivalence, the uid assumption, TPM DA counter, memory, the password broker's trust model, the ssh agent's threat parts |
  | `docs/portable.md` | portable use: no install, no admin, `TSWAP_CONFIG_DIR`, what refuses without sudo and why, per-OS limits (Linux TPM, unsigned binaries) |
  | `docs/security-model.md` | the sudo split, threat model and non-goals, touch posture, **a posture table per backend** (absorbs the doc parts of #158; one table, a row per backend variant; each cell sourced from #158's text, the "Status" and touch sections of `HARDWARE_BACKENDS.md` or the README's setup and touch text, with its date, "not documented" where no source says, no new claims; amended 2026-11-05 after the plan reviews) and the Secure Enclave's unreviewed construction stated plainly (#159) |
  | `docs/agent-integration.md` | agent and operator roles, policy example, installing and keeping the skill current, evaluating it (links `evals/skill/README.md`) |
  | `docs/rotating-and-burning.md` | rotating a secret and the burn and rotate playbook, merged |
  | `docs/examples.md` | the agent workflow, backup script, config files, Helm patterns |
  | `docs/upgrading-from-0.1.md` | classic vaults, `migrate --to-records`, `vault reindex`, the removed `--keyring` |
  | `docs/README.md` | an index of the above, one line each |
- **D3. One command reference page, `docs/commands.md`, that can't drift (owner):** its per-command part is generated
  from `CommandRegistry.All` (`Name`, `HelpUsage`, `Description`, `RequiresSudo`) between generated markers, and a
  test fails when the committed page differs from what the code generates. That failure is intended when another
  branch changes a command's help (the YubiKey track adds `yubikey setup`): it regenerates the page in its own branch. It also lists the environment variables
  and the files tswap writes (README "Files", "Environment variables").
- **D4. Design records apart (owner):** `MULTI_MACHINE_KEYING.md`, `HARDWARE_BACKENDS.md`, `docs/ssh-agent-wire.md`
  and `REFACTORING_PLAN.md` move to `docs/design/` (`git mv`, kept whole), linked from the guides where a reader
  wants the why. Their how-to parts (for example "Checking a no-touch Secure Enclave slot on a Mac") move into the
  guides, with a one-line pointer left in the design record.
- **D5. Nothing a user or a program points at breaks (owner: "keep every existing anchor ... or redirect it"):**
  - **Root stubs (my call):** `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md` stay at the root as stubs of a
    few lines linking to `docs/design/...` and the relevant guides, because released tswap binaries print those
    bare names (InitCommand.cs:255, :612, GuidedInit.cs:327, SlotCommand.cs:429, Tpm2ToolsInterop.cs:122).
  - **`docs/BROKER.md` keeps its path** as the broker guide (the systemd unit's `Documentation=` URL, the SELinux
    policy file and installed units point at it), keeps a `SELinux` heading, and keeps a short
    `Redaction confirms whole guesses` section that links to the threat model page (the broker's short-secret log line
    and its test name that heading).
  - **README anchors (my call):** README headings that move away are kept as anchors in a compact "Moved sections"
    table at the end of the README (old heading → new page), each row carrying the old anchor as
    `<a id="old-slug"></a>`, so links from outside the repo (posts, issues, chat) still land somewhere useful.
  - All 33 internal anchor links found today are repointed to their new homes.
  - **The table's size (my call):** one row per README heading that moves (about 45), inside a collapsed
    `<details>` block at the end, so it costs the front page one line; it doesn't count toward D1's length.
  - **No other stubs (my call):** the inventory found `docs/ssh-agent-wire.md` and `REFACTORING_PLAN.md` named only
    in code comments and design docs, never by a program message, unit file or URL, so they move without stubs and
    the comments are swept.
  - **Program strings (inventory 4a):** no message names a README anchor; the five that name a file are covered by
    the root stubs and by `docs/BROKER.md` keeping its path and headings. No `src` string changes.
- **D6. A link check:** a test that every relative link and `#anchor` in the repo's Markdown (outside
  `docs/superpowers` and `docs/briefs`, outside code fences, GitHub slug rules) resolves, so the restructure can't
  leave a dead link and later edits can't either.
  Release notes are included (my call): `v0.2.0.md` is never edited, and its links still resolve because a link into
  a moved README section lands on the "Moved sections" anchor.
- **D7. Close #172** (the old Phase 6 README draft, superseded) when this merges.

## Non-goals

- New features or behaviour. No `src` change except what D3 and D6 need (tests, and a generator in the test project)
  and path sweeps in code **comments** that name moved design files (about 45; comments only).
- Rewriting the design records' content (they move whole; only how-to parts leave them).
- Documenting v0.3.0's features in advance (FIDO2 slots, `tswap yubikey setup`, SSH enrolment). Their tracks write
  those parts into this structure (below).
- `docs/briefs/` and `docs/superpowers/`: stay where they are; they are agent history, not reader docs.
- The help text's banner ("YubiKey Secret Manager") and its ykman-only Prerequisites block: fixed by the YubiKey SDK
  track, which owns `CommandRegistry.PrintHelp` (file ownership, below).
- #158's code parts (a protection column in `tswap slots`, `init --tpm` printing its limit): only the doc parts are
  absorbed; the issue stays open for the rest if any remain.

## Anti-goals

- Losing content silently: every README/design section ends somewhere (a page, a design record, release notes) or is
  dropped with a reason recorded in the plan's ledger (the only planned drop: README "Setup", lines 176-198, the
  retired classic two-key ykman flow, superseded by the guided init).
- A front page that still reads like a manual (the README over ~300 lines).
- Duplicated explanations: a topic has one home; other pages link to it, they don't retell it.
- A broken link or anchor anywhere a user, a program or an installed unit points.
- Statements made more confident than the source (posture, review status, verified-on lists are copied as stated,
  with their dates).

## Constraints

- **Parallel with the YubiKey SDK stage 1 track (owner), file ownership (my call):**
  - this track owns `README.md`, `docs/**` (except `docs/superpowers/**` and `docs/briefs/**`), the root design
    files, `AGENTS.md`'s doc pointers, `contrib/**` doc pointers, and new tests for D3 and D6;
  - the YubiKey track owns everything else in `TswapCli/`, `TswapCore/` and existing tests, including
    `CommandRegistry.cs`; this track changes code comments only by path sweep, and does not touch `CommandRegistry.cs`;
  - this track lands first (it is the shorter one). The YubiKey track then merges `main` and rewrites the one
    "Preparing a YubiKey" section in `docs/setup.md` (ykman → `tswap yubikey setup`), updates `docs/install.md`'s
    YubiKey prerequisites (no ykman; the udev rule; `libpcsclite` used if present, not needed), its parts of
    `docs/portable.md`, and regenerates `docs/commands.md` (the D3 test tells it to).
- Copy rules (owner's house style for tswap docs): plain English, short sentences, lists and tables over long
  paragraphs; commands in code blocks; no marketing words.
- The generated command reference uses only what `ICliCommand` exposes; the per-subcommand sudo split for `slot` and
  `broker` (which mix sudo and non-sudo subcommands) stays a short hand-written table outside the generated block.
- Release notes stay per version in `docs/release-notes/` (owner); `v0.2.0.md` is history and isn't edited.
- External reviews as for every tswap brief: GLM and MiMo on the plan and on the final diff (project rule).

## Left to the builder

- Exact section order inside each guide, headings, and how much each moved section is tightened (no new claims).
- The generator's location (test project) and how regeneration is triggered (an environment variable on the test run
  is my suggestion; no new tswap command).
- The link checker's slug implementation (GitHub's rules: lower-case, spaces to `-`, punctuation dropped, duplicates
  suffixed `-1`, `-2`).
- Whether `docs/examples.md` and `docs/rotating-and-burning.md` are worth separate pages or fold into others, if a page
  would be under ~40 lines.
