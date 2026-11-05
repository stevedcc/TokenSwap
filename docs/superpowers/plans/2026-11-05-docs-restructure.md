# Docs restructure (v0.3.0, #244) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A short README front page, one guide per topic under `docs/`, a generated command reference that can't drift, design records under `docs/design/`, and tests that keep every link and old anchor working.

**Architecture:** Two guard tests come first (links and old anchors; the command reference), so every later move is checked as it happens. Then the design records move, then the guides are written from the existing text, then the README is cut down last, when every section it loses already has a home.

**Tech Stack:** Markdown (GitHub rendering), C# xUnit tests in `TswapTests` (net10.0).

**Spec:** `docs/superpowers/specs/2026-11-05-docs-restructure-design.md` (approved by the owner 2026-11-05). Inventory (section maps with line ranges, inbound links, drift, duplication): `docs/superpowers/specs/2026-11-05-docs-inventory.md`.

## Global Constraints

- Owner: "Communication is important." The guides are what people read about tswap: plain English, short sentences, lists and tables over long paragraphs, commands in code blocks, no marketing words. Each page opens with one or two sentences saying who it is for and what it covers.
- **No new claims.** Posture, review status and "verified on" statements are copied as their source states them, with their dates; a guide may shorten a statement but not strengthen it. Where two sources disagree, the code wins: check the command's `HelpUsage` or the message text, and record the disagreement in the task report.
- **One home per topic.** A topic is explained once; other pages link to it in one sentence.
- **Nothing lost silently.** Every section of `README.md`, `docs/BROKER.md` and the how-to parts of the two design files ends up in a page, a design record or the release notes. The only planned drop is README "Setup" (lines 176-198, the retired classic two-key ykman flow). Any other drop needs a `Ruling:` line in the ledger with the reason.
- **No `src` change** except the new tests (and their helpers) and path sweeps in code **comments**. `TswapCli/CommandRegistry.cs` is not touched (the YubiKey SDK track owns it). No string a program prints changes.
- Paths kept: `docs/BROKER.md` (the broker guide), root `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md` (short stubs), `docs/release-notes/v0.2.0.md` (never edited).
- `docs/superpowers/**` and `docs/briefs/**` are not edited and are outside the link check.
- `ykman` instructions: they stay where they are needed today (YubiKey preparation) but are gathered into the one section "Preparing a YubiKey" in `docs/setup.md`; no other page repeats them. The YubiKey SDK track rewrites that section later.
- README length: 300 lines at most, not counting the collapsed "Moved sections" block.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no session links. One commit per task.

## Review Focus

1. **A reader following a guide top to bottom with a fresh machine:** the commands work in the order shown and match `HelpUsage` (no removed flags such as `--keyring`, no classic-vault steps outside the upgrading page). Pinned by each guide task's "walk-through check" step.
2. **Old links from outside the repo** (posts, issues, chat) to README anchors land on something useful. Pinned by Task 1's `OldReadmeAnchorsStillResolve`.
3. **A statement that got stronger in the move** (for example "verified" for something verified on one machine, or the Secure Enclave construction sounding reviewed). Pinned by the reviewers' check of each task's source-to-target table (Tasks 3-6 report it).
4. **The broker threat model split away from the guide** leaves a reader who sets up a broker without the two warnings they must see (the vault user is root-equivalent for its secrets; no container may run as the vault user's uid). Pinned by Task 4's step requiring both in the guide's setup section as one-line warnings that link to the threat model.
5. **The generated command reference** goes stale when a command changes. Pinned by Task 2's `CommandReferenceIsCurrent`.

---

### Task 1: Link check and old-anchor guard

**Model: Sonnet.**

**Files:**
- Create: `TswapTests/Docs/MarkdownLinks.cs` (helpers: repo root, GitHub slugs, links, anchors), `TswapTests/Docs/DocLinkTests.cs`, `TswapTests/Docs/old-readme-anchors.txt` (the 58 README heading slugs of today, one per line, generated once from the current README with the same slug helper; checked in)

**Interfaces:**
- Produces: `internal static class MarkdownLinks` with `string RepoRoot()` (walk up from `AppContext.BaseDirectory` to the folder holding `TokenSwap.slnx`), `IReadOnlyList<string> Anchors(string markdown)` (heading slugs by GitHub's rules: lower-case; spaces to `-`; drop everything but letters, digits, `-` and `_`; duplicates get `-1`, `-2`; headings inside fenced code blocks ignored; plus every `<a id="...">` / `<a name="...">`), and `IReadOnlyList<(int Line, string Target)> Links(string markdown)` (inline `[text](target)` links outside code fences and inline code). Task 2 and the guide tasks rely on these tests.

- [ ] **Step 1: Write the failing tests:**
  - `Slug_FollowsGitHubRules`: `"Threat Model & Non-Goals"` → `threat-model--non-goals`; `"Setting up: the guided \`tswap init\`"` → `setting-up-the-guided-tswap-init`; `"Install (compiled binary — recommended)"` → `install-compiled-binary--recommended`; two `## Setup` headings → `setup`, `setup-1`; a `# comment` line inside a fenced block is not a heading.
  - `EveryRelativeLinkResolves`: for every `.md` file under the repo root except `docs/superpowers/`, `docs/briefs/`, `bin/`, `obj/` and `.git/`: every link that isn't `http(s):`/`mailto:` points at an existing file (relative to the linking file), and its `#anchor`, if any, is in that file's `Anchors`; a bare `#anchor` is in the linking file. The failure message lists `file:line → target` for every broken one.
  - `OldReadmeAnchorsStillResolve`: every slug in `old-readme-anchors.txt` is in `Anchors(README.md)`.
  - `GuardFilesExist`: `MULTI_MACHINE_KEYING.md`, `HARDWARE_BACKENDS.md` and `docs/BROKER.md` exist; `docs/BROKER.md` has the anchors `selinux` and `redaction-confirms-whole-guesses` (the broker's log line names that heading).
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~DocLinkTests"` → FAIL only because the helpers don't exist (compile error), then, with the helpers, `Slug_FollowsGitHubRules` passes and the three guard tests **pass on today's tree** (the inventory found no dead link). Break-it-once: change one README link target to a missing anchor, see `EveryRelativeLinkResolves` fail naming it, revert.
- [ ] **Step 3: Commit.**

### Task 2: Generated command reference

**Model: Sonnet.**

**Files:**
- Create: `TswapTests/Docs/CommandReference.cs` (the generator), `TswapTests/Docs/CommandReferenceTests.cs`, `docs/commands.md`

**Interfaces:**
- Consumes: `MarkdownLinks.RepoRoot()` (Task 1); `CommandRegistry.All` (`Name`, `HelpUsage`, `Description`, `RequiresSudo`).
- Produces: `docs/commands.md` with hand-written parts and one generated block between `<!-- BEGIN GENERATED: commands (TswapTests/Docs/CommandReference.cs) -->` and `<!-- END GENERATED: commands -->`. `internal static string CommandReference.Generate()` returns the block's content: one `### <name>` heading per command in registry order, then a fenced block with `[sudo ]tswap <HelpUsage>`, then the `Description` line. Every command heading's anchor is its name (`#init`, `#slot`, ...).

- [ ] **Step 1: Write the failing tests:**
  - `CommandReferenceIsCurrent`: the text between the markers equals `Generate()` exactly (line endings normalised). With `TSWAP_REGENERATE_DOCS=1` set, the test writes the new block into the file instead and passes; the failure message says to run `TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent` and commit the result.
  - `CommandReferenceCoversEveryCommand`: for each command in `CommandRegistry.All`, `docs/commands.md` has the anchor equal to its `Name`.
  - `EnvironmentVariablesDocumented`: `TSWAP_CONFIG_DIR`, `TSWAP_YUBIKEY_SERIAL`, `TSWAP_AGENT_SOCK` appear in `docs/commands.md`; none of `TSWAP_TEST_KEY`, `TSWAP_TEST_TERMINAL`, `TSWAP_TEST_SUDO_BYPASS`, `TSWAP_TEST_BROKER_RUN_DIR` does.
- [ ] **Step 2:** run → FAIL (no file).
- [ ] **Step 3:** write `docs/commands.md`: a short intro (one paragraph: what's here, that the per-command block is generated); "Which commands need sudo" (the hand-written split for `slot` and `broker` subcommands from README "Commands" and AGENTS.md line 65; others follow `[sudo]` in the generated block); the generated block; "Environment variables" (README lines 1417-1436); "Files" (README lines 1374-1416). Generate the block with the env var.
- [ ] **Step 4:** tests → PASS; break-it-once: change one command's `Description` in the generated block by hand, see `CommandReferenceIsCurrent` fail, revert.
- [ ] **Step 5: Commit.**

### Task 3: Design records to `docs/design/`, stubs, comment sweep

**Model: Sonnet.**

**Files:**
- `git mv`: `MULTI_MACHINE_KEYING.md` → `docs/design/multi-machine-keying.md`, `HARDWARE_BACKENDS.md` → `docs/design/hardware-backends.md`, `docs/ssh-agent-wire.md` → `docs/design/ssh-agent-wire.md`, `REFACTORING_PLAN.md` → `docs/design/refactoring-plan.md`
- Create: root `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md` stubs (each: one heading with the old title, two sentences — "This design record moved to docs/design/... . For setting tswap up, see docs/setup.md and docs/multi-machine.md." — and the links; no other content), `docs/design/README.md` (one line per record)
- Modify: links to the moved files in every `.md` outside `docs/superpowers`/`docs/briefs`; `AGENTS.md` (lines 185, 211 and any other path), `runtests.sh` comments (lines 12, 14), code **comments** naming the moved files (inventory section 4, "Code comments citing design docs"; `grep -rn 'MULTI_MACHINE_KEYING\|HARDWARE_BACKENDS\|ssh-agent-wire\|REFACTORING_PLAN' TswapCli TswapCore TswapTests --include=*.cs --include=*.swift`), but **not** string literals a program prints (inventory 4a: `InitCommand.cs:255`, `:612`, `GuidedInit.cs:327`, `SlotCommand.cs:429`, `Tpm2ToolsInterop.cs:122` stay as they are; the stubs answer them).

- [ ] **Step 1:** the moves, stubs and sweep. Inside the moved files, fix relative links that now point one folder off.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS; `grep -rn` of the old names over `TswapCli TswapCore` shows only the five printed strings and no comment; `dotnet build` → 0 warnings (comments only changed); the stubs are under 10 lines each.
- [ ] **Step 3: Commit.**

### Task 4: The broker: guide and threat model

**Model: Opus.**

**Files:**
- Modify: `docs/BROKER.md` (becomes the guide)
- Create: `docs/broker-threat-model.md`
- Source map: inventory section 3, `docs/BROKER.md` table.

Content (spec D2): the guide keeps the opening (lines 1-30, shortened), Costs, Setup 1-8, the how-to parts of "A broker with a vault password" and "SSH: an agent that signs" (its Setup), Command templates (defining, examples, binds, output, logging), Platforms, Limits; "Changed in v0.2.0 (breaking)" becomes one line linking to `docs/release-notes/v0.2.0.md`. The threat model page takes "Threat model" (all of it), the trust model of the password broker and its control socket, memory and dumpability, the ssh agent's "How a signature is allowed" / "What the restriction does and doesn't do" / "What a compromised container can and can't do", and the template's "What a compromised container can do" / "What a template author must not do". The guide's Setup section carries, as one-line warnings linking to the threat model: the vault user is root-equivalent for its secrets; no container may run with the vault user's uid (Review Focus 4). The guide keeps a `SELinux` section (setup steps; the reasoning moves) and a two-line `Redaction confirms whole guesses` section that links to the threat model's full text. The two `Setup` headings become distinct (`Setting up the broker` and `Setting up the SSH agent`; the old anchors `#setup` and `#setup-1` are kept with `<a id>`).

- [ ] **Step 1:** write both pages from the existing text.
- [ ] **Step 2: Source-to-target table in the report:** every heading of the old `docs/BROKER.md` → its new page and heading (or "release notes", or a ruling).
- [ ] **Step 3: Walk-through check:** read the guide's Setup as a new user: every command in it matches `tswap broker` `HelpUsage` and the README/AGENTS sudo split; list any mismatch found and how it was resolved (code wins).
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs|FullyQualifiedName~BrokerContrib|FullyQualifiedName~BrokerShortSecretWarning"` → PASS.
- [ ] **Step 5: Commit.**

### Task 5: Setup, install, multi-machine, vault password, portable

**Model: Opus.**

**Files:**
- Create: `docs/install.md`, `docs/setup.md`, `docs/multi-machine.md`, `docs/vault-password-and-agent.md`, `docs/portable.md`
- Modify: `docs/design/multi-machine-keying.md`, `docs/design/hardware-backends.md` (only: their how-to parts are replaced by a one-line pointer to the guide that now holds them)
- Source map: inventory section 2 (README rows with destination install/setup/multi-machine/vault-password) and section 3 (the user-guidance parts of the two design files: "Checking a no-touch Secure Enclave slot on a Mac", "Under sudo: used as the vault folder's owner", "Several keys plugged in", fleet enrolment steps, the vault password how-to).

Content (spec D2 table): `setup.md` has the guided `init` in full (README 199-242), per-backend setup (243-364 without the security disclosures, which go to `security-model.md` in Task 6: leave a one-line link), **one** section `Preparing a YubiKey` holding the ykman slot-2 instructions (today's text from README 247 and 822; nowhere else), the recovery key, limits. `multi-machine.md` holds sharing, joining, remote enrolment step by step, sync transports, and a short record-format-3 / `vault reindex` paragraph linking to the design record. `vault-password-and-agent.md` holds README 434-609 and is the one home for that topic (the other four copies become links). `install.md` holds the per-OS detail, Windows notes, prerequisites and building from source. `portable.md` holds what exists today: `TSWAP_CONFIG_DIR`, running from any folder, what refuses without sudo and why, the Linux TPM limit (needs `tss` and `tpm2-tools`), unsigned binaries (Gatekeeper quarantine, SmartScreen) — no YubiKey SDK content (that track adds it).

- [ ] **Step 1:** write the five pages.
- [ ] **Step 2: Source-to-target table** in the report (each README/design section used → page and heading).
- [ ] **Step 3: Walk-through check:** follow `install.md` then `setup.md` as a new user on Linux with a YubiKey, and on macOS with the Secure Enclave: every command matches its `HelpUsage` (no `--keyring`, no classic-vault steps); list mismatches and resolutions.
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS.
- [ ] **Step 5: Commit.**

### Task 6: Security model, agent integration, rotating, examples, upgrading

**Model: Opus.**

**Files:**
- Create: `docs/security-model.md`, `docs/agent-integration.md`, `docs/rotating-and-burning.md`, `docs/examples.md`, `docs/upgrading-from-0.1.md`
- Source map: inventory section 2 (README rows with these destinations); #158 and #159 (read with `gh issue view 158 -R stevedcc/TokenSwap` and `159`); `docs/design/hardware-backends.md` "Status" sections (PoC-grade, Linux TPM, Windows TPM).

Content: `security-model.md` holds the sudo split (README 30-72), threat model and non-goals (871-903), touch posture (817-870), the password's protection limits (from 544-589, the part about what it protects; the how-to stays in `vault-password-and-agent.md`), the integrity/rollback notes (735-756), and **a posture table per backend** (YubiKey OTP slot with/without touch, Linux TPM, Windows TPM, Secure Enclave with/without touch, recovery key): columns "what unlocks it", "presence needed", "PIN/password", "reviewed/verified" — every cell sourced from #158's text or a Status section, with its date; the Secure Enclave row says plainly that its ECIES construction is hand-rolled and has had no independent review (#159), with the link to the design record. `agent-integration.md` holds README 904-1028 and links `evals/skill/README.md` instead of repeating it. `rotating-and-burning.md` merges README 620-659 and 1029-1108; the "Quick reference" (1109-1134) becomes a link to `docs/commands.md`. `examples.md` holds 1185-1313. `upgrading-from-0.1.md` holds 73-97 and 797-816, and the `--keyring` removal (from 313, 813, 1139), linking `docs/release-notes/v0.2.0.md` for the full notes.
If a page would be under ~40 lines, fold it into its nearest neighbour and say so (spec: left to the builder).

- [ ] **Step 1:** write the pages.
- [ ] **Step 2: Source-to-target table** in the report; for the posture table, one line per cell naming its source.
- [ ] **Step 3: Walk-through check:** the commands in `rotating-and-burning.md` and `upgrading-from-0.1.md` match `HelpUsage` (`migrate --to-records`, `vault reindex`, `vault merge` with its real options).
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS.
- [ ] **Step 5: Commit.**

### Task 7: The README front page, the index, and the moved-sections table

**Model: Opus.**

**Files:**
- Modify: `README.md`
- Create: `docs/README.md` (the index: one line per guide, grouped "Getting started", "Using tswap", "Security", "Reference", "Design records")

Content (spec D1): what tswap is and why (the current pitch, lines 1-27, kept tight; no links to design docs here); install (release download, the macOS quarantine note, `installscript`; per-OS detail is a link to `docs/install.md`); the guided `tswap init` (short: what it asks, one example run, link to `docs/setup.md`); the first secret and `tswap run` (about 10 lines from "Example: AI Agent Workflow"); "Where to go next" (the index's groups, one line each); License. At the end, inside `<details><summary>Moved sections</summary>`, a table with one row per README heading that moved: old heading, `<a id="old-slug"></a>` in the row, and a link to its new page and heading. Every slug in `TswapTests/Docs/old-readme-anchors.txt` resolves (Task 1's guard), and the README is at most 300 lines outside the `<details>` block.

- [ ] **Step 1:** write the README and the index.
- [ ] **Step 2: Coverage check in the report:** every row of the inventory's README section map → where it went (page, design record, release notes, or the planned drop of "Setup" 176-198); nothing unaccounted for. Then `grep -n` each of the README's old H2 titles across `docs/*.md` to show it lives somewhere.
- [ ] **Step 3:** `wc -l` of the README outside the `<details>` block ≤ 300; `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS; the whole suite `./runtests.sh` → PASS.
- [ ] **Step 4: Commit.**

### Final

The final review (GLM and MiMo, external, as for every tswap brief) reads the whole branch for: lost content (the reports' source-to-target tables), strengthened claims, duplicated explanations, broken reading order, and clarity — would a new user find install → guided init → first secret in five minutes, and would an experienced one find the broker threat model in one click. After merge, close #172 and comment on #158 and #159 with what this covered.
