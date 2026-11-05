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
- **Old anchors everywhere, not only the README (owner: "keep every existing anchor ... or redirect it"):** a heading that leaves `README.md` or `docs/BROKER.md` keeps its old slug as an `<a id>` in that file's "Moved sections" block; the two root stubs carry every old heading slug of the file they replace in the same kind of block, each linking to the same heading in `docs/design/...`. In-repo links never point at a redirect anchor (Task 1's guard).
- **Links only to what exists.** Every task ends with the link guard green, so a page links only to files that exist when its task commits. The task that creates a page adds the links to it that earlier pages need; each such edit is in that task's Files list. Execution order: 1, 2, 3, 4, 6, 5, 5b, 7.
- **Reports are files:** each task's report (with its source-to-target table) is the SDD report file in the plan workspace; the final reviewers get those files.
- **Reviews:** each task gets the SDD task review (a Claude reviewer, a check against the brief); the review that counts for merge is the external one at the end (GLM and MiMo, project rule).
- Pre-existing dead links found by Task 1's guard: fixed in Task 1 with a `Ruling:` line each (not excluded).
- `docs/briefs/**` and `docs/superpowers/**` links into moved README sections land on redirect anchors or rot; accepted (they are history).
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
- Create: `TswapTests/Docs/MarkdownLinks.cs` (helpers: repo root, GitHub slugs, links, anchors), `TswapTests/Docs/DocLinkTests.cs`, and three anchor lists, one slug per line, checked in: `old-readme-anchors.txt` (every README heading slug of today), `old-broker-anchors.txt` (`docs/BROKER.md`), `old-design-anchors.txt` (both design files, prefixed with the file name: `MULTI_MACHINE_KEYING.md#scope-v0--v1--v2`). They are **not** generated by the slug helper: take them from GitHub's own renderer, `gh api -H "Accept: application/vnd.github.html" repos/stevedcc/TokenSwap/contents/<path>`, extracting the `id="user-content-<slug>"` of each heading and of each explicit `<a id>`/`<a name>` only (not other elements' ids) (today's `main`; the inventory's README section map is a second check); Task 1 asserts that today's `Anchors()` of each file equals its list exactly, so the helper and the independent list agree before anything moves.

**Interfaces:**
- Produces: `internal static class MarkdownLinks` with `string RepoRoot()` (walk up from `AppContext.BaseDirectory` to the folder holding `TokenSwap.slnx`), `IReadOnlyList<string> Anchors(string markdown)` (heading slugs by GitHub's rules: lower-case; spaces to `-`; drop everything but letters, digits, `-` and `_`; duplicates get `-1`, `-2`; ATX headings only (the repo uses no setext headings; a test asserts that), trailing `#`s dropped; headings inside ` ``` ` and `~~~` fences, indented code blocks and HTML comments ignored; plus every `<a id="...">` / `<a name="...">`, with a flag for those inside a "Moved sections" `<details>` block), and `IReadOnlyList<(int Line, string Target)> Links(string markdown)` (inline links, image links and reference-style links with their definitions, outside code and comments). Task 2 and the guide tasks rely on these tests.

- [ ] **Step 1: Write the failing tests:**
  - `Links_IgnoreInlineCode`: a backticked `` `docs/x.md#y` `` and a `](x)` inside a code span are not links.
  - `Slug_FollowsGitHubRules`: `"Threat Model & Non-Goals"` → `threat-model--non-goals`; `"Setting up: the guided \`tswap init\`"` → `setting-up-the-guided-tswap-init`; `"Install (compiled binary — recommended)"` → `install-compiled-binary--recommended`; two `## Setup` headings → `setup`, `setup-1`; a `# comment` line inside a fenced block is not a heading.
  - `Anchors_EqualIndependentLists`: today (Task 1 only; later tasks change the files) `Anchors(README.md)` equals `old-readme-anchors.txt`, `Anchors(docs/BROKER.md)` equals `old-broker-anchors.txt`, and the two design files equal their prefixed entries. Later tasks delete the equality half of this test in Task 3 (design files), Task 4 (BROKER) and Task 7 (README) and keep the subset guards below; each deletion is named in that task's commit message.
  - `EveryRelativeLinkResolves`: for every `.md` file under the repo root except `docs/superpowers/`, `docs/briefs/`, `bin/`, `obj/` and `.git/`: every link that isn't `http(s):`/`mailto:` points at an existing file or directory (relative to the linking file), compared **case-sensitively** against the directory listing (so `docs/broker.md` fails on macOS too), and its `#anchor`, if any, is in that file's `Anchors`; a bare `#anchor` is in the linking file. The failure message lists `file:line → target` for every broken one.
  - `OldReadmeAnchorsStillResolve`: every slug in `old-readme-anchors.txt` is in `Anchors(README.md)`; the same for `old-broker-anchors.txt` in `docs/BROKER.md`, and for `old-design-anchors.txt` in the root stub files.
  - `NoInRepoLinkToRedirectAnchor`: no link in the repo's Markdown targets an anchor that exists only as a redirect inside a "Moved sections" block, except links in `docs/release-notes/` files of released versions (never edited; landing on a redirect is what redirects are for).
  - `NoDuplicateIds`: in each file, an explicit `<a id>` never equals a heading slug or another explicit id (the helper does not apply `-1`/`-2` to explicit ids, as GitHub doesn't).
  - `GuardFilesExist`: `MULTI_MACHINE_KEYING.md`, `HARDWARE_BACKENDS.md` and `docs/BROKER.md` exist; `docs/BROKER.md` has the heading anchors `selinux` and `redaction-confirms-whole-guesses` (the broker's log line names that heading), and the anchors `setup` and `setup-1`.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~DocLinkTests"` → FAIL only because the helpers don't exist (compile error), then, with the helpers, `Slug_FollowsGitHubRules` passes and the three guard tests **pass on today's tree** (the inventory found no dead link). Break-it-once: change one README link target to a missing anchor, see `EveryRelativeLinkResolves` fail naming it, revert.
- [ ] **Step 3: Commit.**

### Task 2: Generated command reference

**Model: Opus** (the page has reader-facing prose and the sudo split, the most security-relevant guidance in the docs).

**Files:**
- Create: `TswapTests/Docs/CommandReference.cs` (the generator), `TswapTests/Docs/CommandReferenceTests.cs`, `docs/commands.md`

**Interfaces:**
- Consumes: `MarkdownLinks.RepoRoot()` (Task 1); `CommandRegistry.All` (`Name`, `HelpUsage`, `Description`, `RequiresSudo`).
- Produces: `docs/commands.md` with hand-written parts and one generated block between `<!-- BEGIN GENERATED: commands (TswapTests/Docs/CommandReference.cs) -->` and `<!-- END GENERATED: commands -->`. `internal static string CommandReference.Generate()` returns the block's content: one `### <name>` heading per command in registry order, then a fenced block with `[sudo ]tswap <HelpUsage>`, then the `Description` line. Every command heading's anchor is its name (`#init`, `#slot`, ...).

- [ ] **Step 1: Write the failing tests:**
  - `CommandReferenceIsCurrent`: the text between the markers equals `Generate()` exactly (line endings normalised). With `TSWAP_REGENERATE_DOCS=1` set, the test writes the new block into the file instead and passes; the failure message says to run `TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent` and commit the result.
  - `CommandReferenceCoversEveryCommand`: for each command in `CommandRegistry.All`, `Anchors(docs/commands.md)` contains `Slug(Name)` exactly once.
  - `EnvironmentVariablesDocumented`: every `TSWAP_*` or `XDG_*` name the code reads (string literals passed to `GetEnvironmentVariable` or to the `getEnv` seam in `TswapCli/` and `TswapCore/` `.cs`; a name found only in a comment doesn't count) is in `docs/commands.md`, except the test-only ones (`TSWAP_TEST_*`); every `TSWAP_*`/`XDG_*` name in `docs/commands.md` is read by the code. (The regeneration instruction, `TSWAP_REGENERATE_DOCS`, lives only in the test's failure message, not in the page.)
  - `SudoTableCoversSubcommands`: every subcommand token in `SlotCommand`'s and `BrokerCommand`'s `HelpUsage` (the words after `slot`/`broker` up to the first option or `|`) has a row in the "Which commands need sudo" table, and every row names a token that exists.
  - `NoTestOnlyVariablesInDocs`: no `TSWAP_TEST_` appears in any `.md` under `docs/` (outside `docs/superpowers`, `docs/briefs`, `docs/design`) or in `README.md`.
  - `Regenerate_RoundTrip`: on a temp copy of the file, `CommandReference.Rewrite(path)` (the writer the env var uses) on a file whose block was altered restores it byte for byte, writes LF line endings (the test's failure message says so, for Windows checkouts with CRLF), writes through a temp file and rename; a file with a missing or duplicated marker fails with a message naming the marker.
- [ ] **Step 2:** run → FAIL (no file).
- [ ] **Step 3:** write `docs/commands.md`: a short intro (one paragraph: what's here, that the per-command block is generated); "Which commands need sudo" (the hand-written split for `slot` and `broker` subcommands, derived from the code: each subcommand's `RequireSudo`/sudo refusal in `SlotCommand.cs` and `BrokerCommand.cs`, then checked against README "Commands" and AGENTS.md line 65; a disagreement is reported and the code wins; others follow `[sudo]` in the generated block); this table is the one home of the sudo split by subcommand, and `docs/security-model.md` links to it for that detail; the generated block; "Environment variables" (README lines 1417-1436); "Files" (README lines 1374-1416; the intro says the generated block and the environment variables are checked against the code and the Files list is not). Generate the block with the env var.
- [ ] **Step 4:** tests → PASS; break-it-once: change one command's `Description` in the generated block by hand, see `CommandReferenceIsCurrent` fail; then run the regenerate command and check `git diff docs/commands.md` is empty.
- [ ] **Step 4b: Walk-through check:** for every row of the sudo table, the subcommand really refuses without sudo / works without it (read the code path; list each with file:line in the report).
- [ ] **Step 5: Commit.**

### Task 3: Design records to `docs/design/`, stubs, comment sweep

**Model: Sonnet.**

**Files:**
- `git mv`: `MULTI_MACHINE_KEYING.md` → `docs/design/multi-machine-keying.md`, `HARDWARE_BACKENDS.md` → `docs/design/hardware-backends.md`, `docs/ssh-agent-wire.md` → `docs/design/ssh-agent-wire.md`, `REFACTORING_PLAN.md` → `docs/design/refactoring-plan.md`
- Create: root `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md` stubs (each: one heading with the old title, one sentence — "This design record moved to docs/design/... ." — and its link (Tasks 5 and 5b add the guide links), and a collapsed "Moved sections" block with every old heading slug of that file as an `<a id>` row linking to the same heading in the moved file), `docs/design/README.md` (one line per record)
- Modify: links to the moved files in every `.md` outside `docs/superpowers`/`docs/briefs`; `AGENTS.md` (lines 185, 211 and any other path), `runtests.sh` comments (lines 12, 14), code **comments** naming the moved files (inventory section 4, "Code comments citing design docs"; `grep -rn 'MULTI_MACHINE_KEYING\|HARDWARE_BACKENDS\|ssh-agent-wire\|REFACTORING_PLAN' TswapCli TswapCore TswapTests --include=*.cs --include=*.swift`), but **not** string literals a program prints (inventory 4a: `InitCommand.cs:255`, `:612`, `GuidedInit.cs:327`, `SlotCommand.cs:429`, `Tpm2ToolsInterop.cs:122` stay as they are; the stubs answer them).

- Ownership note: `runtests.sh` comments and `TswapTests` comments are touched here by the design's comment-sweep carve-out; this track lands before the YubiKey track, which merges `main` afterwards.
- [ ] **Step 1:** the moves, stubs and sweep; delete the design-file half of `Anchors_EqualIndependentLists` (they moved; the stub guard takes over). Inside the moved files, fix relative links that now point one folder off.
- [ ] **Step 2:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS; `grep -rn` of the old names over `TswapCli TswapCore TswapTests` shows only the five printed strings and no comment; `dotnet build` → 0 warnings (comments only changed); the stubs are under 10 lines each outside their `<details>` block.
- [ ] **Step 3: Commit.**

### Task 4: The broker: guide and threat model

**Model: Opus.**

**Files:**
- Modify: `docs/BROKER.md` (becomes the guide)
- Create: `docs/broker-threat-model.md`
- Source map: inventory section 3, `docs/BROKER.md` table.

Content (spec D2): the guide keeps the opening (lines 1-30, shortened), Costs, Setup 1-8, the how-to parts of "A broker with a vault password" and "SSH: an agent that signs" (its Setup), Command templates (defining, examples, binds, output, logging), Platforms, Limits; "Changed in v0.2.0 (breaking)" becomes one line linking to `docs/release-notes/v0.2.0.md`. The threat model page takes "Threat model" (all of it), the trust model of the password broker and its control socket, memory and dumpability, the ssh agent's "How a signature is allowed" / "What the restriction does and doesn't do" / "What a compromised container can and can't do", and the template's "What a compromised container can do" / "What a template author must not do". Every heading that moves out of `docs/BROKER.md` keeps its old slug in a "Moved sections" block at the end of the guide. The guide's "Defining a template" carries a one-line pointer to "What a template author must not do". The guide's Setup section carries, as one-line warnings linking to the threat model: the vault user is root-equivalent for its secrets; no container may run with the vault user's uid (Review Focus 4). The guide keeps a `SELinux` section (setup steps; the reasoning moves) and a two-line `Redaction confirms whole guesses` section that links to the threat model's full text. The two `Setup` headings become distinct (`Setting up the broker` and `Setting up the SSH agent`; the old anchors `#setup` and `#setup-1` are kept with `<a id>`).

- [ ] **Step 1:** write both pages from the existing text; delete the BROKER half of `Anchors_EqualIndependentLists` (named in the commit message).
- [ ] **Step 2: Source-to-target table in the report:** every heading of the old `docs/BROKER.md` → its new page and heading (or "release notes", or a ruling); and, as in Tasks 5/5b/6, every sentence that states a status, a limit, an assumption or a guarantee (root-equivalence, the uid assumption, the identity check's limits, redaction, the TPM counter, memory) quoted source-beside-target.
- [ ] **Step 3: Walk-through check:** read the guide's Setup as a new user: every command in it matches `tswap broker` `HelpUsage` and the README/AGENTS sudo split; list any mismatch found and how it was resolved (code wins).
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs|FullyQualifiedName~BrokerContrib|FullyQualifiedName~BrokerShortSecretWarning"` → PASS.
- [ ] **Step 5: Commit.**

### Task 6: Security model, agent integration, rotating, examples, upgrading

**Runs after Task 4 and before Task 5** (it is placed here in the file for that reason): Tasks 5 and 5b link to `docs/security-model.md`, and this task's pages link only to pages that already exist (`docs/commands.md`, the design records, the release notes, `evals/skill/README.md`). Its link from `security-model.md` to `docs/vault-password-and-agent.md` is added by Task 5b.

**Model: Opus.**

**Files:**
- Create: `docs/security-model.md`, `docs/agent-integration.md`, `docs/rotating-and-burning.md`, `docs/examples.md`, `docs/upgrading-from-0.1.md`
- Source map: inventory section 2 (README rows with these destinations); #158 and #159 (read with `gh issue view 158 -R stevedcc/TokenSwap` and `159`; quote the parts used in the report); `docs/design/hardware-backends.md` "Status" sections (PoC-grade 273-294, Linux TPM 528-548, Windows TPM 672-682) and "Touch or no touch" 295-340; README 302-364 (TPM and Secure Enclave setup, incl. the no-PIN text and the review disclosure 343-346), 403-420 (recovery key), 544-589, 817-870.

Content: `security-model.md` holds the sudo split (README 30-72), threat model and non-goals (871-903), touch posture (817-870), the password's protection limits (from 544-589, the part about what it protects; the how-to stays in `vault-password-and-agent.md`), the integrity/rollback notes (735-756), and **a posture table per backend** (YubiKey OTP slot with/without touch, Linux TPM, Windows TPM, Secure Enclave with/without touch, recovery key): columns "what unlocks it", "presence needed", "PIN/password", "reviewed/verified" — every cell sourced from one of the sources listed above, with its date; a cell no source states says "not documented" (never a guess), and the report lists those cells. (Ruling, recorded in the ledger at plan start: the cell sources are wider than the design's "#158 and the Status sections" — README setup and touch sections and the design's "Touch or no touch" also count — because per-cell provenance and "not documented" keep the no-new-claims rule; "a posture table per backend" is read as one table with a row per backend variant.) the Secure Enclave row says plainly that its ECIES construction is hand-rolled and has had no independent review (#159), with the link to the design record. Every status sentence copied keeps its qualifiers ("one physical TPM (Intel PTT), single vendor", open re-checks, dates). `agent-integration.md` holds README 904-1028 and links `evals/skill/README.md` instead of repeating it. `rotating-and-burning.md` merges README 620-659 and 1029-1108; the "Quick reference" (1109-1134) becomes a link to `docs/commands.md`. `examples.md` holds 1185-1313. `upgrading-from-0.1.md` holds 73-97 and 797-816, and the `--keyring` removal (from 313, 813, 1139), linking `docs/release-notes/v0.2.0.md` for the full notes.
If a page would be under ~40 lines, fold it into its nearest neighbour and say so (spec: left to the builder).

- [ ] **Step 1:** write the pages.
- [ ] **Step 2: Source-to-target table** in the report; for the posture table, one line per cell naming its source.
- [ ] **Step 3: Walk-through check:** the commands in `rotating-and-burning.md` and `upgrading-from-0.1.md` match `HelpUsage` (`migrate --to-records`, `vault reindex`, `vault merge` with its real options).
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS.
- [ ] **Step 5: Commit.**

### Task 5: Install, setup, portable

**Model: Opus.**

**Files:**
- Create: `docs/install.md`, `docs/setup.md`, `docs/portable.md`
- Modify: root `HARDWARE_BACKENDS.md` and `MULTI_MACHINE_KEYING.md` stubs (add "For setting tswap up, see docs/setup.md.")
- Modify: `docs/design/hardware-backends.md` (only these sections' bodies become a one-line pointer to the guide that now holds them, the heading itself staying, since the stubs' redirect rows link to it: "Checking a no-touch Secure Enclave slot on a Mac" 341-407, "Under sudo: used as the vault folder's owner, not root" 247-272, "Several keys plugged in, and the touch posture" 153-174; every other section stays byte-identical, including "Touch or no touch: an explicit choice", which Task 6 needs)
- Source map: inventory section 2, README rows with destination install or setup (100-175, 199-433), and the three design sections above.

Content: `install.md` holds the per-OS detail, Windows notes, prerequisites, building from source, and a subsection named exactly **"YubiKey prerequisites"** (today: ykman and its install; the YubiKey track rewrites this subsection). `setup.md` has the guided `init` in full (README 199-242; its flag list is **not** repeated: link to `docs/commands.md#init`), per-backend setup (243-364 without the security disclosures, which go to `security-model.md` in Task 6: leave a one-line link), **one** section named exactly **"Preparing a YubiKey"** holding the ykman slot-2 instructions (today's text from README 247 and 822; nowhere else), the recovery key (403-420), limits (421-433). `portable.md` is short and owns only "using tswap without installing it": running from any folder; pointing at a vault with `TSWAP_CONFIG_DIR` (how-to; the variable's reference entry is `docs/commands.md`) from README 1417-1436; what refuses without sudo, as one paragraph that links to `docs/security-model.md` for why (the sudo split's home); the Linux TPM limit (from `docs/design/hardware-backends.md` "Linux TPM" 499-527: needs the `tss` group and `tpm2-tools`); unsigned binaries as one paragraph linking to `install.md` (README 110-117 and 171-175 are owned there). No YubiKey SDK content (that track adds a section named exactly **"YubiKeys"**; leave a one-line placeholder saying YubiKey notes arrive with v0.3.0's YubiKey work).

- [ ] **Step 1:** write the three pages.
- [ ] **Step 2: Source-to-target table** in the report: each source line range → page and heading; for every sentence in a source that states a status, a limit, a review state or a date, the target sentence quoted beside the source sentence.
- [ ] **Step 3: Walk-through check:** follow `install.md` then `setup.md` as a new user on Linux with a YubiKey, and on macOS with the Secure Enclave: every command matches its `HelpUsage` (no `--keyring`, no classic-vault steps); list mismatches and resolutions.
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS.
- [ ] **Step 5: Commit.**

### Task 5b: Multi-machine, the vault password and the agent

**Model: Opus.**

**Files:**
- Create: `docs/multi-machine.md`, `docs/vault-password-and-agent.md`
- Modify: root `MULTI_MACHINE_KEYING.md` stub (add the `docs/multi-machine.md` link); `docs/security-model.md` (its one-sentence link to the how-to page); `docs/BROKER.md` (its kept password how-to is cut to the broker-specific steps, and the general setup becomes a link to `docs/vault-password-and-agent.md`)
- Modify: `docs/design/multi-machine-keying.md` (only these bodies, headings kept: "Hand-carried enrollment (v0)" 350-384, "Fleet enrollment" 385-466 and the how-to part of "The vault password" 575-680 become one-line pointers; the rest byte-identical)
- Source map: inventory section 2 (README 365-402, 434-609, 660-796, 1314-1373), section 3 (the design parts above), and the duplication list in section 6.

Content: `multi-machine.md` holds sharing, joining, remote enrolment step by step, the guide's commands, sync transports, and a short record-format-3 / `vault reindex` paragraph linking to the design record. `vault-password-and-agent.md` holds README 434-543 and 590-609 and is the one home for setting up and using the password and the agent; README 544-589 ("What the password does and doesn't protect") and the integrity/rollback notes (README 735-756) are in `docs/security-model.md` (Task 6); this page and `multi-machine.md` link to them in one sentence each. The other copies (design records, `docs/BROKER.md` 357-493, release notes) are not edited except the design-record pointers above; `docs/BROKER.md` gets its link in this task (Files above).

- [ ] **Step 1:** write the two pages.
- [ ] **Step 2: Source-to-target table** in the report, with the quoted status/limit sentences as in Task 5.
- [ ] **Step 3: Walk-through check:** join a second machine following `multi-machine.md` (`slot request`, approve, accept, merge as `HelpUsage` names them); set a password and start the agent following `vault-password-and-agent.md`; list mismatches and resolutions.
- [ ] **Step 4:** `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS.
- [ ] **Step 5: Commit.**

### Task 7: The README front page, the index, and the moved-sections table

**Model: Opus.**

**Files:**
- Modify: `README.md`
- Modify (comments and agent docs that point at README sections, now at their new homes): `TswapCore/Validation.cs:114` ("README §Threat model" → `docs/security-model.md`), `TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift:205` ("the README's macOS RAM disclosure": find where that text went), `TswapTests/CliEnvironmentTests.cs:89`, `AGENTS.md:185`; and `grep -rn 'README' TswapCli TswapCore TswapTests AGENTS.md` for any other.
- Create: `docs/README.md` (the index: one line per guide, grouped "Getting started", "Using tswap", "Security", "Reference", "Design records")

Content (spec D1): what tswap is and why (the current pitch, lines 1-27, kept tight; no links to design docs here); install (release download, the macOS quarantine note, `installscript`; per-OS detail is a link to `docs/install.md`); the guided `tswap init` (short: what it asks, one example run, link to `docs/setup.md`); the first secret and `tswap run` (about 10 lines from "Example: AI Agent Workflow"); "Where to go next" (the index's groups, one line each); License. At the end, inside `<details><summary>Moved sections</summary>`, a table with one row per README heading that moved or was dropped (the dropped "Setup", `#setup`, points to `docs/setup.md`, the guided init that replaced it; a slug that is still a live README heading gets no row): old heading, `<a id="old-slug"></a>` in the row, and a link to its new page and heading. Every slug in `TswapTests/Docs/old-readme-anchors.txt` resolves (Task 1's guard), and the README is at most 300 lines outside the `<details>` block.

- [ ] **Step 1:** write the README and the index.
- [ ] **Step 2: Coverage check in the report:** every row of the inventory's README section map → where it went (page and heading, design record, or the planned drop of "Setup" 176-198; "release notes" only where `docs/release-notes/v0.2.0.md` already holds it); nothing unaccounted for. Delete the README half of `Anchors_EqualIndependentLists` (named in the commit message).
- [ ] **Step 2b: GitHub render check:** render `README.md`, `docs/BROKER.md` and the two root stubs with `gh api markdown -f mode=gfm -f context=stevedcc/TokenSwap -F text=@<file>` and check that every slug of the matching old-anchor list appears as `id="user-content-<slug>"` (checked on 2026-11-05: GitHub keeps `<a id>` inside a table cell inside `<details>`); list any missing.
- [ ] **Step 3:** `wc -l` of the README outside the `<details>` block ≤ 300; `dotnet test TswapTests --filter "FullyQualifiedName~Docs"` → PASS; the whole suite `./runtests.sh` → PASS.
- [ ] **Step 4: Commit.**

### Final

The final review (GLM and MiMo, external, as for every tswap brief) reads the whole branch for: lost content (the reports' source-to-target tables), strengthened claims, duplicated explanations, broken reading order, and clarity — would a new user find install → guided init → first secret in five minutes, and would an experienced one find the broker threat model in one click. After merge, close #172 and comment on #158 and #159 with what this covered. **Owner spot check after merge** (Step 2b already checked the rendered ids): on github.com, open three old README anchors, two old `docs/BROKER.md` anchors and one old design-file anchor from the root stubs; each lands on its "Moved sections" row with a working link. If GitHub doesn't honour `id` inside table cells, the fallback is `<a name>` or a line per anchor; record the result on #244.
