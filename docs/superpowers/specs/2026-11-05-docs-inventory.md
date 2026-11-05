# tswap docs inventory (worktree tswap-wt/dr, branch docs/restructure, read-only)

Issue context: #244 (open; README 1,433 lines in the issue, 1,453 lines in the tree, 58 headings, plus the H1). #158 (slots protection column, SecurityWarnings, migrate, honest per-backend posture table in README, `init --tpm` prints the no-PIN/no-PCR limit) and #159 (README must state the Secure Enclave ECIES construction is hand-rolled and unreviewed) are open and are to be absorbed by the security-model page. Both are code+doc items: check which code parts already landed (InitCommand.cs:609-612 and GuidedInit.cs:327 already print the SE review note; README.md:343-346 has the disclosure). #172 ("Document Phase 6 v0 multi-machine keyring vaults in README") exists and is OPEN, the old Phase 6 README draft; #244 says to close it.

## 1. Markdown files (excluding docs/superpowers, bin, obj)

| Path | Lines | Purpose |
|---|---|---|
| README.md | 1453 | Everything: pitch, install, setup, password/agent, multi-machine, security, agent skill install, burn playbook, commands, examples, sync, files, prerequisites |
| AGENTS.md | 243 | Agent/contributor guide: architecture, build, sudo split, rules (CLAUDE.md and .github/copilot-instructions.md point to it) |
| CLAUDE.md | 3 | Pointer to AGENTS.md |
| .github/copilot-instructions.md | 27 | Pointer + review key points |
| HARDWARE_BACKENDS.md | 936 | Backend seam, per-backend status/verification, Swift shim and tpm2-tools rationale, vault password per backend, adding a backend |
| MULTI_MACHINE_KEYING.md | 801 | Keyring design: crypto, slots, enrolment, record store, record format 3, vault password, deferred work |
| REFACTORING_PLAN.md | 769 | Phase 0-6 refactor plan (history; Phase 6 section referenced from code comments) |
| docs/BROKER.md | 1305 | Broker threat model + ssh agent + setup + templates + platforms + limits |
| docs/ssh-agent-wire.md | 405 | Pinned ssh-agent wire format (RFC 9987); referenced from SshAgent*.cs |
| docs/release-notes/v0.2.0.md | 185 | Only release-notes file; migration-first notes |
| docs/briefs/*.md (17 files: i224, t1, t2, t4-t14, t16-s1, t17) | 468, 103, 111, 134, 106, 283, 292, 331, 270, 223, 256, 158, 204, 212, 573, 1516 | Agent task briefs (history/specs; t17 alone is 1,516 lines). Candidates for docs/design/ or leave as-is |
| evals/skill/README.md | 55 | How the skill eval works (overlaps README "Evaluating the skill") |

Specs/briefs: the issue's "the specs" means docs/briefs/*.md (there is no docs/specs/). docs/superpowers excluded as asked.

## 2. README section map

Columns: level, title, GitHub anchor (computed with GitHub's slug rules, duplicates suffixed), line range, line count, proposed destination. Headings inside code fences were excluded (many `# comment` lines in bash blocks). Ranges run to the line before the next heading, so a level-2 container with no body is a 2-9 line stub.

| L | Title | Anchor | Lines | Count | Destination |
|---|---|---|---|---|---|
| 1 | tswap - hardware-backed secret manager | `#tswap---hardware-backed-secret-manager` | 1-27 | 27 | README: what/why, trimmed to about 25 lines; keep the four-point pitch, drop the "Further reading" links to design docs |
| 2 | How It Works | `#how-it-works` | 28-29 | 2 | (container heading) drop; README gets a short "how it works" |
| 3 | AI Agent Safety | `#ai-agent-safety` | 30-72 | 43 | docs/security-model.md (sudo privilege split table); README keeps 5 lines. AGENTS.md describes the same split (duplicate) |
| 3 | YubiKey Cold Storage (classic vault, migration only) | `#yubikey-cold-storage-classic-vault-migration-only` | 73-97 | 25 | docs/upgrading-from-0.1.md; largely duplicates 797-816 |
| 2 | Quick Start | `#quick-start` | 98-99 | 2 | (container heading) README |
| 3 | Download a release | `#download-a-release` | 100-118 | 19 | README Install (release download; macOS quarantine note at 110-117) |
| 3 | Install (compiled binary — recommended) | `#install-compiled-binary--recommended` | 119-152 | 34 | README Install, shortened; per-OS detail to docs/install.md |
| 3 | Reinstall using installscript | `#reinstall-using-installscript` | 153-170 | 18 | README installscript, 2 lines |
| 3 | Windows notes | `#windows-notes` | 171-175 | 5 | docs/install.md (Windows notes); line 174 link to Helm Deployment Patterns must be repointed |
| 3 | Setup | `#setup` | 176-198 | 23 | DROP: stale classic two-YubiKey ykman setup, superseded by the guided init section; first-secret/run lines move to README |
| 3 | Setting up: the guided `tswap init` | `#setting-up-the-guided-tswap-init` | 199-242 | 44 | README guided `tswap init` (core front-page material); the flag list goes to docs/commands.md |
| 3 | Setup with a YubiKey keyring vault (one key per slot) | `#setup-with-a-yubikey-keyring-vault-one-key-per-slot` | 243-270 | 28 | docs/setup.md (YubiKey keyring vault) |
| 3 | Two YubiKeys plugged in | `#two-yubikeys-plugged-in` | 271-301 | 31 | docs/setup.md (several YubiKeys plugged in) |
| 3 | Setup on a TPM or Secure Enclave machine | `#setup-on-a-tpm-or-secure-enclave-machine` | 302-364 | 63 | docs/setup.md (TPM / Secure Enclave); the Secure Enclave review disclosure (343-346) and TPM no-PIN text -> docs/security-model.md (#158/#159) |
| 3 | Remote enrolment of a YubiKey into a TPM vault, step by step | `#remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step` | 365-402 | 38 | docs/multi-machine.md (remote enrolment walk-through) |
| 3 | The recovery key | `#the-recovery-key` | 403-420 | 18 | docs/setup.md (recovery key) |
| 3 | Limits of this version | `#limits-of-this-version` | 421-433 | 13 | docs/setup.md "Limits"; format-stability note to release notes |
| 2 | The vault password and the agent (v0.2) | `#the-vault-password-and-the-agent-v02` | 434-442 | 9 | (container heading) docs/vault-password-and-agent.md |
| 3 | Setup with a password | `#setup-with-a-password` | 443-489 | 47 | docs/vault-password-and-agent.md |
| 3 | Typing it, or the agent | `#typing-it-or-the-agent` | 490-543 | 54 | docs/vault-password-and-agent.md |
| 3 | What the password does and doesn't protect | `#what-the-password-does-and-doesnt-protect` | 544-589 | 46 | docs/vault-password-and-agent.md plus docs/security-model.md |
| 3 | The agent's socket and containers | `#the-agents-socket-and-containers` | 590-609 | 20 | docs/vault-password-and-agent.md |
| 2 | Containers: credentials they never hold | `#containers-credentials-they-never-hold` | 610-619 | 10 | docs/broker.md intro; 1 paragraph that restates docs/BROKER.md 1-30 (duplicate); line 618 mentions "BROKER.md" without a link |
| 2 | Rotating a secret | `#rotating-a-secret` | 620-659 | 40 | docs/rotating-and-burning.md (merge with Burn & Rotate) |
| 2 | Sharing a vault between machines | `#sharing-a-vault-between-machines` | 660-756 | 97 | docs/multi-machine.md (synced folders, join); the integrity/rollback notes (about 735-756) to security-model |
| 3 | Record format 3 and `vault reindex` | `#record-format-3-and-vault-reindex` | 757-796 | 40 | docs/multi-machine.md short paragraph; format detail duplicates MULTI_MACHINE_KEYING.md 498-574 (design record) |
| 2 | Upgrading from 0.1: classic vaults and `vault reindex` | `#upgrading-from-01-classic-vaults-and-vault-reindex` | 797-816 | 20 | docs/upgrading-from-0.1.md; docs/release-notes/v0.2.0.md 7-35 repeats it |
| 2 | Security: YubiKey Touch Requirement | `#security-yubikey-touch-requirement` | 817-829 | 13 | docs/security-model.md (touch posture per backend) |
| 3 | Without Touch (a deliberate choice) | `#without-touch-a-deliberate-choice` | 830-852 | 23 | docs/security-model.md |
| 3 | Migrating to Touch-Required Slots | `#migrating-to-touch-required-slots` | 853-870 | 18 | docs/security-model.md; check against the `migrate` command (it now refuses/handles classic vaults differently) |
| 2 | Threat Model & Non-Goals | `#threat-model--non-goals` | 871-874 | 4 | docs/security-model.md |
| 3 | What tswap protects against | `#what-tswap-protects-against` | 875-886 | 12 | docs/security-model.md |
| 3 | What tswap does NOT protect against | `#what-tswap-does-not-protect-against` | 887-899 | 13 | docs/security-model.md |
| 3 | Design rationale | `#design-rationale` | 900-903 | 4 | docs/security-model.md (4 lines) |
| 2 | Recommended Agent Permissions | `#recommended-agent-permissions` | 904-907 | 4 | docs/agent-integration.md (container) |
| 3 | Agent role (no sudo) | `#agent-role-no-sudo` | 908-933 | 26 | docs/agent-integration.md; overlaps the skill text printed by `tswap prompt` and AGENTS.md |
| 3 | Operator role (requires sudo) | `#operator-role-requires-sudo` | 934-947 | 14 | docs/agent-integration.md |
| 3 | Example: policy enforcement | `#example-policy-enforcement` | 948-964 | 17 | docs/agent-integration.md |
| 3 | Global install (recommended) | `#global-install-recommended` | 965-1004 | 40 | docs/agent-integration.md (skill install) |
| 3 | Per-project install (fallback) | `#per-project-install-fallback` | 1005-1015 | 11 | docs/agent-integration.md |
| 3 | Keeping the skill current | `#keeping-the-skill-current` | 1016-1019 | 4 | docs/agent-integration.md |
| 3 | Evaluating the skill | `#evaluating-the-skill` | 1020-1028 | 9 | docs/agent-integration.md or just link evals/skill/README.md (same topic) |
| 2 | Burn & Rotate Playbook | `#burn--rotate-playbook` | 1029-1032 | 4 | docs/rotating-and-burning.md |
| 3 | Step 1: Burn immediately | `#step-1-burn-immediately` | 1033-1042 | 10 | same as the section above it |
| 3 | Step 2: Assess scope | `#step-2-assess-scope` | 1043-1059 | 17 | same as the section above it |
| 3 | Step 3: Rotate at the source | `#step-3-rotate-at-the-source` | 1060-1070 | 11 | same as the section above it |
| 3 | Step 4: Create replacement secret | `#step-4-create-replacement-secret` | 1071-1083 | 13 | same as the section above it |
| 3 | Step 5: Update references | `#step-5-update-references` | 1084-1098 | 15 | same as the section above it |
| 3 | Step 6: Verify and clean up | `#step-6-verify-and-clean-up` | 1099-1108 | 10 | same as the section above it |
| 3 | Quick reference | `#quick-reference` | 1109-1134 | 26 | docs/rotating-and-burning.md; 26 lines that repeat the Commands table (duplicate) |
| 2 | Commands | `#commands` | 1135-1184 | 50 | docs/commands.md, generated or checked against HelpUsage; hand-written table already drifts (section 6) |
| 2 | Example: AI Agent Workflow | `#example-ai-agent-workflow` | 1185-1230 | 46 | docs/examples.md; README first-secret keeps about 10 lines. Lines 1221-1228 quote error texts that live in Validation |
| 2 | Example: Backup Script | `#example-backup-script` | 1231-1243 | 13 | docs/examples.md |
| 2 | Example: Keeping Secrets Out of Config Files | `#example-keeping-secrets-out-of-config-files` | 1244-1270 | 27 | docs/examples.md |
| 3 | Helm Deployment Patterns | `#helm-deployment-patterns` | 1271-1313 | 43 | docs/examples.md (Helm) |
| 2 | Sync transports | `#sync-transports` | 1314-1373 | 60 | docs/multi-machine.md (sync transports) or docs/sync.md |
| 2 | Files | `#files` | 1374-1416 | 43 | docs/commands.md appendix "Files" or docs/reference-files.md |
| 3 | Environment variables | `#environment-variables` | 1417-1436 | 20 | docs/commands.md (Environment variables); the same list is printed by CommandRegistry.PrintHelp |
| 2 | Prerequisites | `#prerequisites` | 1437-1450 | 14 | README Prerequisites trimmed plus docs/install.md; ".NET 10 SDK" matches global.json 10.0.302 |
| 2 | License | `#license` | 1451-1454 | 4 | README License |
Notes: the pitch (lines 1-27) is already the best front page; "How It Works" (28-97) is half sudo-table, half classic-vault history. Roughly: README keeps about 150-250 lines (1-27, install 100-175, guided init 199-242, first secret/run, links); guides take about 850 lines; Commands+Files+Env about 120 go to commands.md; examples about 140.

## 3. Other large docs (brief)

### MULTI_MACHINE_KEYING.md (801): almost all design rationale. Becomes docs/design/multi-machine-keying.md.
User guidance mixed in (extract or just link, do not duplicate): "Hand-carried enrollment (v0)" 350-384 and "Fleet enrollment: receipts, merge..." 385-466 (steps duplicate README 365-402 and 660-756); "Shared vault folders: the record store" 467-497 and "Record format 3" 498-574 (duplicates README 757-796); "The vault password (brief T17, v0.2.0)" 575-680 (duplicates README 434-609; README 488 links here); "YubiKey slots: one key per slot" 259-298 (overlaps HARDWARE_BACKENDS.md 98-152 and README 243-301). Pure design: Scope, Why, crypto, design space, enforcement rule, keyring model, k>=2, two-layer wrap, AAD, X25519, recovery slot (path not taken), landmine, mapping to code, ordering, open questions, deferred. Headings carry brief/issue numbers (anchors long and fragile).

| L | Title | Lines (count) |
|---|---|---|

| 1 | Multi-machine keying: hardware backends and the vault key model | 1-12 (12) |
| 2 | Scope: v0 / v1 / v2 | 13-33 (21) |
| 2 | Why: broaden hardware support to grow adoption | 34-49 (16) |
| 2 | How today's crypto actually works (be precise) | 50-69 (20) |
| 2 | The design space (and why it all funnels to one answer) | 70-82 (13) |
| 3 | The Secure Enclave is the tiebreaker | 83-93 (11) |
| 2 | Where enforcement can and cannot live (a standing rule) | 94-120 (27) |
| 2 | The model: a keyring of wrapped shares (k = 1) | 121-146 (26) |
| 3 | Extension implies decryption — an "extension-only" recovery slot isn't achievable | 147-171 (25) |
| 3 | Why not k ≥ 2 (yet) | 172-199 (28) |
| 3 | Two-layer slot wrap | 200-222 (23) |
| 3 | AAD binding | 223-238 (16) |
| 3 | Per-slot X25519 keypair | 239-258 (20) |
| 3 | YubiKey slots: one key per slot (brief T4, issue #184) | 259-298 (40) |
| 2 | The recovery slot: a bare keypair, not a CA-issued certificate (a path not taken) | 299-336 (38) |
| 3 | Per-backend wrap primitive | 337-349 (13) |
| 2 | Hand-carried enrollment (v0) | 350-384 (35) |
| 3 | Fleet enrollment: receipts, merge and the recovery key (brief T5, issues #190, #152, #187) | 385-466 (82) |
| 3 | Shared vault folders: the record store (brief T6) | 467-497 (31) |
| 3 | Record format 3: metadata and value sections (brief T16-S1, v0.2.0) | 498-574 (77) |
| 3 | The vault password (brief T17, v0.2.0) | 575-680 (106) |
| 2 | The landmine: threshold downgrade | 681-697 (17) |
| 2 | How this maps onto the code already in the branch | 698-715 (18) |
| 2 | Implementation ordering | 716-750 (35) |
| 2 | Open questions | 751-769 (19) |
| 2 | Deferred to v1 | 770-802 (33) |

### HARDWARE_BACKENDS.md (936): design record plus per-backend status. Becomes docs/design/hardware-backends.md.
User guidance mixed in: "Checking a no-touch Secure Enclave slot on a Mac" 341-407 (a how-to; README 330 links to it) and "Touch or no touch" 295-340; "Under sudo: used as the vault folder's owner" 247-272 (README 340 links); "Several keys plugged in, and the touch posture" 153-174 (overlaps README 271-301); "Status: PoC-grade" 273-294 (the unreviewed-ECIES disclosure; README 343 quotes it; this is the #159 source and belongs in the security model page as a short statement, with the long form staying here); "Dev/test setup: swtpm" 588-613, "Virtual TPM (Parallels)" 683-707, "Dev environment note ... cellular link" 708-721 are developer notes, not user docs (candidates for CONTRIBUTING/dev doc or drop; 708-721 is trivia). "The vault password per backend" 722-867: design, linked from README 487. Per-backend posture (#158 table) should be written into docs/security-model.md from "Status" sections 273-294, 528-548, 672-682.

| L | Title | Lines (count) |
|---|---|---|
| 1 | Hardware backends | 1-7 (7) |
| 2 | The seam | 8-42 (35) |
| 3 | The enrollment seam (issue #151) | 43-69 (27) |
| 3 | The simulated backend (issue #153) | 70-82 (13) |
| 3 | TPM and Secure Enclave vaults are keyring vaults (brief T2, decisions 2 and 4) | 83-97 (15) |
| 3 | YubiKey keyring slots: one key per slot (brief T4, issue #184) | 98-152 (55) |
| 3 | Several keys plugged in, and the touch posture (brief T7, issues #198 and #185) | 153-174 (22) |
| 3 | A TPM or Secure Enclave machine joins a fleet (brief T5, issue #152) | 175-215 (41) |
| 2 | Config discriminator | 216-229 (14) |
| 2 | Secure Enclave: implemented, runs unsigned, verified on real hardware | 230-246 (17) |
| 3 | Under sudo: used as the vault folder's owner, not root (brief T12, issue #157) | 247-272 (26) |
| 3 | Status: PoC-grade, not yet production-hardened | 273-294 (22) |
| 3 | Touch or no touch: an explicit choice (brief T11) | 295-340 (46) |
| 3 | Checking a no-touch Secure Enclave slot on a Mac | 341-407 (67) |
| 3 | Why a Swift shim, not raw Security.framework P/Invoke (the path not taken) | 408-444 (37) |
| 3 | The trade-off this brings | 445-465 (21) |
| 3 | Distribution: the dylib is embedded, not shipped as a companion file | 466-498 (33) |
| 2 | Linux TPM: implemented, verified on a software simulator and on a physical Intel PTT | 499-527 (29) |
| 3 | Status: verified on one physical TPM (Intel PTT), single vendor | 528-548 (21) |
| 4 | Simulator phase (before 2026-10-29) | 549-587 (39) |
| 3 | Dev/test setup: swtpm in a container | 588-613 (26) |
| 3 | Why a shellout to tpm2-tools, not P/Invoke libtss2-esys/libtss2-fapi (the path not taken) | 614-627 (14) |
| 2 | Windows TPM: implemented, verified on a virtual TPM, also run on a physical one during development | 628-671 (44) |
| 3 | Status: virtual TPM verified; physical TPM tested during development, v0.1.0 re-check open | 672-682 (11) |
| 4 | Virtual TPM (Parallels) | 683-707 (25) |
| 3 | Dev environment note: this VM's internet connection is a marginal cellular link | 708-721 (14) |
| 2 | The vault password per backend (brief T17) | 722-736 (15) |
| 3 | Linux TPM: the auth value through tpm2-tools | 737-772 (36) |
| 3 | Windows TPM: `PCP_USAGEAUTH` at creation and at use | 773-800 (28) |
| 3 | Secure Enclave: the Enclave checks the password | 801-847 (47) |
| 3 | YubiKey: the KDF only | 848-855 (8) |
| 3 | Dev/test: swtpm on the build machine | 856-867 (12) |
| 2 | Adding a backend | 868-895 (28) |
| 2 | Redundancy and Phase 6 | 896-937 (42) |

### docs/BROKER.md (1305): one file, three audiences. Split into docs/broker.md (guide: Setup 682-951, Command templates 952-1241 operational parts, Platforms 1242-1283, Limits 1284-1306, Costs 674-681) and docs/design/ or docs/broker-threat-model.md (Threat model 31-356, password broker trust model 357-493, ssh threat parts 588-637, "What a compromised container can do" sections). The issue asks for "the user guide, with the threat model in its own page". Pieces that are both: "A broker with a vault password" 357-493 (setup+trust), "SSH: an agent that signs" 494-673 (Setup 510-587 is how-to, rest is threat model), "Changed in v0.2.0 (breaking)" 1220-1241 (release notes material, duplicates v0.2.0.md "Broker: each socket names its container" 138+). Duplicate heading "Setup" appears twice (anchors `#setup` at 510 and `#setup-1` at 682): inbound links to `#setup` are ambiguous; none exist today.

| L | Title | Lines (count) |
|---|---|---|
| 1 | tswap broker: credentials for containers that never hold them | 1-30 (30) |
| 2 | Threat model | 31-32 (2) |
| 3 | Redaction is best-effort | 33-79 (47) |
| 3 | Redaction confirms whole guesses | 80-117 (38) |
| 3 | Timing | 118-126 (9) |
| 3 | What a compromised container can and can't do | 127-151 (25) |
| 3 | Limits of the identity check | 152-224 (73) |
| 3 | SELinux | 225-271 (47) |
| 3 | The vault user is root-equivalent for its secrets | 272-283 (12) |
| 3 | The load-bearing assumption: no container runs with the vault user's uid | 284-301 (18) |
| 3 | The TPM's dictionary-attack counter | 302-332 (31) |
| 3 | Memory | 333-356 (24) |
| 2 | A broker with a vault password (brief T17) | 357-416 (60) |
| 3 | The control socket and its trust model | 417-452 (36) |
| 3 | Memory and dumpability of a password broker | 453-474 (22) |
| 3 | SELinux for the control socket | 475-493 (19) |
| 2 | SSH: an agent that signs with vault keys (brief T10) | 494-509 (16) |
| 3 | Setup | 510-587 (78) |
| 3 | How a signature is allowed | 588-609 (22) |
| 3 | What the restriction does and doesn't do | 610-624 (15) |
| 3 | What a compromised container can and can't do (ssh) | 625-637 (13) |
| 3 | Memory, limits and logging | 638-673 (36) |
| 2 | Costs | 674-681 (8) |
| 2 | Setup | 682-683 (2) |
| 3 | 1. The vault user | 684-709 (26) |
| 3 | 2. The socket folder | 710-770 (61) |
| 3 | 3. Routes and sockets (`broker.json`) | 771-827 (57) |
| 3 | 4. The systemd unit | 828-853 (26) |
| 3 | 5. Finding a container's uid | 854-870 (17) |
| 3 | 6. Starting a container | 871-883 (13) |
| 3 | 7. Bind the socket to its container | 884-921 (38) |
| 3 | 8. Using it from inside the container | 922-951 (30) |
| 2 | Command templates | 952-969 (18) |
| 3 | What the sandbox gives | 970-1012 (43) |
| 3 | Secrets reach the child through env or a read-only file only | 1013-1031 (19) |
| 3 | The bind rule (`binds`, `cwd`) | 1032-1066 (35) |
| 3 | Defining a template | 1067-1099 (33) |
| 3 | Examples | 1100-1144 (45) |
| 3 | One unlock per call, reading only the template's secrets | 1145-1153 (9) |
| 3 | Output | 1154-1180 (27) |
| 3 | What a compromised container can do with a template | 1181-1190 (10) |
| 3 | What a template author must not do | 1191-1207 (17) |
| 3 | Logging | 1208-1219 (12) |
| 3 | Changed in v0.2.0 (breaking) | 1220-1241 (22) |
| 2 | Platforms | 1242-1283 (42) |
| 2 | Limits (v1) | 1284-1306 (23) |
Other large docs: docs/ssh-agent-wire.md (405) is a spec; move to docs/design/ (code refs it as `docs/ssh-agent-wire.md` at SshAgentListener.cs:15, SshWire.cs:6, SshAgentProtocol.cs:3). REFACTORING_PLAN.md (769) is history; code cites it by "REFACTORING_PLAN.md section Phase 6" (KeyringFormat.cs:5, FilenameHasher.cs:12). docs/briefs/t17-vault-password-agent.md (1516) is the biggest brief.

## 4. Inbound links that must keep working

Anchor check: I extracted every `](path#anchor)` and `](#anchor)` link in README.md, HARDWARE_BACKENDS.md, MULTI_MACHINE_KEYING.md, docs/BROKER.md, docs/release-notes/v0.2.0.md, docs/ssh-agent-wire.md and computed GitHub slugs: all 33 anchor links resolve today (no dead anchors). Link targets that README sections are the target of (so keep or redirect):

### 4a. Strings printed by the program (user-visible; cannot be changed after release, only the files can stay or redirect)
| Source | Exact text | Target exists |
|---|---|---|
| TswapCli/Commands/InitCommand.cs:255 | `(k = 1) — see MULTI_MACHINE_KEYING.md. Add more keys later, each as its own` | file, yes |
| TswapCli/Commands/InitCommand.cs:612 | `has not had an independent cryptographic review. See HARDWARE_BACKENDS.md.` | file, yes |
| TswapCli/Commands/GuidedInit.cs:327 | `has not had an independent cryptographic review. See HARDWARE_BACKENDS.md.` (same message) | file, yes |
| TswapCli/Commands/SlotCommand.cs:429 | `(a classic, non-keyring vault has no K_v to share — see MULTI_MACHINE_KEYING.md).` | file, yes |
| TswapCore/Broker/BrokerShortSecretWarnings.cs:25 | log line `... see BROKER.md "Redaction confirms whole guesses"` (bare name, no docs/); heading exists at BROKER.md:80; the string is also asserted verbatim in TswapTests/BrokerShortSecretWarningTests.cs:37, so changing it means editing that test (AGENTS.md rule: input change is allowed, say so in the commit) | yes |
| contrib/systemd/tswap-broker.service:24 | `Documentation=https://github.com/stevedcc/TokenSwap/blob/main/docs/BROKER.md` (the only absolute blob URL in the repo; the moved file would 404 unless docs/BROKER.md stays or the URL is edited; already-installed units keep the old URL) | yes |
| TswapCore/InstallScript.cs | no doc links; it only mentions SKILL.md (not a repo file) | n/a |

No program message points at a README anchor. CommandRegistry.PrintHelp prints no URLs or doc paths. README is cited only from comments: TswapCore/Validation.cs:114 `README §Threat model` (anchor `#threat-model--non-goals`, exists), TswapCore/Vault/Interop/swift/TswapSecureEnclave.swift:205 ("the README's macOS RAM disclosure"; no anchor, find the text before moving), TswapTests/CliEnvironmentTests.cs:89 (`README: set TSWAP_CONFIG_DIR`).

### 4b. Links among docs
| Source:line | Target | Exists |
|---|---|---|
| README.md:14 | #upgrading-from-01-classic-vaults-and-vault-reindex | yes (797) |
| README.md:22, 348, 884, 1156 | #the-vault-password-and-the-agent-v02 | yes (434) |
| README.md:24 | HARDWARE_BACKENDS.md | yes |
| README.md:25 | MULTI_MACHINE_KEYING.md | yes |
| README.md:102 | https://github.com/stevedcc/TokenSwap/releases | external |
| README.md:173, 233, 1139 (and 1143 area) | #commands | yes (1135) |
| README.md:174 | #helm-deployment-patterns | yes (1271) |
| README.md:233, 812, 1139 | #setting-up-the-guided-tswap-init | yes (199) |
| README.md:330 | HARDWARE_BACKENDS.md#checking-a-no-touch-secure-enclave-slot-on-a-mac | yes (341) |
| README.md:340 | HARDWARE_BACKENDS.md#under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157 | yes (247) |
| README.md:343 | HARDWARE_BACKENDS.md#status-poc-grade-not-yet-production-hardened | yes (273) |
| README.md:487 | HARDWARE_BACKENDS.md#the-vault-password-per-backend-brief-t17 | yes (722) |
| README.md:488 | MULTI_MACHINE_KEYING.md#the-vault-password-brief-t17-v020 | yes (575) |
| README.md:542, 1162 | docs/BROKER.md#a-broker-with-a-vault-password-brief-t17 | yes (357) |
| README.md:618 | docs/BROKER.md (and bare text "see BROKER.md") | yes |
| README.md:815 | docs/release-notes/v0.2.0.md | yes |
| README.md:1139 | #setup-with-a-yubikey-keyring-vault-one-key-per-slot | yes (243) |
| README.md:1139 | #setup-on-a-tpm-or-secure-enclave-machine | yes (302) |
| README.md:1140, 1318, 1325 | #sharing-a-vault-between-machines | yes (660) |
| README.md:1144 | #rotating-a-secret | yes (620) |
| README.md:1161 | #containers-credentials-they-never-hold | yes (610) |
| README.md:1172 | #remote-enrolment-of-a-yubikey-into-a-tpm-vault-step-by-step | yes (365) |
| README.md:1173 | #the-recovery-key | yes (403) |
| README.md:1422 | #two-yubikeys-plugged-in | yes (271) |
| README.md:1446 | HARDWARE_BACKENDS.md | yes |
| HARDWARE_BACKENDS.md:700 | #windows-tpm-pcp_usageauth-at-creation-and-at-use | yes (773) |
| HARDWARE_BACKENDS.md:725 | MULTI_MACHINE_KEYING.md#the-vault-password-brief-t17-v020 | yes (575) |
| docs/BROKER.md:26 | #command-templates | yes |
| docs/BROKER.md:282 | #memory-and-dumpability-of-a-password-broker | yes |
| docs/BROKER.md:402 | #timing | yes |
| docs/BROKER.md:498 | ssh-agent-wire.md (relative) | yes; breaks if either file moves alone |
| docs/release-notes/v0.2.0.md:5 | #vault-password-and-agent | yes (local heading at line 94), but readers wanting the README section land in the release note. Release notes are immutable history: keep as is |
| AGENTS.md:65 | docs/BROKER.md | yes |
| AGENTS.md:185 | text `README "The vault password and the agent" and MULTI_MACHINE_KEYING.md` | yes |
| AGENTS.md:211 | text `HARDWARE_BACKENDS.md` section "YubiKey keyring slots" and again `HARDWARE_BACKENDS.md` | yes |
| contrib/systemd/tswap-broker.service:1,5,28; contrib/selinux/tswap-broker.cil:7,17 | `docs/BROKER.md`, `docs/BROKER.md "SELinux"` | yes (heading at BROKER.md:225) |
| runtests.sh:12,14 | HARDWARE_BACKENDS.md Linux TPM / Windows TPM sections | yes |
| REFACTORING_PLAN.md (347-353, 372, 380, 651-724) | MULTI_MACHINE_KEYING.md § names, HARDWARE_BACKENDS.md | yes |

Code comments citing design docs (about 45 in TswapCore, TswapCli, TswapTests; all as file names in prose, some with section names): MULTI_MACHINE_KEYING.md at Keyring.cs:19,25,74; SlotEnrollmentFile.cs:132; SlotFingerprint.cs:12,17; KeyringFormat.cs:5; RecoverySlotWrap.cs:5; FilenameHasher.cs:13,31; RecoverySlotKek.cs:7; SlotKeyPair.cs:21; SlotPayloadWrap.cs:7; VaultUnlocker.cs:469; SlotsCommand.cs:17,167,221; SlotCommand.cs:10,429; SecureEnclaveHardwareService.cs:10,18,103; TpmHardwareServiceBase.cs:58; Windows/LinuxTpmHardwareService.cs; TswapTests/CommandTests.cs:327, SlotPayloadWrapTests.cs:13. HARDWARE_BACKENDS.md at IHardwareEnrollmentService.cs:27; PlatformCryptoProviderInterop.cs:16; Tpm2ToolsInterop.cs:17,65,122 (the :122 one is in an exception message, user-visible: `simulator in dev/test — see HARDWARE_BACKENDS.md`); TswapSecureEnclave.swift:6; SlotCommand.cs:304; InitCommand.cs:542,609; LinuxTpmHardwareServiceTests.cs:19; WindowsTpmHardwareServiceTests.cs:28. If the design files move to docs/design/, either `git mv` and sweep these (sed over paths) or leave stub files at the old paths. Because the program prints `MULTI_MACHINE_KEYING.md` and `HARDWARE_BACKENDS.md` (4a) and old releases do too, leave short redirect stubs at the root paths (or keep the files there) rather than only moving.

Not found: no `README.md#...` links from outside README; no links in CI workflows (.github/workflows/*.yml have none); no `raw.githubusercontent` URLs; install script has no doc links.

## 5. Command reference source

* ICliCommand (TswapCli/ICliCommand.cs) has `Name`, `HelpUsage`, `Description`, `RequiresSudo`, `NeedsVault`, `WorksOnClassicVault`. Each of 31 files in TswapCli/Commands/ owns its usage string. 30 commands are registered in the ordered array in TswapCli/CommandRegistry.cs:12-43; `CommandRegistry.All` (line ~46) is public and read by CompletionCommand.
* Help screen: `CommandRegistry.PrintHelp` (lines ~121-163): lists non-sudo commands first as `{p} {HelpUsage,-20}    {Description}`, then `[sudo]` ones; prints an Environment block (TSWAP_CONFIG_DIR, TSWAP_YUBIKEY_SERIAL, TSWAP_AGENT_SOCK, sudo home rule), Examples, Prerequisites. Per-command help: `PrintCommandHelp` prints `Usage: [sudo ]tswap <HelpUsage>` and the Description only (so subcommand detail for broker/slot lives in one long HelpUsage string each, e.g. SlotCommand.cs:43, InitCommand.cs:28, BrokerCommand.cs:22).
* Flag fragments are composed from shared constants: `SecureEnclaveTouchChoice.Flags`, `VaultPasswordChoice.Flags`.
* Existing tests: TswapTests/HelpTests.cs checks `--help`/`-h` behaviour and that InitCommand's HelpUsage appears in `init --help`, plus the sudo/TSWAP_CONFIG_DIR and TSWAP_YUBIKEY_SERIAL lines in the top-level help. No test reads README.md or any .md file (grep for README in TswapTests finds only a comment). So README-vs-CLI drift is unchecked today. (WorkaroundRegisterTests from the Croft convention does not exist here.)
* How a docs/commands.md check could work: a xunit test in TswapTests that walks `CommandRegistry.All`, and for each command asserts docs/commands.md contains a row/heading for `Name` and the exact `HelpUsage` and `Description` text in a fenced block (fenced block generated by a small `tswap`-side or test-side printer), locating the file by walking up from AppContext.BaseDirectory to the dir with TokenSwap.slnx. Better: generate the file (`dotnet test` with an env var to regenerate, or a hidden `tswap docs` command is unwise as it adds surface) and have the test fail with a diff when committed file differs from the generated one; hand-written prose sits outside generated markers (`<!-- BEGIN GENERATED -->`). Sudo column from `RequiresSudo` (note: `broker` and `slot` mix sudo and non-sudo subcommands, README's table splits them by hand; the registry says RequiresSudo=false for `broker`, and `slot` per AGENTS.md:65; a generator can't produce the per-subcommand sudo split, so keep that split as a hand-written table checked by asserting each registry HelpUsage subcommand token appears). Also assert env var names listed (TSWAP_CONFIG_DIR, TSWAP_YUBIKEY_SERIAL, TSWAP_AGENT_SOCK) appear in both the help output and commands.md; the code also reads TSWAP_TEST_KEY, TSWAP_TEST_TERMINAL, TSWAP_TEST_SUDO_BYPASS, TSWAP_TEST_BROKER_RUN_DIR (test-only, must not be documented) and XDG_CONFIG_HOME (README line ~1420 documents it; help does not).
* Pitfall: help text has `FakeConsole` capture available through `CliRunner.Run(ctx, args)` (see HelpTests.Run), so a test can render `PrintHelp` without a vault; `NeedsVault` false commands work with no home.

## 6. Duplication and drift

Drift against code:
1. **Help banner and prerequisites are YubiKey-only**: CommandRegistry.cs prints `tswap - YubiKey Secret Manager`, `Add -v or --verbose ... for detailed YubiKey output`, and a "Prerequisites: ykman CLI: pip install yubikey-manager / ykman otp chalresp --generate --touch 2" block. TPM and Secure Enclave vaults need none of it; README's own title is "hardware-backed secret manager". Fix in code in the same change as the docs (and HelpTests if it asserts the banner).
2. **README Setup section (176-198)** teaches `ykman otp chalresp` for "both YubiKeys" then `tswap init`; the classic two-key model is retired (README 14, 813: "The two-YubiKey XOR vault can no longer be created"). Same ykman line repeated at 247, 822, 1444 and in the help text: four copies of one instruction.
3. **`--keyring`**: README.md:313 says `init` rejects `--keyring`, README.md:813 says `init --keyring` is refused, README.md:1139 says "`--keyring` is gone". These are accurate history notes about the removal in 0.2.0, not stale instructions. Still, three mentions of a removed flag are noise for a front page; move to upgrading/release notes. `grep` found no other `--keyring` use as an instruction.
4. **Commands table vs HelpUsage**: README 1139 init row omits `init --vault-dir` combined usage form (it has a separate row, fine) but the table's hand-written flags can't be checked. Rows missing options present in code: `vault merge <folder>` (code: `vault merge <other-vault-dir> [--yes] (takes --recovery-key-stdin) | vault reindex`; README row 1170ish lacks `--yes`, `--recovery-key-stdin` and has no `vault reindex` row; it only appears in section headings 757/797); `recover` row lacks `[--recovery-key-stdin]`. `agent` help is `agent <start [--timeout <d>]|serve [--foreground]|stop|status>`, README splits it into rows (fine but unchecked). Registry has `installscript` and `completion`; README groups them in one row.
5. **Troubled env table**: README Environment variables (1417-1436) lists XDG_CONFIG_HOME which the help does not; help lists the sudo-home rule in prose. Two sources.
6. **Build prerequisites** README 1448 ".NET 10 SDK" matches global.json (10.0.302) and net10.0; fine. AGENTS.md is .NET 10 too.
7. HARDWARE_BACKENDS.md:676-682 "v0.1.0 re-check open (#156)" and 549 "Simulator phase (before 2026-10-29)" are time-bound statuses; verify before restating in guides. MULTI_MACHINE_KEYING.md headings embed brief numbers and "v0" which will go stale ("Scope: v0 / v1 / v2", "Deferred to v1").
8. Release notes: only v0.2.0 exists in docs/release-notes. v0.3.0 notes will want to go there; the #244 text "Release notes stay per version".

Duplication (same content in two or more places):
* Record store / record format 3: README 757-796 vs MULTI_MACHINE_KEYING.md 498-574.
* Vault password and agent: README 434-609 vs MULTI_MACHINE_KEYING.md 575-680 vs HARDWARE_BACKENDS.md 722-867 vs docs/BROKER.md 357-493 vs release notes 94-137.
* Remote enrolment / fleet enrolment: README 365-402 and 660-756 vs MULTI_MACHINE_KEYING.md 350-466 vs HARDWARE_BACKENDS.md 175-215.
* YubiKey one-key-per-slot: README 243-301 vs MULTI_MACHINE_KEYING.md 259-298 vs HARDWARE_BACKENDS.md 98-174.
* Upgrading from 0.1: README 73-97 and 797-816 vs release notes 7-35.
* Broker intro: README 610-619 vs BROKER.md 1-30; BROKER.md 1220-1241 vs release notes 138-185.
* Sudo privilege split: README 30-72 vs AGENTS.md; command table README 1135-1184 vs README 30-72 vs help text.
* Skill install/eval: README 965-1028 vs evals/skill/README.md and `tswap prompt` (the skill text).
* Quick reference (README 1109-1134) repeats Commands table.
* ykman touch instruction repeated 4 times (above).
* SE review disclosure: README 343-346, HARDWARE_BACKENDS.md 273-294, InitCommand.cs:609-612, GuidedInit.cs:327.

Observations for restructuring: README has two `### Setup` style collisions? README has only one `Setup` heading; BROKER.md has two (`#setup`, `#setup-1`). The H1 "tswap - hardware-backed secret manager" slug is `#tswap---hardware-backed-secret-manager`. Headings in code fences were excluded; any link checker must do the same.
