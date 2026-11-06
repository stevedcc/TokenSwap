# `apply` behind sudo, `run` with a file token — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** No sudo-free command prints secret values any more: `tswap apply` becomes sudo-only, and `tswap run` gains a file token (`{{@path}}`) that hands a child process the file with its `# tswap:` markers filled in, with the child's output redacted, so ops (Helm and the like) keep working for people and agents alike.

**Architecture:** `run` already substitutes, runs through a PTY and redacts. It learns one more token kind, `{{@path}}`: tswap fills the file with `Apply.ApplySecrets` into a private, user-only folder, replaces the token with that file's path, adds every substituted value to the redaction list, and deletes the folder when the child exits. `ApplyCommand.RequiresSudo` turns true. The agent skill prompt and the docs switch from `<(tswap apply …)` to the `run` form.

**Tech Stack:** C# / .NET 10 NativeAOT, RedactingPty (unchanged), xUnit (TswapTests).

**Spec:** issue #251 as rewritten on 2026-11-06 (owner decision: "If it leaks as it is now, it needs to go sudo"; "leaking easily is a no no"): https://github.com/stevedcc/TokenSwap/issues/251

## Global Constraints

- `tswap apply <file>` requires sudo (`RequiresSudo => true`), like `get` and `list`; its output is unchanged.
- The file token is `{{@<path>}}`: `@` can't start a secret name (`[a-zA-Z0-9_-]+`), so it never collides with `{{name}}` or `{{name:previous}}`. `<path>` is any run of characters other than `{`, `}`, resolved against the current directory.
- Substitution semantics are `Apply.ApplySecrets`' unchanged (the same markers, quoting, `:previous`, burned warnings to stderr, refusal of unknown markers and missing secrets).
- Every check `run` makes today still applies (blocklist before and after substitution, no pipe or redirect in the template, burned warnings); a command may mix `{{name}}` and `{{@file}}` tokens; `run` without any token is still refused.
- The filled file lives in a folder only the user can open: Linux/macOS `0700` folder (under `$XDG_RUNTIME_DIR` when set and a directory, else `Path.GetTempPath()`), file `0600`, created with the mode at creation (no chmod after write); Windows a folder under `Path.GetTempPath()` (per-user). The file keeps the original file name (tools may care about the extension).
- The folder is deleted when the child exits, also when it fails or tswap is interrupted (finally); the file's bytes are overwritten with zeros before deletion. A `tswap-run-*` folder older than one hour is removed at the start of the next `run` (crash leftovers).
- Every value written into a filled file is added to the redaction list (the raw value, and its escaped form when `EscapeForQuote` changed it), longest first, as `run` does today.
- Nothing is written to disk before every token and marker resolved; a missing file, a file with no `# tswap:` markers, or a marker naming a missing secret refuses before any child starts.
- No new sudo-free path prints a value: the help text, the skill prompt (`TswapCore/Prompt.cs`) and the docs never suggest `<(tswap apply …)` again.
- British English; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, no session links; commit with explicit paths. Full suites go through `~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh` (another branch is being built on this machine).
- AGENTS.md is changed only with the owner's approval.

### Plan review round 1 (GLM, MiMo; owner on the threat model, 2026-11-06)
- **Threat model (owner: "a shallow sandbox against accidents"; docs/security-model.md:69, :100):** tswap stops accidental leaks and casual exfiltration, not a determined local actor. Out of scope, documented (Task 2): an agent running as the user reading the filled copy from a second command while the first runs; a NOPASSWD sudo grant for tswap (it voids the sudo gate on `apply`, as on `get`).
- **Casual exfiltration is blocked:** with any `{{@file}}` token, refuse programs that print, encode or copy a file: `base64`, `base32`, `basenc`, `xxd`, `od`, `hexdump`, `hd`, `strings`, `cp`, `mv`, `dd`, `install`, `rsync`, `scp`, `tar`, `zip`, `gzip`, `bzip2`, `xz`, `zstd`, `openssl`, `gpg`, `less`, `more`, `head`, `tail`, `nl`, `sort`, `uniq`, `rev`, `tac`, `split`, `ln`, `certutil` (Windows), plus the existing blocklist; and refuse a file token as argv[0] or as the script argument of a shell or interpreter (`sh`, `bash`, `zsh`, `fish`, `dash`, `ksh`, `python*`, `perl`, `ruby`, `node`, `php`, `pwsh`, `powershell`, `cmd`, `lua`, `awk`/`gawk`/`mawk`, `sed`): the file is data for a tool, never a program. The list is a shallow guard, documented as such.
- **One substitution pass on the raw template:** name tokens and file tokens are found in the command as typed; substituted values are never scanned again (a value containing `{{@…}}` is plain text).
- **Every written form is redacted:** `Apply.ApplySecretsReporting` returns the exact strings it wrote into the file (raw value, the `"`-escaped form, the `'`-escaped form, whichever were written) per secret, and all of them go into the replacement list.
- **Folder creation:** root = `$XDG_RUNTIME_DIR` when it is set, a directory owned by the current user and not group- or world-writable; else `Path.GetTempPath()`. The folder name is `tswap-run-` + 16 CSPRNG hex characters, created exclusively (`mkdir` with `0700`; an existing path is an error, retried with a new name); after creation verify it is a directory (not a symlink) owned by the user with mode `0700` before writing. Files are created with `FileMode.CreateNew` and `0600`.
- **Same base name:** each source file gets its own subfolder (`<folder>/1/values.yaml`, `<folder>/2/values.yaml`), keeping the base name; the same resolved source path (case-sensitive comparison on Linux, case-insensitive on macOS and Windows) maps to one copy.
- **Interruption:** SIGINT, SIGTERM and SIGHUP (and Ctrl+C on Windows) are handled: the child is signalled, the folder is zeroed and removed, then tswap exits with the child's or the signal's code. SIGKILL and power loss leave the folder until the next sweep; documented.
- **Sweep:** at the start of each `run`, both roots (the XDG root and the temp root) are swept for `tswap-run-*` folders owned by the current user that are older than one hour **and** not live: each folder holds a `.lock` that the running tswap holds an exclusive lock on (`flock` on Unix, an open-without-sharing handle on Windows); a locked folder is never swept. Sharing violations on Windows are skipped, not fatal.
- **Elevated:** `run` with a file token refuses to run as root (`sudo tswap run …{{@f}}`: "run it as your own user"); no secret file is ever created by root in a user's folder.
- **Other refusals:** an empty `{{@}}`, nested braces in a token, an unreadable source (a `TswapException`, not a raw `UnauthorizedAccessException`). The verbose `Executing:` line masks file tokens too. `run`'s help and description mention `{{@file}}`.

## Review Focus

1. **The child is killed or tswap is interrupted (Ctrl-C) while the filled file exists:** expected: the folder is removed by the `finally`, or at worst by the next `run`'s sweep; nothing else can read it meanwhile. Pinned by Task 1's `RunFileToken_ChildFails_FolderRemoved` and `RunFileToken_StaleFolders_Swept`.
2. **A secret value containing a quote or backslash:** the filled file holds the escaped form, and a child that prints the file (`cat {{@f}}`) must show `[REDACTED: …]`, not the escaped value. Pinned by Task 1's `RunFileToken_EscapedValueIsRedacted`.
3. **A relative path from another directory, a path with spaces, the same file twice, two different files:** each resolves against the current directory; the same file twice gives one filled copy; two files give two. Pinned by Task 1's `RunFileToken_PathForms`.
4. **A marker naming a missing secret, or no markers at all:** refused before any child starts or any file is written. Pinned by Task 1's `RunFileToken_Refusals_WriteNothing`.
5. **An agent following the old prompt** (`tswap apply f` without sudo): refused with a message that names the `run` form. Pinned by Task 2's `Apply_WithoutSudo_RefusedNamingRunForm`.

---

### Task 1: `run` learns `{{@path}}`

**Files:**
- Modify: `TswapCore/Validation.cs` (the file-token regex and extraction), `TswapCli/Commands/RunCommand.cs`, `TswapCore/Apply.cs` (report what it substituted)
- Create: `TswapCli/FilledFiles.cs` (the private folder, the filled copies, cleanup and sweep)
- Test: `TswapTests/RunFileTokenTests.cs`, plus the existing run tests unchanged

**Interfaces:**
- Produces:
  - `public static readonly Regex Validation.FileTokenRegex` = `\{\{@([^{}]+)\}\}`; `public static IReadOnlyList<string> Validation.ExtractFileTokens(string command)` (distinct paths, in order).
  - `public static (string Content, IReadOnlyList<(string Name, string Value)> Applied) Apply.ApplySecretsReporting(string content, SecretsDb db, TextWriter? warnings)`; the existing `ApplySecrets` calls it and returns `.Content` (behaviour unchanged).
  - `internal sealed class FilledFiles : IDisposable` with `string Add(string sourcePath, string content)` (returns the filled copy's path, one copy per distinct source path) and `static void SweepStale(TimeProvider time)`; `Dispose` zeroes and deletes.

- [ ] **Step 1: Write the failing tests** (`RunFileTokenTests`, with the PTY runner faked as the existing run tests do — find their seam):
  - `RunFileToken_ChildGetsTheFilledFile` (the child's argv has a path; reading that path while the child runs gives the file with the markers filled, compared to `Apply.ApplySecrets` of the same input),
  - `RunFileToken_ChildOutputIsRedacted` (the fake child echoes the filled file: the output shows `[REDACTED: db-pw]`, never the value),
  - `RunFileToken_EscapedValueIsRedacted` (a value with `"` and `\`: neither the raw nor the escaped form appears in the output),
  - `RunFileToken_FolderIsPrivate` (Unix: folder `0700`, file `0600`, owner the user; Windows: skip with the reason),
  - `RunFileToken_FolderRemovedAfterSuccess` and `RunFileToken_ChildFails_FolderRemoved` (exit code passed through; folder gone; the file was zeroed before deletion — assert through a seam that records the last bytes written, or by checking the delete happened after a zeroing write),
  - `RunFileToken_StaleFolders_Swept` (a `tswap-run-*` folder older than an hour is removed at start; a newer one is kept),
  - `RunFileToken_PathForms` (relative from a subdirectory, spaces, the same file twice → one copy, two files → two copies, mixed with a `{{name}}` token),
  - `RunFileToken_Refusals_WriteNothing` (missing file, no markers, a marker naming a missing secret, an unknown marker suffix: refused, no child started, no folder created),
  - `RunFileToken_BlocklistStillApplies` (`run sh -c "cat {{@f}}"` refused as today),
  - `RunFileToken_BurnedValueWarns` (stderr warning, as `apply` gives),
  - `RunFileToken_SingleQuotedAndDoubleQuotedFormsRedacted` (one secret written once as `"…"` and once as `'…'`, value containing `"`, `'` and `\`: none of the three forms appears in the output),
  - `RunFileToken_EncodersAndCopiersRefused` (theory over the new list, and `run bash {{@f}}`, `run {{@f}}`, `run python3 {{@f}}`: refused, no folder created),
  - `RunFileToken_ValueContainingFileTokenIsText` (a secret value `{{@/etc/passwd}}`: no second file is filled; the child gets the literal text),
  - `RunFileToken_SameBaseNameTwoFiles` (`a/values.yaml` and `b/values.yaml`: two distinct copies, each with its own content),
  - `RunFileToken_PrecreatedFolderOrSymlinkRefused` (a pre-created `tswap-run-` path or a symlink at the chosen name: never written through; a hostile `$XDG_RUNTIME_DIR` (group-writable or another owner) falls back to the temp root),
  - `RunFileToken_SweepSkipsLiveFolder` (a locked folder older than an hour is kept; an unlocked one is removed; both roots swept),
  - `RunFileToken_InterruptRemovesFolder` (a fake SIGINT path: child signalled, folder gone),
  - `RunFileToken_AsRootRefused` (euid 0 seam: refused before anything is written),
  - `RunFileToken_EmptyOrNestedTokenRefused`.
- [ ] **Step 2: Run them** (`dotnet test TswapTests --filter "FullyQualifiedName~RunFileToken"`) → fail to compile.
  (`RunFileToken_FolderIsPrivate` also asserts the folder is not a symlink and is owned by the user.)
- [ ] **Step 3: Implement.** In `RunCommand`: extract name tokens and file tokens; "no tokens" only when both are empty; resolve and fill every file (in memory) before creating anything on disk; then create the `FilledFiles` set, substitute both token kinds in argv, re-run the post-substitution blocklist, add the applied values (and changed escaped forms) to the replacements, run, dispose in `finally`. Create folder and file with their final modes at creation (`UnixCreateMode`).
- [ ] **Step 4: Run them** → pass; then `~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh` → all green. Break-it-once: leave the applied values out of the replacements → `RunFileToken_ChildOutputIsRedacted` fails.
- [ ] **Step 5: Commit** "run: {{@file}} hands the child a filled copy of the file, output redacted".

### Task 2: `apply` behind sudo; the prompt and the docs switch to `run`

**Files:**
- Modify: `TswapCli/Commands/ApplyCommand.cs` (`RequiresSudo => true`; description), `TswapCore/Prompt.cs`, `docs/commands.md` (regenerated), `docs/examples.md` (Helm patterns), `docs/install.md` (the Windows note about process substitution), `README.md` where it shows `apply`, `docs/release-notes/v0.3.0.md` (a "Breaking" entry: scripts using `<(tswap apply …)`), and the sudo-refusal text if it lists commands
- Test: `TswapTests/ApplyTests.cs` (existing tests run with the sudo bypass where they need it), `TswapTests/PromptTests` or wherever the prompt is pinned

- [ ] **Step 1: Write the failing tests:**
  - `Apply_WithoutSudo_RefusedNamingRunForm` (exit as other sudo commands; the message names `tswap run … {{@file}}`),
  - `Apply_WithSudo_UnchangedOutput` (the existing output, byte for byte),
  - `Prompt_NeverSuggestsApplyForAgents` (the skill text lists `apply` among the sudo commands, contains the `run … {{@file}}` form, and contains no `<(` + `apply`),
  - the docs guard tests pass with the regenerated `docs/commands.md`.
- [ ] **Step 2: Run them** → fail.
- [ ] **Step 3: Implement.** Prompt: move `apply` to "Commands you must NEVER use"; replace the Helm line with `%CMD% run helm upgrade app ./chart -f {{@values.yaml}}`; keep `check`/`tocomment` as they are. Docs: every `<(tswap apply …)` becomes the `run` form; `docs/security-model.md` gains the file token's limits (a same-user agent can read the copy while the child runs; encoders/copiers are blocked as a shallow guard; a NOPASSWD sudo grant voids the `apply` gate; SIGKILL leaves the copy until the next sweep); the Windows note says the `run` form works in cmd and PowerShell. Release notes: the breaking change and the one-line migration.
- [ ] **Step 4: Run them** → pass; whole suite through the lock → green. Break-it-once: set `RequiresSudo` back to false → `Apply_WithoutSudo_RefusedNamingRunForm` fails.
- [ ] **Step 5: Commit** "apply needs sudo; the agent prompt and docs use run {{@file}}".
