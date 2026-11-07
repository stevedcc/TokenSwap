# `apply` behind sudo, `run` with a file token — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** No sudo-free command prints secret values any more: `tswap apply` becomes sudo-only, and `tswap run` gains a file token (`{{@path}}`) that hands a child process the file with its `# tswap:` markers filled in, with the child's output redacted, so ops (Helm and the like) keep working for people and agents alike.

**Architecture:** `run` already substitutes, runs through a PTY and redacts. It learns one more token kind, `{{@path}}`: tswap fills the file with `Apply.ApplySecrets` into a private, user-only folder, replaces the token with that file's path, adds every substituted value to the redaction list, and deletes the folder when the child exits. `ApplyCommand.RequiresSudo` turns true. The agent skill prompt and the docs switch from `<(tswap apply …)` to the `run` form.

**Tech Stack:** C# / .NET 10 NativeAOT, RedactingPty (unchanged), xUnit (TswapTests).

**Spec:** issue #251 as rewritten on 2026-11-06 (owner decision: "If it leaks as it is now, it needs to go sudo"; "leaking easily is a no no"): https://github.com/stevedcc/TokenSwap/issues/251

## Global Constraints

(Rewritten after plan review rounds 1 and 2 (GLM, MiMo) so that each rule appears once; the owner ruled on the threat model on 2026-11-06.)

**Threat model.** tswap is "a shallow sandbox against accidents" (owner; `docs/security-model.md:69`, `:100`): it stops accidental leaks and casual exfiltration, not a determined local actor. Documented limits, not defects (Task 2 writes them into `docs/security-model.md`): an agent running as the user that deliberately reads the filled copy from a second command while the first runs; a NOPASSWD sudo grant for tswap (it voids the sudo gate on `apply`, as on `get`); a child that sends the file over the network (`curl -F f=@{{@f}}`, `wget --post-file`, `git`, cloud CLIs: clients `run`'s core use needs, like `curl -H "Authorization: Bearer {{token}}"`, aren't refused; `scp` and `rsync` are refused as copiers regardless of transport); any transformation beyond the redacted forms below (a value inside a larger base64 blob, custom encodings); SIGKILL or power loss leaving the copy until the next sweep.

**`apply`.** `tswap apply <file>` requires sudo (`RequiresSudo => true`), like `get` and `list`; its output is unchanged.

**The token.** `{{@<path>}}`: `@` can't start a secret name (`[a-zA-Z0-9_-]+`), so it never collides with `{{name}}` / `{{name:previous}}`. `<path>` is any run of characters other than `{`, `}`, resolved against the current directory. Refused, in this order, before the "no tokens" check, by `Validation.ValidateFileTokens(string command)` (a scan of every `{{@` occurrence, separate from `FileTokenRegex`, which can't see malformed ones): an empty `{{@}}`, a token with nested or unbalanced braces — also when the command has valid `{{name}}` tokens too. Name tokens and file tokens are found in one pass over the command as typed; substituted values are never scanned again (a value containing `{{@…}}` is plain text). A command may mix both kinds; `run` without any token is still refused.

**Filling.** `Apply.ApplySecrets`' semantics are unchanged (markers, quoting, `:previous`, burned warnings on stderr, refusal of unknown markers and missing secrets). Every file is resolved and filled in memory before anything is written; a missing or unreadable file (a `TswapException`, not a raw `UnauthorizedAccessException`), a file with no `# tswap:` markers, or a marker naming a missing secret refuses before any folder is created or any child starts.

**Redaction.** For every secret written into a filled file, the replacement list gets every distinct form `Apply` actually wrote (raw, `"`-escaped, `'`-escaped) and, for each of those and for the raw value: its base64 and base64url encodings (padded and unpadded, as `RedactProcessor` already computes for `tswap redact`), and for multi-line values the `\r\n` form of each of those (a PTY translates `\n` to `\r\n` on output) and that form's base64 too. The same base64/base64url and `\r\n` variants are added for `{{name}}` tokens too (today's `run` benefits). Longest first, as today. Multi-line matching across the PTY relay's chunk boundaries is RedactingPty's job; Task 1 pins it with a test and stops (NEEDS_CONTEXT) if RedactingPty can't.

**Obvious printers refused.** With any `{{@file}}` token present, refuse when **any word of the command** (the basename of each argv element, before substitution; so wrappers like `env`, `nice -n 10`, `timeout 5`, `xargs`, `busybox`, `sudo` need no parsing) is a printer, encoder or copier: `cat`, `echo`, `printf`, `tee`, `base64`, `base32`, `basenc`, `xxd`, `od`, `hexdump`, `hd`, `strings`, `uuencode`, `iconv`, `cp`, `mv`, `dd`, `install`, `rsync`, `scp`, `tar`, `zip`, `gzip`, `bzip2`, `xz`, `zstd`, `openssl`, `gpg`, `less`, `more`, `head`, `tail`, `nl`, `sort`, `uniq`, `rev`, `tac`, `split`, `ln`, `certutil` (Windows), plus the existing blocklist; or a shell or interpreter (`sh`, `bash`, `zsh`, `fish`, `dash`, `ksh`, `python*`, `perl`, `ruby`, `node`, `php`, `pwsh`, `powershell`, `cmd`, `lua`, `awk`/`gawk`/`mawk`, `sed`), also as any word; or a file token as argv[0]. A `{{@path}}` word counts as its file's basename (so `{{@cat}}` is refused). Any plain argument counts too, subcommands and messages included (`git checkout tail` would be refused): false refusals are accepted under the shallow-sandbox model; the refusal names the word, and the way out is to rename the file or, for a word that isn't a file, to pass the secret with a plain `{{name}}` token instead. The file is data for a tool, never a program. This refuses the obvious one-step printers; it is a shallow guard, documented as such, not a claim that exfiltration is impossible.

**The private folder.** Root (Unix): `$XDG_RUNTIME_DIR` when it is set, a directory (not a symlink) owned by the current user and not group- or world-writable; otherwise `Path.GetTempPath()`. Windows: `Path.GetTempPath()`, and the created folder gets an explicit ACL granting only the current user (inheritance from the parent removed), verified after creation. Folder name `tswap-run-` + 16 CSPRNG hex characters, created exclusively (Unix: `mkdir(path, 0700)` by P/Invoke, an existing path is an error and a new name is tried); after creation verify it is a directory (not a symlink) owned by the user with mode `0700` (Windows: the ACL) before writing. Each source file gets its own numbered subfolder (`<folder>/1/values.yaml`), created the same way, keeping the base name (tools may care about the extension); the same resolved source path (case-sensitive on Linux, case-insensitive on macOS and Windows) maps to one copy. Files are created with `FileMode.CreateNew` and `0600`. Test seams: the name generator, the ownership/mode check (`stat`), euid, the signal trigger and a recorder of what cleanup writes are injectable through one `FilledFilesEnvironment` record passed to `FilledFiles` (instance methods, including the sweep).

**Lifetime.** A `.lock` file in the folder is created and exclusively locked (`flock` on Unix, an open-without-sharing handle on Windows) before the first secret is written, and held until cleanup. Cleanup, after the child has exited: overwrite every filled file with zeros (best effort: tmpfs and SSDs may keep copies), delete the folder, release the lock. On SIGINT, SIGTERM or SIGHUP (Ctrl+C / Ctrl+Break on Windows): forward the signal to the child's process group, wait up to 10 seconds for it to exit (then SIGKILL / TerminateProcess), clean up, and exit with the reaped child's exit code (128 + signal if it died from it). `finally` covers exceptions.

**Sweep.** At the start of each `run` with a file token, both roots (the XDG root and the temp root) are swept: a `tswap-run-*` folder owned by the current user whose modification time is older than one hour, and whose `.lock` the sweep can acquire or which has no `.lock` (a crash between creating the folder and the lock), is zeroed and deleted; a folder whose lock is held is never touched; Windows sharing violations are skipped, not fatal.

**Elevated.** `run` with a file token refuses to run as root (`sudo tswap run …{{@f}}`: "run it as your own user"), so root never creates a secret file in a user's folder. On Windows an elevated (admin) tswap is allowed (the per-user temp folder and the ACL already make it private to that user); `RunFileToken_AsRootRefused` is Unix-only.

**Unchanged and still applied.** `run`'s blocklist before and after substitution, the pipe/redirect check on the template, burned warnings. The verbose `Executing:` line masks file tokens too. `run`'s help and description mention `{{@file}}`.

**Docs and prompt.** No sudo-free path suggests printing values: the help text, the skill prompt (`TswapCore/Prompt.cs`) and the docs never suggest `<(tswap apply …)` again.

**Process.** British English; commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, no session links; commit with explicit paths. Full suites go through `~/RiderProjects/tswap-wt/tools/with-suite-lock.sh ./runtests.sh` (another branch is built on this machine). AGENTS.md is changed only with the owner's approval.

## Review Focus

1. **The child is killed or tswap is interrupted (Ctrl-C) while the filled file exists:** expected: the folder is removed after the child has exited (signal handling and `finally`), or after SIGKILL by the sweep of the next `run` that has a file token, which never touches a live run's folder; no other user can read it meanwhile. Pinned by Task 1's `RunFileToken_ChildFails_FolderRemoved`, `RunFileToken_InterruptRemovesFolder`, `RunFileToken_StaleFolders_Swept` and `RunFileToken_SweepSkipsLiveFolder`.
2. **A secret value containing a quote or backslash, a multi-line value, or a chart that base64-encodes it (`helm template` of a Secret):** every written, escaped and base64 form shows as `[REDACTED: …]`. Pinned by Task 1's `RunFileToken_EscapedValueIsRedacted`, `RunFileToken_SingleQuotedAndDoubleQuotedFormsRedacted`, `RunFileToken_MultiLineValueRedacted` and `RunFileToken_Base64OfValueRedacted`.
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
  - `public static readonly Regex Validation.FileTokenRegex` = `\{\{@([^{}]+)\}\}`; `public static IReadOnlyList<string> Validation.ExtractFileTokens(string command)` (distinct paths, in order); `public static void Validation.ValidateFileTokens(string command)` (scans every `{{@` occurrence; throws `TswapException` naming the token for an empty, nested or unclosed one).
  - `public static (string Content, IReadOnlyList<(string Name, string Raw, IReadOnlyList<string> WrittenForms)> Applied) Apply.ApplySecretsReporting(string content, SecretsDb db, TextWriter? warnings)` (one row per secret used; `WrittenForms` = every distinct string written into the file for it); the existing `ApplySecrets` calls it and returns `.Content` (behaviour unchanged).
  - `public static IReadOnlyList<string> Redaction.Variants(string writtenForm)` (the form itself and its base64 and base64url, padded and unpadded; for a multi-line form also its `\r\n` form and that form's base64 and base64url, padded and unpadded: exactly the Redaction constraint's list), shared by `run` for both token kinds; reuse `RedactProcessor`'s variant code rather than duplicating it.
  - `internal sealed class FilledFiles : IDisposable` with `string Add(string sourcePath, string content)` (returns the filled copy's path, one copy per distinct source path) and `void SweepStale()` (an instance method on the same `FilledFilesEnvironment` record, of which the sweep uses time, stat and euid; the name generator, signal trigger and cleanup recorder serve `Add`, cleanup and the signal path); `Dispose` zeroes and deletes.

- [ ] **Step 1: Write the failing tests** (`RunFileTokenTests`, with the PTY runner faked as the existing run tests do — find their seam):
  - `RunFileToken_ChildGetsTheFilledFile` (the child's argv has a path; reading that path while the child runs gives the file with the markers filled, compared to `Apply.ApplySecrets` of the same input),
  - `RunFileToken_ChildOutputIsRedacted` (the fake child echoes the filled file: the output shows `[REDACTED: db-pw]`, never the value),
  - `RunFileToken_EscapedValueIsRedacted` (a value with `"` and `\`: neither the raw nor the escaped form appears in the output),
  - `RunFileToken_FolderIsPrivate` (Unix: folder `0700`, file `0600`, owner the user; Windows: skip with the reason),
  - `RunFileToken_FolderRemovedAfterSuccess` and `RunFileToken_ChildFails_FolderRemoved` (exit code passed through; folder gone; the file was zeroed before deletion — asserted through the cleanup recorder: for each filled file, a write of all zeros of its full length, then its deletion, in that order),
  - `RunFileToken_StaleFolders_Swept` (a `tswap-run-*` folder older than an hour is removed at start; a newer one is kept),
  - `RunFileToken_PathForms` (relative from a subdirectory, spaces, the same file twice → one copy, two files → two copies, mixed with a `{{name}}` token),
  - `RunFileToken_Refusals_WriteNothing` (missing file, no markers, a marker naming a missing secret, an unknown marker suffix: refused, no child started, no folder created),
  - `RunFileToken_BlocklistStillApplies` (`run sh -c "cat {{@f}}"` refused as today),
  - `RunFileToken_BurnedValueWarns` (stderr warning, as `apply` gives),
  - `RunFileToken_SingleQuotedAndDoubleQuotedFormsRedacted` (one secret written once as `"…"` and once as `'…'`, value containing `"`, `'` and `\`: none of the three forms appears in the output),
  - `RunFileToken_EncodersAndCopiersRefused` (theory over the new list, and `run bash {{@f}}`, `run {{@f}}`, `run python3 {{@f}}`: refused, no folder created),
  - `RunFileToken_ValueContainingFileTokenIsText` (a secret value `{{@/etc/passwd}}`: no second file is filled; the child gets the literal text),
  - `RunFileToken_SameBaseNameTwoFiles` (`a/values.yaml` and `b/values.yaml`: two distinct copies, each with its own content),
  - `RunFileToken_PrecreatedFolderOrSymlinkRefused` (through the injectable name generator: a pre-created `tswap-run-` path or a symlink at the first chosen name is never written through, a second name is used; through the injectable stat seam: a group-writable or foreign-owned `$XDG_RUNTIME_DIR` falls back to the temp root),
  - `RunFileToken_SweepSkipsLiveFolder` (a locked folder older than an hour is kept; an unlocked one is removed; both roots swept),
  - `RunFileToken_InterruptRemovesFolder` (a fake signal path: the child's process group is signalled, tswap waits for it, then the folder is gone; the exit code is the reaped child's), and `RunFileToken_RealSigint_RemovesFolder` (Unix: start the built tswap as a child process with `run sleep 30 {{@f}}`, send it SIGINT once the folder exists, assert exit code 130 and the folder gone; skipped on Windows with the reason),
  - `RunFileToken_AsRootRefused` (euid 0 seam: refused before anything is written),
  - `RunFileToken_EmptyOrNestedTokenRefused` (refused for that reason, before the "no tokens" check; also in a mixed command `helm upgrade app ./chart -f {{@va{lues}} {{name}}`),
  - `RunFileToken_Base64OfValueRedacted` (the fake child prints the base64 and base64url of a filled value, as `helm template` of a Secret does: shown as `[REDACTED: …]`),
  - `Run_NameToken_Base64Redacted` (the same for a plain `{{name}}` token: today's `run` gains it),
  - `RunFileToken_MultiLineValueRedacted` (a PEM-like multi-line value echoed with `\r\n` line ends and split across relay chunks: redacted; the base64 of its `\r\n` form, echoed by the child, redacted too; if RedactingPty can't match across chunks, stop with NEEDS_CONTEXT),
  - `RunFileToken_WrappersLookedThrough` (`env base64 {{@f}}`, `timeout 5 cat {{@f}}`, `nice -n 10 cp {{@f}} /tmp/x`, `env -u FOO base64 {{@f}}`, `xargs cat {{@f}}`, `busybox base64 {{@f}}`: refused, naming the word; `env FOO=1 helm template -f {{@f}}`: allowed),
  - `RunFileToken_InterpreterAnywhereRefused` (`python3 x.py {{@f}}`, `awk '{print}' {{@f}}`, `sed y/a/A/ {{@f}}`: refused),
  - `RunFileToken_WindowsFolderAclIsCurrentUserOnly` (Windows only; skipped elsewhere with the reason; it runs on CI's `windows-latest` leg, `.github/workflows/ci.yml`).
- [ ] **Step 2: Run them** (`dotnet test TswapTests --filter "FullyQualifiedName~RunFileToken"`) → fail to compile.
  (`RunFileToken_FolderIsPrivate` also asserts the folder is not a symlink and is owned by the user.)
- [ ] **Step 3: Implement.** In `RunCommand`: call `Validation.ValidateFileTokens` first; extract name tokens and file tokens; "no tokens" only when both are empty; resolve and fill every file (in memory) before creating anything on disk; then create the `FilledFiles` set, substitute both token kinds in argv, re-run the post-substitution blocklist, add, for every secret, each of its `WrittenForms` and every `Redaction.Variants` form of each (and of the raw value) to the replacements, run, dispose in `finally`. Create folder and file with their final modes at creation (`UnixCreateMode`).
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
