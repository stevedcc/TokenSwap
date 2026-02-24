# PR #50 Review: Route diagnostic output to stderr

## Summary

The change is well-motivated and correct in principle. Routing diagnostic output to
`Console.Error` follows standard Unix conventions and is the right fix to make commands
like `tswap apply values.yaml > output.yaml` and `helm upgrade -f <(tswap apply
values.yaml)` work cleanly.

---

## What's correct

**Core stderr routing** — All `Console.WriteLine` → `Console.Error.WriteLine` changes in
`CmdToComment` (Program.cs, tswap.cs) and `WarnIfNoTouch` (YubiKey.cs) are correct.

**Continuation-line suppression** — The new logic in `CmdToComment` to suppress
unredactable base64 fragments (setting `After = ""`) rather than printing them verbatim
is a sound security improvement. It correctly addresses the partial-match redaction
limitation.

**tswap.cs parity** — The PR also backfills the redaction logic that was added to
`Program.cs` in #49 but was never applied to `tswap.cs`. This fixes a security
inconsistency between the two entry points.

**YubiKey.cs emoji fix** — `⚠️` was already replaced by `[!]` in `tswap.cs` (PR #48) but
`TswapCore/YubiKey.cs` was missed. This PR corrects that.

---

## Bugs: three tests assert against the wrong stream

`RunTswap` separates stdout and stderr (both are captured independently via
`RedirectStandardOutput` / `RedirectStandardError`). All `CmdToComment` diff output is
now routed to `Console.Error.WriteLine`, which means it appears in **stderr**, not
stdout. The three new tests discard stderr (`var (exit, stdout, _) = …`) and then assert
that diagnostic strings appear in `stdout` — they will all fail.

### `ToComment_DryRun_DoesNotExposeSecretInOutput`

```csharp
// BUG: both strings are now written to Console.Error.WriteLine
var (exit, stdout, _) = RunTswap("tocomment", yamlFile, "--dry-run");
Assert.Contains("[REDACTED: my-password]", stdout);   // will be empty
Assert.Contains("# tswap: my-password", stdout);      // will be empty
```

Fix: capture stderr and assert against it.

```csharp
var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");
Assert.DoesNotContain("supersecretvalue123", stdout);
Assert.DoesNotContain("supersecretvalue123", stderr);
Assert.Contains("[REDACTED: my-password]", stderr);
Assert.Contains("# tswap: my-password", stderr);
```

### `ToComment_Live_DoesNotExposeSecretInOutput`

```csharp
// BUG: diff output is in stderr, not stdout
var (exit, stdout, _) = RunTswap("tocomment", yamlFile);
Assert.Contains("[REDACTED: my-password]", stdout);   // will be empty
```

Fix: same pattern — capture and assert against `stderr`.

### `ToComment_ContinuationLine_DoesNotLeakFragmentInOutput`

```csharp
// BUG: placeholder is written to Console.Error.WriteLine
var (exit, stdout, _) = RunTswap("tocomment", yamlFile, "--dry-run");
Assert.Contains("[removed continuation line]", stdout);  // will be empty
```

Fix:

```csharp
var (exit, stdout, stderr) = RunTswap("tocomment", yamlFile, "--dry-run");
Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stdout);
Assert.DoesNotContain("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", stderr);
Assert.Contains("[removed continuation line]", stderr);
Assert.DoesNotContain("supersecretvalue123", stdout);
Assert.DoesNotContain("supersecretvalue123", stderr);
```

---

## Minor observation: `Apply_DiagnosticsGoToStderr_NotStdout` is vacuous

The test cannot generate a YubiKey warning (no real hardware), so the assertions about
box-drawing characters being absent from stdout always pass regardless of whether the fix
is present. The test is harmless but provides no signal about the feature it claims to
test. Consider documenting this explicitly (a comment already partially does so) or
removing the YubiKey-specific assertions.

---

## Verdict

**Request changes** — the core logic is correct, but the three test bugs mean the tests
will fail and, more importantly, they give false confidence: they pass vacuously (empty
stdout) rather than actually verifying that diagnostic content moved to stderr. Fix the
assertions to target `stderr` before merging.
