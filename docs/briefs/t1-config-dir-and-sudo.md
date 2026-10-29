# Brief T1: tswap finds the right vault for a fresh user and under `sudo -u`, and `--help` never runs a command (#175, #176, #177)

Read AGENTS.md first and follow it. One commit per item, test first, and a break-it-once check per
item. Run the unit tests with `./runtests.sh --unit` after the last change of each item, and the
full `./runtests.sh` once at the end. Run no hardware suites (`Category=SecureEnclave`, `Tpm`,
`TpmWindows`). Never run a `sudo` command.

Another brief (T2, the TPM keyring) runs at the same time. It does not touch
`TswapCli/CliEnvironment.cs`, `TswapTests/CliEnvironmentTests.cs`, `CommandContext.cs` or
`CommandRegistry.cs`; this brief touches only those files, their tests and, if needed, README/AGENTS.md
lines about the config folder and help. T2 owns `InitCommand.cs`: #177's `init` half is in T2.

Both bugs were found on 2026-10-29 while verifying the Linux TPM backend on real hardware (#155,
results in the issue): a Fedora CoreOS 44 VM, with a new user created by `useradd -m`.

## Item 1: the config folder is always absolute (#175)

**What's wrong now.** `CliEnvironment.FromSystem` and the non-sudo branch of `ResolveConfigDir`
(`TswapCli/CliEnvironment.cs:27` and `:71-72`) call
`Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)`. With the default
`SpecialFolderOption.None`, .NET returns `""` when that folder does not exist. For a user without
`~/.config`, `Path.Combine("", "tswap")` is then the **relative** path `tswap`: `init` wrote
`~/tswap/config.json` (cwd was `~`), and the same user got "Not initialized" from any other folder.

**What to do.**
- The application-data folder comes from
  `Environment.GetFolderPath(SpecialFolder.ApplicationData, SpecialFolderOption.DoNotVerify)`.
  On Linux and macOS that returns `$XDG_CONFIG_HOME` or `$HOME/.config` whether or not it exists,
  and tswap already creates the `tswap` folder below it on `init`. Don't use
  `SpecialFolderOption.Create`: resolving a path must not create folders, because `names` runs
  without a vault too.
- `ResolveConfigDir` throws a `TswapException` with a clear message ("cannot determine the
  config folder: set HOME or TSWAP_CONFIG_DIR") if the folder it would return is not rooted
  (`Path.IsPathRooted`). That catches an empty `HOME` as well.
- `TSWAP_CONFIG_DIR` keeps overriding everything, unchanged. A relative `TSWAP_CONFIG_DIR` is
  the caller's choice; leave it alone.

**Tests** (`TswapTests/CliEnvironmentTests.cs`, through the existing `getApplicationDataDir`
seam):
1. The seam returns `""` → `TswapException` whose message names `TSWAP_CONFIG_DIR`.
2. The seam returns `/home/u/.config` → `/home/u/.config/tswap` (an existing case may cover this;
   keep it).
3. `FromSystem`'s default seam is `DoNotVerify`: test it in the cheapest honest way you find,
   for example by extracting the default lambda to a named static method and asserting that,
   with `HOME` pointing at a temp folder without `.config`, it returns a rooted path ending in
   `.config`. Don't change `HOME` for the whole test process; xUnit runs classes in parallel.

**Break-it-once.** Change `DoNotVerify` back to the plain call: test 3 must fail. Revert.

## Item 2: `SUDO_USER` only counts when the process is privileged (#176)

**What's wrong now.** `ResolveConfigDir` (`:60-69`) follows `SUDO_USER` whenever it is set, so
that `sudo tswap get` reads the invoking user's vault. `sudo -iu tswaptest tswap init --tpm`,
run by `core`, therefore tried `/home/core/.config/tswap` ("Access to the path ... is denied"),
because `SUDO_USER` still names the caller when sudo switches to a **non-root** user.

**What to do.**
- `ResolveConfigDir` takes a new parameter, `bool isPrivileged`. `FromSystem` passes
  `Environment.IsPrivilegedProcess`, the same check `CommandContext.RequireSudo` uses (`:70`).
- The `SUDO_USER` branch applies only when `isPrivileged` is true. Otherwise tswap uses the
  current user's folder (Item 1's resolution), whatever `SUDO_USER` says.
- Keep the parameter required (no default value), so every existing caller and test states it.
  Existing tests that exercise the `SUDO_USER` path pass `isPrivileged: true`: that is a new
  input the brief requires, not a changed assertion. Say so in the commit message.
- Update the doc comment's sudo bullet: "under sudo **to root**".

**Tests:**
1. `SUDO_USER=alice`, `isPrivileged: true` → alice's folder (`/home/alice/.config/tswap` on Linux).
2. `SUDO_USER=alice`, `isPrivileged: false` → the seam's folder, not alice's.
3. No `SUDO_USER`, `isPrivileged: true` (root logged in directly) → the seam's folder.

**Break-it-once.** Remove the `isPrivileged` condition: test 2 must fail. Revert.

## Item 3: `--help` prints usage and never runs the command (#177, the dispatch half)

**What's wrong now.** `CommandRegistry.Dispatch` (`TswapCli/CommandRegistry.cs:44-57`) prints the
help screen only for `tswap` with no arguments; `tswap --help` is "Unknown command: --help", and
`tswap init --help` passes `--help` to `init`, which ignores it and **starts a YubiKey
initialisation**. Read #177 in full.

**What to do** (in `Dispatch`, so it holds for every command):
- `tswap --help`, `tswap -h` and `tswap help` print the help screen and exit 0.
- `tswap <command> --help` or `-h` prints that command's `HelpUsage` and `Description` and exits 0
  **without calling `Execute`**. For every command except `run`, the flag counts anywhere in its
  arguments. For `run`, only directly after `run` (`tswap run --help`): everything after that is
  the child's command line, so `tswap run curl --help` still runs `curl --help`.

**Tests** (in-process, through the registry):
1. `init --help` exits 0, prints init's usage, and never reaches the hardware services: use a
   fake YubiKey/hardware service that fails the test if called.
2. `--help`, `-h` and `help` at the top level print the help screen and exit 0.
3. `get --help` exits 0 without sudo and without a vault (it must not even check).
4. `run true --help` runs the child (`true` with argument `--help`); `run --help` prints usage.
   Don't use `echo` as the child: `run`'s exfiltration check blocks it.

**Break-it-once.** Remove the per-command check: test 1 must fail (the fake is called). Revert.

## Out of scope
- The hard-coded `/home/<user>` and `/Users/<user>` for `SUDO_USER` (reading the passwd entry
  would be better; it works today on Fedora CoreOS because `/home` links to `/var/home`). Mention
  it in the report if you agree it is worth an issue; don't change it.
- Everything TPM, keyring or enrollment (brief T2), including `init` rejecting unknown flags
  (#177's other half, T2 item 4).
