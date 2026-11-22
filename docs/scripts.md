# Passing secrets to scripts

`tswap run` hands a secret to the program it starts. When that program is a script, the script's own language
decides whether the value stays one piece of text or gets parsed as code. This page says, per shell, how to read a
value safely and the one thing that breaks it. The end-to-end tests named in each section check the behaviour with
the real binary and awkward values (quotes, `&`, `|`, `%`, `!`, `$`, backticks, spaces, line breaks, tswap's own
token syntax).

## How a value reaches a script

There are three ways, and none goes through a shell: tswap substitutes the value and starts the program directly.

| Way | Example | The script reads |
|---|---|---|
| One argument | `tswap run ./deploy.sh {{db-pw}}` | `"$1"` (or `$args[0]`, `%1`: see below) |
| The environment | `tswap run --env PGPASSWORD={{db-pw}} -- ./deploy.sh` | `"$PGPASSWORD"` |
| A file | `tswap run ./deploy.sh {{@values.yaml}}` | the filled copy's path, as `"$1"` |

Which to use:

- **An argument** is the simplest, but while the command runs, other local users can see it in the process list
  (on Linux `/proc/<pid>/cmdline`, unless `/proc` is mounted with `hidepid`).
- **The environment** isn't visible to other users, only to the same user and root
  ([who can read what](security-model.md#who-can-read-a-secret-run-hands-to-a-command)); see
  [`run --env`](commands.md#run---env). It is also the way to give a value to a Windows batch file (below).
- **A file** suits tools that read a config file; tswap writes a private copy and removes it when the command exits
  ([Files with secrets](security-model.md#files-with-secrets-run-with-file)).

Whichever you use, the calling shell never sees the value: only the token's own quoting matters there
([below](#the-calling-shell-doesnt-see-values)).

## bash

```bash
#!/usr/bin/env bash
psql "postgresql://app:$1@db/app"     # "$1", always in double quotes
```

Run it as `tswap run bash ./deploy.sh {{db-pw}}` (or `./deploy.sh` with its execute bit set). Quoted, `"$1"` is the
value as it is, whatever it holds.

What breaks it: `eval "$1"`, `source` or `.` with the value, `bash -c "$1"`, or an unquoted `$1`, which bash splits
at spaces and expands as a pattern (`*`, `?`). Each turns the value into code or into several words.

Tested by `EndToEndTests.Run_UnixShellScripts_EvilValues_ArriveExactly`.

## zsh

```zsh
#!/bin/zsh -f
curl -u "app:$1" https://api.example.com/   # "$1"
```

Run it as `tswap run zsh -f ./deploy.zsh {{db-pw}}`. Read `"$1"`. An unquoted `$1` isn't split in zsh by default
(unless `SH_WORD_SPLIT` is set), but quoting it costs nothing.

What breaks it: `eval "$1"` (and `source`, `zsh -c "$1"`), which run the value as code.

Tested by `EndToEndTests.Run_UnixShellScripts_EvilValues_ArriveExactly` (where zsh is installed: macOS has it).

## PowerShell (Windows PowerShell 5.1, and PowerShell 7 on Windows, Linux and macOS)

```powershell
# deploy.ps1
param($Password)            # or $args[0]
& psql "postgresql://app:$Password@db/app"
```

Run it with `-File`, always: `tswap run powershell -File .\deploy.ps1 '{{db-pw}}'` (or `pwsh -File`). With `-File`,
PowerShell passes each argument to the script as a string. PowerShell 7 (`pwsh`) works the same on Linux and macOS: `tswap run pwsh -File ./deploy.ps1
'{{db-pw}}'` (the tests below run on Windows; the rules are the same everywhere).

What breaks it:

- `Invoke-Expression` with the value, or `& ([scriptblock]::Create(...))`, which run it as code.
- Leaving out `-File`: `powershell .\deploy.ps1 ...` or `powershell -Command ...` reads the rest of the command line
  as PowerShell code, so the value is parsed too. `run` refuses `-Command` and `-EncodedCommand`; give `-File` every
  time.
- In a PowerShell window, an unquoted token: PowerShell reads `{...}` as a script block, so `tswap` never sees the
  token. Quote it: `'{{db-pw}}'` ([Windows notes](install.md#windows-notes)).

Tested by `EndToEndTests.Run_PowerShellFile_EvilValues_ArriveExactly_Windows` (both editions, in a console and with
output redirected).

## cmd and batch files

On Windows, `run` refuses to pass a secret to a batch file (`.cmd`, `.bat`) or to `cmd` itself when the value holds
a character cmd.exe interprets: one of `"` `&` `|` `<` `>` `^` `%` `!` `(` `)` or a line break. A batch file's
arguments are parsed again when it starts, and again by every `%1` inside the script; a value with such a character
can run as a command. tswap's generated values often contain them (`create` uses `! @ # $ % ^ & * ( ) - _ = +`), and
a value without a space or a quote reaches cmd.exe without any quotes at all. The check looks at every program the
command starts (`timeout 5 deploy.cmd`, `find . -exec deploy.cmd ...`, `powershell -File deploy.cmd`, `pwsh deploy.cmd`), at the
filled copy of a `{{@file}}` (whose name may hold `&` or `%`; when the temporary folder's path holds one, the refusal
says so: set `TMP` and `TEMP` to a folder without them), and names the secret, never the value. A program it
doesn't know runs a batch file out of its sight (`wrapper.exe deploy.cmd {{db-pw}}`): don't.

The way: pass the value in the environment, and read it with delayed expansion.

```bat
@echo off
rem deploy.cmd, run as: tswap run --env PW={{db-pw}} -- deploy.cmd
setlocal EnableDelayedExpansion
psql "postgresql://app:!PW!@db/app"
```

`!PW!` is expanded after cmd.exe has parsed the line, so the value is never read as command text. `--env` values
never reach the command line, so `run` allows them for a batch file.

What breaks it: `%PW%` or `%1` with a secret. Both are expanded before cmd.exe parses the line, so the value's `&`
or `|` runs a command. A `for /f` loop over the value has its own rules for `'` and backticks: that is the script's
business. Better still, write the script in PowerShell (above).

Tested by `EndToEndTests.Run_BatchFile_EvilValues_NeverInject_Windows` (the refusal) and
`EndToEndTests.Run_EnvWithDelayedExpansion_BatchCases_ArriveExactly_Windows` (the environment).

## Files that a shell sources

A filled `{{@file}}` copy is written literally. If a shell sources it (`source .env`, `. ./.env`), a value with
`$(...)`, a backtick or another `$` runs a command or expands there. A shell-sourced file needs single-quoted values
(`KEY=''`), and a value containing `'` breaks even that. Details: [Files with secrets](security-model.md#files-with-secrets-run-with-file).

## The calling shell doesn't see values

Tokens are substituted inside tswap, after the shell you type in has done its work, so no value ever passes
through it. Only the token's own quoting matters:

- **bash:** `{{db-pw}}` arrives unchanged, quoted or not (with `set -B`, the default, and with `shopt -s extglob`).
- **zsh:** `{{db-pw}}` arrives unchanged, unless `BRACE_CCL` is set: then zsh expands the unquoted braces to their
  characters, and tswap finds no token. With `BRACE_CCL`, quote tokens: `'{{db-pw}}'`.
- **PowerShell:** always quote tokens, `'{{db-pw}}'` (above).
- **cmd:** no quotes needed.

Tested by `EndToEndTests.Run_TheCallingShell_PassesTheTokenOn_UnlessZshBraceCcl`.
