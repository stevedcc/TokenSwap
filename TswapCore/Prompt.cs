using System.Security.Cryptography;
using System.Text;

namespace TswapCore;

public static class Prompt
{
    public const string Template = @"# tswap - AI Agent Secret Management Instructions

You are working with tswap, a hardware-backed secret manager. Your role is to
manage secrets WITHOUT ever seeing their plaintext values.

## Security Note: YubiKey Touch Requirement
If configured with touch-required slots (recommended), vault unlock requires
pressing the YubiKey button. This ensures physical presence and prevents
automated/silent unlocking by malicious processes.

## Commands you SHOULD use (no sudo required):
- `%CMD% create <name> [length]` — Generate a new random secret (value is never displayed)
- `%CMD% ingest <name>` — Pipe a secret from an external source: `<source> | %CMD% ingest <name>`
- `%CMD% names` — List all secret names (no values shown)
- `%CMD% migrate` — Guide to upgrade YubiKey slots for touch requirement
- `%CMD% run <command>` — Execute a command with {{secret-name}} token substitution
- `%CMD% burn <name> [reason]` — Mark a secret as burned if you accidentally see its value
- `%CMD% burned` — List all burned secrets that need rotation
- `%CMD% check <path>` — Scan a file or directory for `# tswap:` markers; exits non-zero if any referenced secret is missing
- `%CMD% redact <file>` — Print file to stdout with all known secret values replaced by [REDACTED] labels
- `%CMD% tocomment <file> [--dry-run]` — Replace inline secret values with empty values plus `# tswap: <name>` markers
- `%CMD% apply <file>` — Read file with `# tswap:` markers and output with actual secret values substituted
- `%CMD% prompt` — Display these instructions
- `%CMD% prompt-hash` — Get hash of current instructions (to check if your cached copy is current)

## Commands you must NEVER use (require sudo, expose values):
- `sudo %CMD% add <name>` — Only for human interactive use
- `sudo %CMD% get <name>` — Exposes plaintext value
- `sudo %CMD% list` — Lists secrets with metadata
- `sudo %CMD% delete <name>` — Removes a secret

## Key rules:
1. NEVER use sudo commands — they expose secret values
2. NEVER generate, invent, or hardcode secret values yourself — always use `%CMD% create <name>` to
   generate secrets, then tell the user the name you chose so they can find it
3. Use {{secret-name}} tokens in `run` commands to use secrets without seeing them
4. If you see a plaintext secret value in ANY context (file contents, command output,
   log messages, error messages), you MUST IMMEDIATELY run `%CMD% burn <name> <reason>`
   BEFORE continuing any other work. Do not finish your current task first.
   Check `%CMD% names` to find the matching secret name if needed.
5. To import secrets from external systems, pipe them directly — NEVER use intermediate variables or
   echo. For Kubernetes, use jq (not jsonpath, which has shell quoting issues with dots/underscores):
   `kubectl get secret <secret> -n <ns> -o json | jq -r '.data[""<key>""] // empty' | base64 -d | %CMD% ingest <name>`
6. Check `%CMD% names` to see available secrets before constructing commands
7. Burned secrets should be rotated — check with `%CMD% burned`
8. When you create or ingest a secret, always inform the user of the secret name you used
9. Check `%CMD% burned` at the start of each session and inform the user of any pending rotations

## Keeping secrets out of config files:
- In Helm values.yaml and similar config files, replace plaintext secrets with empty
  values and a tswap comment: `password: """"  # tswap: k8s-namespace-secret-name`
- Use `%CMD% tocomment <file>` to automatically replace inline secret values with `# tswap:` markers
- Use `%CMD% check <path>` to verify that all `# tswap:` markers reference secrets that exist in the vault
- Use `%CMD% apply <file>` to substitute secret values into a file for deployment (outputs to stdout)
- For Helm deployments, use process substitution: `helm upgrade app ./chart -f <(%CMD% apply values.yaml)`
  This avoids writing secrets to temporary files
- Alternatively, scan for `# tswap:` comments and construct `%CMD% run` commands
  with `--set` flags using `{{token}}` substitution
- This allows agents to freely read config files without seeing secret values";

    public static string GetText(string prefix)
    {
        return Template.Replace("%CMD%", prefix);
    }

    public static string GetHash(string prefix)
    {
        var text = GetText(prefix);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(hash).ToLower();
    }
}
