using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TswapCore;
using TswapCore.Keyring;

namespace TswapCli.Commands;

/// <summary>
/// Brief T28 test seams of <c>slot approve|merge --staged</c> (in the style of <c>RequestHooks</c>): what a same-user
/// process on the host could do to the staging folder between two steps.
/// </summary>
public sealed class StagedFileSeams
{
    /// <summary>Called with the staged file's path once it is read into its buffer and its hash matched, before it is parsed.</summary>
    public Action<string>? AfterHashChecked { get; init; }

    /// <summary>Called with <c>approve.json</c>'s path once <c>approve --staged</c> has written it, before its fingerprint is printed.</summary>
    public Action<string>? AfterApproveWritten { get; init; }
}

/// <summary>
/// Brief T28: the host's staging folder of an interactive <c>slot enrol --via</c>, <c>&lt;config dir&gt;/enrol-staged/&lt;id&gt;/</c>
/// (the SSH user's; under sudo <see cref="CliEnvironment"/> resolves the same folder from <c>SUDO_USER</c>). The files
/// travel through it on batch-form SSH calls (<c>slot stage &lt;id&gt; put|get|clean</c>, never under sudo, so they stay
/// the user's), while approve and merge run on a terminal of their own (<c>ssh -t</c>), so sudo and the vault can ask
/// there. <c>--expect &lt;sha256&gt;</c> binds what the joining machine sent: the staged file is read once, its buffer
/// hashed and compared, and that buffer parsed (A1). The approve file coming back is bound only by the fingerprint the
/// person compares (A3): a human check, as the hand-carried flow's.
/// </summary>
public sealed partial class SlotCommand
{
    private const string StagedFolderName = "enrol-staged";

    [GeneratedRegex("^[0-9a-f]{8}$")]
    private static partial Regex StagedIdPattern();

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex ExpectPattern();

    /// <summary>The help forms of <c>slot stage</c>, shared by <see cref="Forms"/> and its own usage.</summary>
    private static string StageForm => "slot stage <id> put request|receipt | slot stage <id> get approve | slot stage <id> clean";

    /// <summary>The help form of the staged approve and merge.</summary>
    private const string StagedApproveForm = "slot approve --staged <id> --expect <sha256-hex>";
    private const string StagedMergeForm = "slot merge --staged <id> --expect <sha256-hex>";

    private static bool IsStagedId(string id) => StagedIdPattern().IsMatch(id);

    /// <summary>The staging folder for <paramref name="id"/> in this user's config folder (resolved as for any command).</summary>
    private static string StagedFolder(CommandContext ctx, string id) => Path.Combine(ctx.Env.ConfigDir, StagedFolderName, id);

    /// <summary>
    /// A3: the fingerprint of an approve file's exact bytes, in <see cref="SlotFingerprint"/>'s style (the SHA-256's first 8
    /// bytes, upper-case hex in groups of 4). One helper for the host's line and the joining machine's, so the two lines are
    /// byte-identical when the files are.
    /// </summary>
    internal static string ApproveFileFingerprint(byte[] approveBytes) => SlotFingerprint.Compute(approveBytes);

    private static int ExecuteStage(CommandContext ctx, string[] args)
    {
        var usage = $"{ctx.Prefix} " + StageForm.Replace(" | ", $" | {ctx.Prefix} ");
        var (id, verb, what) = args switch
        {
            [var i, "put", "request" or "receipt"] => (i, "put", args[2]),
            [var i, "get", "approve"] => (i, "get", "approve"),
            [var i, "clean"] => (i, "clean", ""),
            _ => throw new UsageException(usage),
        };
        if (!IsStagedId(id))
            throw new UsageException(usage + "\n<id> is the enrolment's 8 lower-case hex characters.");
        // A8: the files must be the SSH user's, so 'sudo tswap slot stage' (a real escalation) is refused; a root login is the user.
        if (ctx.Env.SudoEscalated)
            throw new TswapException("slot stage runs as the SSH user, not under sudo.");

        var folder = StagedFolder(ctx, id);
        switch (verb)
        {
            case "put":
            {
                var fileWhat = what == "request" ? "request file" : "receipt";
                if (!ctx.Console.IsInputRedirected)
                    throw new TswapException(
                        $"slot stage: put reads the {fileWhat} from stdin, and stdin is a terminal here. Pipe the file in.");
                var text = ReadBoundedStdin(ctx, "slot stage", fileWhat);
                CreatePrivateFolder(Path.GetDirectoryName(folder)!, folder);
                // Verbatim (A1): the bytes the joining machine sent and hashed, no newline, BOM or line-ending change.
                ctx.WriteOutputFile(Path.Combine(folder, what == "request" ? RequestFileName : ReceiptFileName), Encoding.UTF8.GetBytes(text));
                return 0;
            }
            case "get":
            {
                var path = Path.Combine(folder, ApproveFileName);
                if (!File.Exists(path))
                    throw new TswapException($"No staged approve file for {id} in {folder}. Nothing was changed.");
                var bytes = File.ReadAllBytes(path);
                try
                {
                    ctx.Console.Out.Write(Encoding.UTF8.GetString(bytes));
                    ctx.Console.Out.Flush();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
                return 0;
            }
            default:
                if (Directory.Exists(folder))
                    Directory.Delete(folder, recursive: true);
                return 0;
        }
    }

    /// <summary>
    /// A2/A4: takes <c>--staged &lt;id&gt;</c> and <c>--expect &lt;sha256&gt;</c> out of <paramref name="args"/>. Both or
    /// neither; with them, no positional file, <c>-</c> or <see cref="RecoveryKeyFlag"/>. Every refusal is a usage error,
    /// before sudo and any read.
    /// </summary>
    private static (string[] Remaining, string? Id, string? Expect) SplitStaged(string[] args, string stagedUsage)
    {
        (args, var id) = TakeOption(args, "--staged", stagedUsage);
        (args, var expect) = TakeOption(args, "--expect", stagedUsage);
        if (id is null && expect is null)
            return (args, null, null);
        if (id is null || expect is null || !IsStagedId(id) || !ExpectPattern().IsMatch(expect))
            throw new UsageException(stagedUsage +
                "\n--staged and --expect go together: <id> is the enrolment's 8 lower-case hex characters, <sha256-hex> 64 lower-case hex characters.");
        return (args, id, expect);
    }

    /// <summary>
    /// A1: the staged <paramref name="fileName"/> of <paramref name="id"/>, read once into a buffer; the buffer's SHA-256 is
    /// compared with <paramref name="expect"/> (ordinal, lower-case hex) and that buffer, never the path again, is returned
    /// as text for the caller to parse. A6: an absent file has its own message, naming the folder looked in.
    /// </summary>
    private static (string Text, string Folder) ReadStaged(CommandContext ctx, string id, string expect, string fileName, string what, string verb)
    {
        var folder = StagedFolder(ctx, id);
        var path = Path.Combine(folder, fileName);
        var owner = (ctx.Storage as IFileVaultStore)?.Owner ?? DirectoryOwnerMatcher.Default;
        if (!owner.FileExists(path))
            throw new TswapException(
                $"No staged {what} for {id} in {folder}. If the SSH user sets TSWAP_CONFIG_DIR or XDG_CONFIG_HOME, sudo doesn't " +
                $"see it: see docs/multi-machine.md#enrolling-over-ssh. Nothing was {verb}.");
        var bytes = owner.ReadAllBytes(path);
        if (bytes.Length > MaxStdinFileSize)
            throw new TswapException($"The staged {what} is larger than 1 MiB, so it is not a {what}. Nothing was {verb}.");
        if (!string.Equals(Convert.ToHexStringLower(SHA256.HashData(bytes)), expect, StringComparison.Ordinal))
            throw new TswapException($"The staged {what} isn't the one the joining machine sent (its SHA-256 differs). Nothing was {verb}.");
        ctx.StagedSeams?.AfterHashChecked?.Invoke(path);
        return (Encoding.UTF8.GetString(bytes), folder);
    }

    /// <summary>Makes <paramref name="root"/> and <paramref name="folder"/> below it, 0700 on Unix (inside the config folder on Windows).</summary>
    private static void CreatePrivateFolder(string root, string folder)
    {
        if (OperatingSystem.IsWindows())
            Directory.CreateDirectory(folder);
        else
        {
            const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(root, Private);
            Directory.CreateDirectory(folder, Private);
        }
    }
}
