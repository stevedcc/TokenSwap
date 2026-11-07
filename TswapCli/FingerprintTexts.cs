namespace TswapCli;

/// <summary>Brief T16-S2: how a command used the format 2 records it decoded whole (which warning text it prints).</summary>
internal enum FormatTwoUse
{
    /// <summary><c>names</c>, <c>list</c>, <c>burned</c>, <c>check</c>: read names and burn state only.</summary>
    Read,

    /// <summary><c>get</c>, <c>apply</c>: used some of the values.</summary>
    Substitute,
}

/// <summary>
/// Brief T16-S2: the texts about record fingerprints and the old record format 2. They live in the
/// CLI because the fix is written for this platform (<see cref="ElevatedCommand"/>). They carry a
/// count and the fix only, never a secret name (a format 2 tombstone's would reveal a deleted
/// secret), a hashed file name, a value, a length or a type: the count is what anyone listing the
/// vault folder can tell from the cleartext format byte.
/// </summary>
internal static class FingerprintTexts
{
    /// <summary>Writes the format 2 warning to <paramref name="error"/> when <paramref name="count"/> records were decoded whole.</summary>
    public static void WarnFormatTwo(TextWriter error, string prefix, int count, FormatTwoUse use)
    {
        if (count <= 0)
            return;
        var fix = ElevatedCommand.For(prefix, "vault reindex");
        error.WriteLine(use == FormatTwoUse.Read
            ? $"Warning: {count} record(s) are stored in the old record format 2, which keeps a secret's name and value in one " +
              "encrypted block, so tswap decrypted them whole to read their names and burn state and wiped the values without " +
              $"using them. Ask the user to run {fix} once to convert the vault."
            : $"Warning: {count} of the records used here are stored in the old record format 2, which tswap can only decrypt " +
              $"whole; the value versions not used were wiped. Ask the user to run {fix} once to convert the vault.");
    }
}
