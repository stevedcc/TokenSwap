namespace TswapCore.Keyring;

/// <summary>
/// Atomic, explicitly-flushed single-file write (issue #137, work item 1): write to a temp file
/// in the <b>same directory</b> as the target, force the data to durable storage, then rename
/// into place. Standalone infrastructure — this type has no dependency on any
/// <see cref="IVaultStore"/> or on the record wire format in <see cref="SecretRecordCodec"/>; it
/// operates on a plain directory, filename, and byte array so it can be dropped into whatever
/// store eventually reads/writes per-secret record files (issues #119/#124), without needing
/// that store to exist yet.
///
/// <para><b>Why a temp file in the same directory, not <see cref="Path.GetTempPath"/>:</b> a
/// cross-device rename is not atomic — most OSes silently fall back to copy-then-delete, which
/// reintroduces exactly the "torn write on crash" failure mode this class exists to avoid. Same
/// directory guarantees same filesystem/volume, so <see cref="File.Move(string, string, bool)"/>
/// is a single rename syscall.</para>
///
/// <para><b>Why <see cref="FileOptions.WriteThrough"/> <i>and</i>
/// <see cref="FileStream.Flush(bool)"/> with <c>flushToDisk: true</c>, not just one:</b>
/// <c>WriteThrough</c> alone is not honoured on every code path; <c>Flush(flushToDisk: true)</c>
/// is the portable guarantee — it becomes a real SMB2 FLUSH or an NFS COMMIT when the target is
/// a network share, not only a local <c>fsync</c>/<c>FlushFileBuffers</c>. Records are a few
/// hundred padded bytes written occasionally, so the write-through cost this normally buys you
/// out of does not apply here.</para>
///
/// <para><b>Why <see cref="File.Move(string, string, bool)"/> with <c>overwrite: true</c>, not
/// <see cref="File.Replace(string, string, string?)"/>:</b> <c>File.Replace</c> carries
/// backup-file semantics that some SMB servers implement badly or not at all. Plain rename is
/// the primitive every server handles correctly. (<c>File.Replace</c> may still be the right
/// choice elsewhere in this codebase, on paths that are known-local — this class only asserts
/// that record files, which may live on a synced/network directory, should not use it.)</para>
///
/// <para><b>What this is actually verified to do, and no more:</b> unit tests cover the
/// happy path only — write bytes, read them back, byte-exact (see
/// <c>TswapTests/DurableFileWriterTests.cs</c>). Durability under a killed process, a dropped
/// network mount mid-write, or a real SMB/NFS server's specific FLUSH/COMMIT behaviour is not
/// something an honest unit test can claim — see the parent issue's testing notes. This class
/// implements the documented portable pattern; it does not carry proof that pattern survives
/// every real transport's failure modes.</para>
/// </summary>
public static class DurableFileWriter
{
    /// <summary>
    /// Writes <paramref name="bytes"/> to <paramref name="targetFileName"/> inside
    /// <paramref name="directory"/>, atomically: temp file in the same directory, flushed to
    /// durable storage, then renamed over any existing file of that name.
    /// </summary>
    /// <param name="directory">
    /// The directory the record lives in. Must already exist — this method does not create it
    /// (directory creation is a store-level concern, not a write-primitive one).
    /// </param>
    /// <param name="targetFileName">
    /// Bare filename (no directory component) to write, e.g. a record's hex filename from
    /// <see cref="FilenameHasher.ToFilename"/>.
    /// </param>
    /// <param name="bytes">The exact bytes to write.</param>
    public static void WriteAtomic(DirectoryInfo directory, string targetFileName, byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentException.ThrowIfNullOrEmpty(targetFileName);
        ArgumentNullException.ThrowIfNull(bytes);

        if (!directory.Exists)
            throw new DirectoryNotFoundException($"Directory does not exist: {directory.FullName}");

        // Path.GetRandomFileName() produces the same short "8chars.3chars" shape
        // RecordDirectoryScanner recognises as tswap's own in-flight temp file (see that
        // class's TswapTempFile pattern) -- keep the two in sync if this ever changes.
        var tmpPath = Path.Combine(directory.FullName, Path.GetRandomFileName());
        var targetPath = Path.Combine(directory.FullName, targetFileName);

        try
        {
            using (var fs = new FileStream(tmpPath, new FileStreamOptions
                   {
                       Mode = FileMode.CreateNew,
                       Access = FileAccess.Write,
                       Options = FileOptions.WriteThrough,
                   }))
            {
                fs.Write(bytes);
                fs.Flush(flushToDisk: true); // FlushFileBuffers (Windows) / fsync (Unix)
            }

            File.Move(tmpPath, targetPath, overwrite: true);
        }
        catch
        {
            TryDeleteBestEffort(tmpPath);
            throw;
        }

        // Flushing the file does not flush the directory entry the rename above created.
        // Best-effort only -- see UnixDirectoryFsync's doc comment for why this can't be more
        // than that, and why there is no Windows equivalent.
        UnixDirectoryFsync.TryFsync(directory.FullName);
    }

    /// <summary>Convenience overload taking a directory path instead of a <see cref="DirectoryInfo"/>.</summary>
    public static void WriteAtomic(string directoryPath, string targetFileName, byte[] bytes)
        => WriteAtomic(new DirectoryInfo(directoryPath), targetFileName, bytes);

    private static void TryDeleteBestEffort(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best effort cleanup of a stray temp file after a failed write; the original
            // exception from the write/move above is what the caller needs to see, not this.
        }
    }
}
