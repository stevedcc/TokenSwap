namespace ConsoleIntercept;

/// <summary>
/// A find/replace pair applied to intercepted output: every occurrence of
/// <paramref name="Find"/> in the stream is replaced with <paramref name="Replace"/>
/// before the output reaches its destination. The caller decides what the
/// replacement looks like (e.g. <c>[REDACTED: name]</c> for secret masking).
/// </summary>
public sealed record StreamReplacement(string Find, string Replace);
