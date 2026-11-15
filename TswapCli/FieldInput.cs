using System.Text;
using System.Text.Json;
using TswapCore;
using TswapCore.Fields;

namespace TswapCli;

/// <summary>
/// Issue #311, spec "Setting fields": the fields one call sets, in one of two equivalent forms (never both):
/// <c>FIELD=VALUE</c> pairs, split at the first <c>=</c>, or exactly one JSON argument or <c>@FILE</c> holding one
/// flat object whose values are strings or <c>null</c> (a removal). Checks the shape and the field names only;
/// the values are checked by the caller (<see cref="FieldRules.Validate"/>, the guard rails), all before
/// anything is written. Used by <c>field set</c> and by the value commands' <c>--field</c>/<c>--fields</c>.
/// </summary>
public static class FieldInput
{
    private const string UnsetHint = "use 'tswap field unset NAME FIELD' to remove a field";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The edits <paramref name="args"/> ask for, in the order given.</summary>
    /// <exception cref="TswapException">No fields, mixed forms, a malformed pair or object, or a refused field name.</exception>
    public static IReadOnlyList<FieldEdit> Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length == 0)
            throw new TswapException("No fields given: name them as FIELD=VALUE, or give one JSON object or @FILE.");
        if (args.Any(IsJsonForm))
        {
            if (args.Length > 1)
                throw new TswapException(
                    "Give the fields in one form: FIELD=VALUE pairs, or exactly one JSON object or @FILE, not both or several.");
            return ParseJson(args[0]);
        }
        return ParsePairs(args);
    }

    /// <summary>JSON (it starts with <c>{</c>, or <c>[</c> for the refusal) or <c>@FILE</c>; anything else is a <c>FIELD=VALUE</c> pair.</summary>
    private static bool IsJsonForm(string arg)
    {
        var text = arg.TrimStart('\ufeff').TrimStart();
        return text.StartsWith('{') || text.StartsWith('[') || arg.StartsWith('@');
    }

    private static List<FieldEdit> ParsePairs(string[] args)
    {
        List<FieldEdit> edits = [];
        HashSet<string> seen = [with(StringComparer.Ordinal)];
        foreach (var arg in args)
        {
            var eq = arg.IndexOf('=');
            if (eq < 0)
                throw new TswapException($"'{Shown(arg)}' is not FIELD=VALUE (a field is set as name=value).");
            var name = arg[..eq];
            var value = arg[(eq + 1)..];
            if (name.Length == 0)
                throw new TswapException($"'{Shown(arg)}' has no field name before '=' (a field is set as name=value).");
            CheckName(name);
            if (value.Length == 0)
                throw new TswapException($"Refused field '{name}': the value is empty; {UnsetHint}.");
            if (!seen.Add(name))
                throw new TswapException($"Field '{name}' is given twice; give each field once.");
            edits.Add(new FieldEdit(name, value));
        }
        return edits;
    }

    private static List<FieldEdit> ParseJson(string arg)
    {
        var text = arg.StartsWith('@') ? ReadFile(arg[1..]) : arg;
        text = text.TrimStart('\ufeff');
        JsonDocument document;
        try
        {
            // Duplicate keys are refused by the parser and, below, by name after unescaping.
            document = JsonDocument.Parse(text, new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException ex)
        {
            throw new TswapException($"The fields are not valid JSON: {ex.Message}");
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new TswapException("The fields must be one JSON object, e.g. {\"url\": \"https://example.org\"}.");
            List<FieldEdit> edits = [];
            HashSet<string> seen = [with(StringComparer.Ordinal)];
            foreach (var property in document.RootElement.EnumerateObject())
            {
                var name = property.Name;
                CheckName(name);
                if (!seen.Add(name))
                    throw new TswapException($"Field '{name}' is given twice; give each field once.");
                switch (property.Value.ValueKind)
                {
                    case JsonValueKind.Null:
                        edits.Add(new FieldEdit(name, null));
                        break;
                    case JsonValueKind.String:
                        var value = property.Value.GetString()!;
                        if (value.Length == 0)
                            throw new TswapException($"Refused field '{name}': the value is empty; use null, or 'tswap field unset NAME FIELD', to remove a field.");
                        edits.Add(new FieldEdit(name, value));
                        break;
                    default:
                        throw new TswapException(
                            $"Refused field '{name}': a value is a JSON string, or null to remove the field (not {Describe(property.Value.ValueKind)}).");
                }
            }
            return edits;
        }
    }

    private static string ReadFile(string path)
    {
        if (path.Length == 0)
            throw new TswapException("'@' names no file: give @FILE, e.g. @fields.json.");
        if (!File.Exists(path))
            throw new TswapException($"File not found: {path}");
        try
        {
            // A UTF-8 BOM is detected and dropped; bytes that aren't UTF-8 are refused, never replaced.
            return File.ReadAllText(path, StrictUtf8);
        }
        catch (DecoderFallbackException)
        {
            throw new TswapException($"{path} is not UTF-8 text.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new TswapException($"{path} can't be read: {ex.Message}");
        }
    }

    private static void CheckName(string name)
    {
        if (FieldRules.ValidateName(name) is { } refusal)
            throw new TswapException(refusal);
    }

    private static string Describe(JsonValueKind kind) => kind switch
    {
        JsonValueKind.Number => "a number",
        JsonValueKind.True or JsonValueKind.False => "a boolean",
        JsonValueKind.Array => "an array",
        JsonValueKind.Object => "an object",
        _ => kind.ToString().ToLowerInvariant(),
    };

    /// <summary>An argument for a message: printable ASCII as is, anything else as <c>U+XXXX</c>.</summary>
    private static string Shown(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
            builder.Append(c is >= ' ' and <= '~' ? c.ToString() : $"U+{(int)c:X4}");
        return builder.ToString();
    }
}
