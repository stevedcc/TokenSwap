using System;
using System.Collections.Generic;
using TswapCore;

var db = new SecretsDb(new Dictionary<string, Secret> {
    ["k8s-app-name"] = new Secret(
        "myapp",
        DateTime.UtcNow,
        DateTime.UtcNow,
        null,
        null
    )
});

var yaml = System.IO.File.ReadAllText("test_shell_yaml.yaml");

Console.WriteLine("=== BEFORE ===");
Console.WriteLine(yaml);

var (newContent, changes) = Redact.ToComment(yaml, db);

Console.WriteLine("\n=== AFTER ===");
Console.WriteLine(newContent);

Console.WriteLine("\n=== CHANGES ===");
Console.WriteLine($"Total changes: {changes.Count}");
foreach (var change in changes)
{
    Console.WriteLine($"Line {change.LineNumber}:");
    Console.WriteLine($"  Before: {change.Before}");
    Console.WriteLine($"  After:  {change.After}");
}
