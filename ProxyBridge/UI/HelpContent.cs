using System.Text;

namespace ProxyBridge;

internal sealed record HelpSection(string Title, string Body);

internal static class HelpContent
{
    // HELP.txt is the single source for the in-app help and the readable file
    // shipped in the payload. No network or external viewer is needed here.
    public static IReadOnlyList<HelpSection> Sections { get; } = Load();

    static IReadOnlyList<HelpSection> Load()
    {
        using var stream = typeof(HelpContent).Assembly.GetManifestResourceStream("ProxyBridge.Help.txt")
            ?? throw new InvalidOperationException("В сборке отсутствует встроенная справка ProxyBridge.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var sections = new List<HelpSection>();
        var body = new StringBuilder();
        string? title = null;

        void FinishSection()
        {
            if (title == null)
            {
                return;
            }

            string text = body.ToString().Trim();
            if (text.Length == 0)
            {
                throw new InvalidDataException("В справке найден пустой раздел.");
            }

            sections.Add(new(title, text));
            body.Clear();
        }

        while (reader.ReadLine() is { } line)
        {
            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                FinishSection();
                title = line[3..].Trim();
                if (title.Length == 0)
                {
                    throw new InvalidDataException("В справке найден раздел без названия.");
                }
            }
            else if (title != null)
            {
                body.AppendLine(line);
            }
            else if (!string.IsNullOrWhiteSpace(line))
            {
                throw new InvalidDataException("Справка должна начинаться с заголовка раздела.");
            }
        }
        FinishSection();
        if (sections.Count == 0)
        {
            throw new InvalidDataException("В справке нет разделов.");
        }

        return sections.AsReadOnly();
    }
}
