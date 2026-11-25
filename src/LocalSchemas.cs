using System.Net;
using System.Xml;
using System.Xml.Schema;

namespace Kalvin.SefazSp;

internal sealed class LocalSchemas(string directory) : XmlResolver
{
    private const long MaxSchemaSize = 5 * 1024 * 1024;
    private readonly string _directory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));

    public static void Validate(XmlDocument note, string directory)
    {
        var resolver = new LocalSchemas(directory);
        var root = new Uri(Path.Combine(resolver._directory, "nfe_v4.00.xsd"));
        var schemas = new XmlSchemaSet { XmlResolver = resolver };
        schemas.ValidationEventHandler += (_, _) => throw new ConnectorException("O conjunto de XSDs locais está inválido ou incompleto.");
        using var schemaFile = resolver.Open(root);
        using var schemaReader = XmlReader.Create(schemaFile, ReaderSettings(), root.AbsoluteUri);
        schemas.Add(FiscalXml.Namespace, schemaReader);
        schemas.Compile();

        using var source = new StringReader(note.OuterXml);
        var settings = ReaderSettings();
        settings.MaxCharactersInDocument = FiscalXml.MaxBytes;
        settings.Schemas = schemas;
        settings.ValidationType = ValidationType.Schema;
        settings.ValidationFlags = XmlSchemaValidationFlags.ReportValidationWarnings;
        settings.ValidationEventHandler += (_, args) =>
        {
            throw new ConnectorException($"XML incompatível com o XSD informado (linha {args.Exception.LineNumber}).");
        };
        using var reader = XmlReader.Create(source, settings);
        while (reader.Read()) { }
    }

    public override ICredentials? Credentials { set { } }

    public override object GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn) => Open(absoluteUri);

    private Stream Open(Uri uri)
    {
        var locationError = new ConnectorException("Os XSDs precisam ser arquivos locais na mesma pasta, sem links ou referências externas.");
        if (!uri.IsFile || uri.IsUnc || uri.Query.Length != 0 || uri.Fragment.Length != 0) throw locationError;
        var path = Path.GetFullPath(uri.LocalPath);
        if (!string.Equals(Path.GetDirectoryName(path), _directory,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)
            || !string.Equals(Path.GetExtension(path), ".xsd", StringComparison.OrdinalIgnoreCase)
            || IsLink(_directory) || IsLink(path))
        {
            throw locationError;
        }

        using var file = File.OpenRead(path);
        if (file.Length > MaxSchemaSize) throw new ConnectorException("Um arquivo XSD excede o tamanho aceito.");
        var checkedCopy = new MemoryStream((int)file.Length);
        try
        {
            file.CopyTo(checkedCopy);
            checkedCopy.Position = 0;
            using var reader = XmlReader.Create(checkedCopy, ReaderSettings());
            while (reader.Read()) { }
            checkedCopy.Position = 0;
            return checkedCopy;
        }
        catch
        {
            checkedCopy.Dispose();
            throw;
        }
    }

    private static bool IsLink(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static XmlReaderSettings ReaderSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = MaxSchemaSize,
    };
}
