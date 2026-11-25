using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Schema;
using Kalvin.SefazSp;

const string Help = """
    Kalvin SEFAZ-SP | NF-e modelo 55 | homologação

    status (--pfx <arquivo> | --thumbprint <impressão-digital>)
    sign (--pfx <arquivo> | --thumbprint <impressão-digital>) --xml <entrada> --out <novo-arquivo>
    authorize (--pfx <arquivo> | --thumbprint <impressão-digital>) --xml <assinado> --schema-dir <pasta> --confirm-homologation
    protocol (--pfx <arquivo> | --thumbprint <impressão-digital>) --key <chave-de-acesso>

    authorize valida o XML com nfe_v4.00.xsd da pasta informada e transmite à homologação.
    """;

if (args.Length == 0 || args is ["--help"] or ["-h"])
{
    Console.WriteLine(Help);
    return 0;
}

var command = args[0];
var inputs = command switch
{
    "status" => Array.Empty<string>(),
    "sign" => ["--xml", "--out"],
    "authorize" => ["--xml", "--schema-dir", "--confirm-homologation"],
    "protocol" => ["--key"],
    _ => null,
};

try
{
    if (inputs is null) throw new ConnectorException("Comando desconhecido. Use --help.");
    var options = ParseOptions(args, inputs);
    var pfx = options.GetValueOrDefault("--pfx");
    var thumbprint = options.GetValueOrDefault("--thumbprint");

    var note = options.TryGetValue("--xml", out var xmlPath) ? FiscalXml.ReadNote(xmlPath) : null;
    if (command == "authorize") LocalSchemas.Validate(note!, options["--schema-dir"]);
    using var certificate = CertificateSource.Load(pfx, thumbprint, forTransport: command != "sign");
    if (command == "sign")
    {
        FiscalXml.Sign(note!, certificate);
        FiscalXml.WriteNew(note!, options["--out"]);
        Console.WriteLine("XML assinado localmente para homologação.");
        return 0;
    }

    using var http = SefazClient.CreateHttpClient(certificate);
    var client = new SefazClient(http);
    var result = command switch
    {
        "status" => await client.Status(),
        "authorize" => await client.Authorize(note!, certificate),
        "protocol" => await client.Protocol(options["--key"]),
        _ => throw new ConnectorException("Comando desconhecido. Use --help."),
    };
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        ambiente = "homologacao",
        cStat = result.Status,
        xMotivo = result.Reason,
        chNFe = result.AccessKey,
        nProt = result.Protocol,
        cStatLote = result.LotStatus,
    }));
    var successful = command switch
    {
        "status" => result.Status == 107,
        "authorize" => result.Status is 100 or 150 && result.LotStatus == 104,
        "protocol" => result.Status is 100 or 101 or 150 or 151 or 155,
        _ => false,
    };
    return successful ? 0 : 3;
}
catch (ConnectorException ex)
{
    Console.Error.WriteLine(ex.Message);
}
catch (XmlSchemaException)
{
    Console.Error.WriteLine("Não foi possível carregar os XSDs da NF-e. Confira se a pasta contém os arquivos oficiais completos.");
}
catch (Exception ex) when (ex is XmlException or FormatException)
{
    Console.Error.WriteLine("XML inválido ou conteúdo da assinatura incorreto.");
}
catch (CryptographicException)
{
    Console.Error.WriteLine("Falha criptográfica. Confira o certificado, a senha do PFX, a assinatura ou o driver do token.");
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
{
    Console.Error.WriteLine("Não foi possível abrir ou criar o arquivo. Confira os caminhos, permissões e se a saída já existe.");
}
catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
{
    Console.Error.WriteLine("A comunicação com a SEFAZ falhou ou excedeu o tempo limite. Confira o acesso e a cadeia do certificado.");
}

if (command == "authorize")
{
    Console.Error.WriteLine("Se houve falha após iniciar a transmissão, consulte a chave com protocol antes de qualquer reenvio.");
}
return 1;

static Dictionary<string, string> ParseOptions(string[] arguments, string[] required)
{
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = 1; i < arguments.Length; i++)
    {
        var name = arguments[i];
        if (!(name is "--pfx" or "--thumbprint") && !required.Contains(name, StringComparer.Ordinal))
        {
            throw new ConnectorException("Opção não reconhecida para este comando. Use --help.");
        }
        if (options.ContainsKey(name)) throw new ConnectorException("Uma opção foi informada mais de uma vez.");
        if (name == "--confirm-homologation")
        {
            options.Add(name, "");
            continue;
        }
        if (++i >= arguments.Length || arguments[i].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(arguments[i]))
        {
            throw new ConnectorException($"Informe um valor para {name}.");
        }
        options.Add(name, arguments[i]);
    }

    if (options.ContainsKey("--pfx") == options.ContainsKey("--thumbprint"))
    {
        throw new ConnectorException("Informe apenas uma origem do certificado, --pfx ou --thumbprint.");
    }
    foreach (var name in required)
    {
        if (!options.ContainsKey(name)) throw new ConnectorException($"Informe {name} para executar este comando.");
    }
    return options;
}
