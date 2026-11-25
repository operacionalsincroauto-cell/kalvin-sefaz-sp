using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Kalvin.SefazSp;

internal sealed record ServiceResult(int Status, string Reason, string? AccessKey = null, string? Protocol = null, int? LotStatus = null);

internal sealed class SefazClient(HttpClient http)
{
    internal const string Host = "https://homologacao.nfe.fazenda.sp.gov.br";
    internal const string SoapNs = "http://www.w3.org/2003/05/soap-envelope";
    internal const string WsdlBase = FiscalXml.Namespace + "/wsdl/";

    public static HttpClient CreateHttpClient(X509Certificate2 certificate)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ClientCertificateOptions = ClientCertificateOption.Manual,
        };
        handler.ClientCertificates.Add(certificate);
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = FiscalXml.MaxBytes,
        };
    }

    public async Task<ServiceResult> Status()
    {
        var payload = $"<consStatServ xmlns=\"{FiscalXml.Namespace}\" versao=\"4.00\"><tpAmb>2</tpAmb><cUF>35</cUF><xServ>STATUS</xServ></consStatServ>";
        var response = await Call("NFeStatusServico4", "nfeStatusServicoNF", "retConsStatServ", payload);
        if (FiscalXml.Value(response, "cUF") != FiscalXml.SaoPaulo) throw new ConnectorException("UF inesperada na resposta.");
        return ReadResult(response);
    }

    public async Task<ServiceResult> Protocol(string accessKey)
    {
        if (!FiscalXml.ValidAccessKey(accessKey)) throw new ConnectorException("Informe uma chave válida da NF-e modelo 55 de São Paulo.");
        var payload = $"<consSitNFe xmlns=\"{FiscalXml.Namespace}\" versao=\"4.00\"><tpAmb>2</tpAmb><xServ>CONSULTAR</xServ><chNFe>{accessKey}</chNFe></consSitNFe>";
        var response = await Call("NFeConsultaProtocolo4", "nfeConsultaNF", "retConsSitNFe", payload);
        var result = ReadResult(response);
        var protocol = ReadProtocol(response, accessKey);
        if (result.Status is 100 or 150 && (protocol is null || protocol.Status is not (100 or 150)))
        {
            throw new ConnectorException("A resposta não trouxe um protocolo de autorização válido para a NF-e.");
        }
        return result with { AccessKey = protocol?.AccessKey, Protocol = protocol?.Protocol };
    }

    public async Task<ServiceResult> Authorize(XmlDocument document, X509Certificate2 certificate)
    {
        var (note, accessKey) = FiscalXml.VerifySignedNote(document, certificate);
        var lot = accessKey[28..43].TrimStart('0');
        if (lot.Length == 0) lot = "1";
        var payload = $"<enviNFe xmlns=\"{FiscalXml.Namespace}\" versao=\"4.00\"><idLote>{lot}</idLote><indSinc>1</indSinc>{note.OuterXml}</enviNFe>";
        var response = await Call("NFeAutorizacao4", "nfeAutorizacaoLote", "retEnviNFe", payload);
        var result = ReadResult(response);
        if (result.Status != 104) return result with { AccessKey = accessKey };
        var protocol = ReadProtocol(response, accessKey) ?? throw new ConnectorException("Lote processado sem retorno da NF-e.");
        return protocol with { AccessKey = accessKey, LotStatus = result.Status };
    }

    private async Task<XmlElement> Call(string service, string operation, string responseName, string payload)
    {
        var wsdl = WsdlBase + service;
        var body = $"<Envelope xmlns=\"{SoapNs}\"><Body><nfeDadosMsg xmlns=\"{wsdl}\">{payload}</nfeDadosMsg></Body></Envelope>";
        if (Encoding.UTF8.GetByteCount(body) > FiscalXml.MaxBytes) throw new ConnectorException("A mensagem SOAP excede o limite de tamanho.");
        using var content = new StringContent(body, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/soap+xml") { CharSet = "utf-8" };
        content.Headers.ContentType.Parameters.Add(new NameValueHeaderValue("action", $"\"{wsdl}/{operation}\""));
        using var response = await http.PostAsync($"{Host}/ws/{service.ToLowerInvariant()}.asmx", content);
        if (!response.IsSuccessStatusCode) throw new ConnectorException($"A SEFAZ respondeu com HTTP {(int)response.StatusCode}.");

        await using var stream = await response.Content.ReadAsStreamAsync();
        var root = FiscalXml.Read(stream).DocumentElement;
        if (root is null || root.LocalName != "Envelope" || root.NamespaceURI != SoapNs)
        {
            throw new ConnectorException("Resposta SOAP 1.2 inválida.");
        }
        var responseBody = FiscalXml.Child(root, "Body", SoapNs);
        var wrapper = FiscalXml.OptionalChild(responseBody, operation + "Response", wsdl) ?? responseBody;
        var result = FiscalXml.Child(FiscalXml.Child(wrapper, "nfeResultMsg", wsdl), responseName);
        if (result.GetAttribute("versao") != FiscalXml.Version) throw new ConnectorException("Versão inesperada na resposta da SEFAZ.");
        return result;
    }

    private static ServiceResult? ReadProtocol(XmlElement response, string expectedAccessKey)
    {
        var protocol = FiscalXml.OptionalChild(response, "protNFe");
        if (protocol is null) return null;
        var info = FiscalXml.Child(protocol, "infProt");
        var accessKey = FiscalXml.Value(info, "chNFe");
        if (accessKey != expectedAccessKey) throw new ConnectorException("A chave da resposta não corresponde à NF-e consultada.");
        var result = ReadResult(info);
        var number = FiscalXml.OptionalChild(info, "nProt")?.InnerText;
        if (result.Status is 100 or 150 && (number is null || number.Length is not (15 or 17) || !number.All(char.IsAsciiDigit)))
        {
            throw new ConnectorException("A SEFAZ informou a autorização sem um número de protocolo válido.");
        }
        return result with { AccessKey = accessKey, Protocol = number };
    }

    private static ServiceResult ReadResult(XmlElement response)
    {
        if (FiscalXml.Value(response, "tpAmb") != FiscalXml.Environment) throw new ConnectorException("Ambiente inesperado na resposta da SEFAZ.");
        var value = FiscalXml.Value(response, "cStat");
        if (value.Length is not (3 or 4) || !value.All(char.IsAsciiDigit) || !int.TryParse(value, out var status))
        {
            throw new ConnectorException("A resposta não contém um cStat válido.");
        }
        var reason = new string(FiscalXml.Value(response, "xMotivo").Where(c => !char.IsControl(c)).Take(500).ToArray());
        return new ServiceResult(status, reason);
    }
}
