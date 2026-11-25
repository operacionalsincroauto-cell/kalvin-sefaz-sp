using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Kalvin.SefazSp;

const string AccessKeyWithoutDigit = "3526101122233300018155001000000001112345678";
var sum = AccessKeyWithoutDigit.Reverse().Select((digit, index) => (digit - '0') * (2 + index % 8)).Sum();
var checkDigit = sum % 11 < 2 ? 0 : 11 - sum % 11;
var accessKey = AccessKeyWithoutDigit + checkDigit;
var unsigned = $"""
    <NFe xmlns="{FiscalXml.Namespace}"><infNFe Id="NFe{accessKey}" versao="4.00">
      <ide><cUF>35</cUF><cNF>12345678</cNF><mod>55</mod><serie>1</serie><nNF>1</nNF>
        <dhEmi>2026-10-19T12:00:00-03:00</dhEmi><tpEmis>1</tpEmis><cDV>{checkDigit}</cDV><tpAmb>2</tpAmb></ide>
      <emit><CNPJ>11222333000181</CNPJ></emit>
    </infNFe></NFe>
    """;

using var rsa = RSA.Create(2048);
using var certificate = new CertificateRequest("CN=Teste local", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
    .CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1));

var note = Parse(unsigned);
FiscalXml.Sign(note, certificate);
var signedNote = Parse(note.OuterXml);
Assert(FiscalXml.VerifySignedNote(signedNote, certificate).AccessKey == accessKey, "Assinatura local inválida.");
await Reject(() => Task.Run(() => FiscalXml.Sign(Parse(unsigned.Replace("<tpAmb>2", "<tpAmb>1")), certificate)));
await Reject(() => Task.Run(() => FiscalXml.Sign(Parse(unsigned.Replace("<mod>55", "<mod>65")), certificate)));
await Reject(() => Task.Run(() => FiscalXml.Sign(Parse(unsigned.Replace("<cUF>35", "<cUF>33")), certificate)));
await Reject(() => Task.Run(() => FiscalXml.Sign(Parse(unsigned.Replace("<nNF>1", "<nNF>2")), certificate)));
await Reject(() => Task.Run(() => FiscalXml.Sign(signedNote, certificate)));
await Reject(() => Task.Run(() => Parse("<!DOCTYPE NFe [<!ENTITY e SYSTEM 'file:///nope'>]><NFe>&e;</NFe>")));

var schemas = Directory.CreateTempSubdirectory("kalvin-sefaz-");
var rootSchemaPath = Path.Combine(schemas.FullName, "nfe_v4.00.xsd");
var localIncludePath = Path.Combine(schemas.FullName, "test-types.xsd");
const string XmlSchemaNs = "http://www.w3.org/2001/XMLSchema";
var testSchema = $"""
    <xs:schema xmlns:xs="{XmlSchemaNs}" xmlns:nfe="{FiscalXml.Namespace}" targetNamespace="{FiscalXml.Namespace}" elementFormDefault="qualified">
      <xs:include schemaLocation="test-types.xsd"/>
      <xs:element name="NFe" type="nfe:TestNote"/>
    </xs:schema>
    """;
try
{
    File.WriteAllText(rootSchemaPath, testSchema);
    File.WriteAllText(localIncludePath, $"""
        <xs:schema xmlns:xs="{XmlSchemaNs}" targetNamespace="{FiscalXml.Namespace}" elementFormDefault="qualified">
          <xs:complexType name="TestNote"><xs:sequence>
            <xs:element name="infNFe">
              <xs:complexType>
                <xs:sequence><xs:any processContents="skip" maxOccurs="unbounded"/></xs:sequence>
                <xs:anyAttribute processContents="skip"/>
              </xs:complexType>
            </xs:element>
            <xs:any namespace="{SignedXml.XmlDsigNamespaceUrl}" processContents="skip"/>
          </xs:sequence></xs:complexType>
        </xs:schema>
        """);
    LocalSchemas.Validate(signedNote, schemas.FullName);
    await Reject(() => Task.Run(() => LocalSchemas.Validate(Parse(unsigned), schemas.FullName)));
    File.WriteAllText(rootSchemaPath, testSchema.Replace("test-types.xsd", "https://example.invalid/test-types.xsd"));
    await Reject(() => Task.Run(() => LocalSchemas.Validate(signedNote, schemas.FullName)));
    File.WriteAllText(rootSchemaPath, testSchema.Replace("test-types.xsd", "../test-types.xsd"));
    await Reject(() => Task.Run(() => LocalSchemas.Validate(signedNote, schemas.FullName)));
}
finally
{
    File.Delete(rootSchemaPath);
    File.Delete(localIncludePath);
    schemas.Delete();
}

using var handler = new FakeHandler
{
    Reply = (service, request) =>
    {
        Assert(service == "NFeStatusServico4", "Método do status inesperado.");
        Assert(request.Contains("<tpAmb>2</tpAmb><cUF>35</cUF>"), "Ambiente/UF incorretos para o status.");
        return Envelope(service, "retConsStatServ", "<cUF>35</cUF><tpAmb>2</tpAmb><cStat>107</cStat><xMotivo>Em operação</xMotivo>");
    },
};
using var http = new HttpClient(handler);
var client = new SefazClient(http);
Assert((await client.Status()).Status == 107, "Resposta de status inválida.");

handler.Reply = (service, request) =>
{
    Assert(service == "NFeAutorizacao4", "Método de autorização inesperado.");
    Assert(request.Contains("<indSinc>1</indSinc>"), "Lote deve ser síncrono.");
    var embedded = Parse(request);
    var signature = (XmlElement)embedded.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]!;
    var xmlDsig = new SignedXml(embedded);
    xmlDsig.LoadXml(signature);
    Assert(xmlDsig.CheckSignature(certificate, verifySignatureOnly: true), "Assinatura alterada no envelope SOAP.");
    return Envelope(service, "retEnviNFe", $"<tpAmb>2</tpAmb><cStat>104</cStat><xMotivo>Lote processado</xMotivo>{Protocol()}");
};
var authorized = await client.Authorize(signedNote, certificate);
Assert(authorized is { Status: 100, LotStatus: 104, Protocol: "13526000000000001" }, "Autorização não foi interpretada.");

var calls = handler.Calls;
var modified = Parse(signedNote.OuterXml.Replace("2026-10-19T12:00:00", "2026-10-19T12:10:00"));
await Reject(() => client.Authorize(modified, certificate));
await Reject(() => client.Protocol("00000000000000000000000000000000000000000000"));
Assert(handler.Calls == calls, "A entrada inválida gerou uma requisição.");

handler.Reply = (service, request) =>
{
    Assert(service == "NFeConsultaProtocolo4", "Método de consulta inesperado.");
    Assert(request.Contains($"<chNFe>{accessKey}</chNFe>"), "Chave de consulta incorreta.");
    return Envelope(service, "retConsSitNFe", $"<tpAmb>2</tpAmb><cStat>100</cStat><xMotivo>Autorizado</xMotivo>{Protocol()}");
};
Assert((await client.Protocol(accessKey)).AccessKey == accessKey, "Resultado da consulta inválido.");

handler.Reply = (service, _) => Envelope(service, "retEnviNFe", $"<tpAmb>2</tpAmb><cStat>104</cStat><xMotivo>Lote processado</xMotivo>{Protocol("999999")}");
await Reject(() => client.Authorize(signedNote, certificate));
handler.Reply = (service, _) => Envelope(service, "retConsStatServ", "<cUF>35</cUF><tpAmb>1</tpAmb><cStat>107</cStat><xMotivo>Outro ambiente</xMotivo>");
await Reject(() => client.Status());

Console.WriteLine("OK: assinatura, XSD local, envelope SOAP, status, autorização, consulta e bloqueios de homologação.");

string Protocol(string? key = null) =>
    $"<protNFe versao=\"4.00\"><infProt><tpAmb>2</tpAmb><chNFe>{key ?? accessKey}</chNFe><nProt>13526000000000001</nProt><cStat>100</cStat><xMotivo>Autorizado</xMotivo></infProt></protNFe>";

static string Envelope(string service, string resultElement, string content) =>
    $"<soap12:Envelope xmlns:soap12=\"{SefazClient.SoapNs}\"><soap12:Body><nfeResultMsg xmlns=\"{SefazClient.WsdlBase}{service}\"><{resultElement} xmlns=\"{FiscalXml.Namespace}\" versao=\"4.00\">{content}</{resultElement}></nfeResultMsg></soap12:Body></soap12:Envelope>";

static XmlDocument Parse(string value)
{
    using var stream = new MemoryStream(Encoding.UTF8.GetBytes(value));
    return FiscalXml.Read(stream);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static async Task Reject(Func<Task> test)
{
    try
    {
        await test();
    }
    catch (Exception ex) when (ex is ConnectorException or XmlException)
    {
        return;
    }
    throw new Exception("A operação inválida deveria ter sido rejeitada.");
}

internal sealed class FakeHandler : HttpMessageHandler
{
    public required Func<string, string, string> Reply { get; set; }
    public int Calls { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var content = request.Content!;
        var contentType = content.Headers.ContentType;
        var action = contentType?.Parameters.Single(p => p.Name == "action").Value?.Trim('"')
            ?? throw new Exception("Action ausente.");
        var service = action.Split('/')[^2];
        if (uri.AbsoluteUri != $"{SefazClient.Host}/ws/{service.ToLowerInvariant()}.asmx"
            || request.Method != HttpMethod.Post || contentType?.MediaType != "application/soap+xml")
        {
            throw new Exception("Transporte SOAP inesperado.");
        }
        Calls++;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Reply(service, await content.ReadAsStringAsync(cancellationToken)), Encoding.UTF8, "application/soap+xml"),
        };
    }
}
