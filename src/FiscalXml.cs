using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Kalvin.SefazSp;

internal sealed class ConnectorException(string message) : Exception(message);

internal static class FiscalXml
{
    internal const string Namespace = "http://www.portalfiscal.inf.br/nfe";
    internal const string Version = "4.00";
    internal const string Environment = "2";
    internal const string SaoPaulo = "35";
    internal const int MaxBytes = 512_000;
    private const string SignatureNs = SignedXml.XmlDsigNamespaceUrl;

    public static XmlDocument Read(Stream stream)
    {
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxBytes,
        });
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.Load(reader);
        return document;
    }

    public static XmlDocument ReadNote(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > MaxBytes) throw new ConnectorException("O XML excede o limite de tamanho.");
        return Read(stream);
    }

    public static void Sign(XmlDocument document, X509Certificate2 certificate)
    {
        var (note, info, accessKey) = ValidateNote(document, signed: false);
        using var key = certificate.GetRSAPrivateKey()
            ?? throw new ConnectorException("Chave RSA privada indisponível para assinatura.");
        var signer = new SignedXml(document) { SigningKey = key };
        if (!ReferenceEquals(signer.GetIdElement(document, "NFe" + accessKey), info))
        {
            throw new ConnectorException("O identificador da NF-e é ambíguo.");
        }

        var signedInfo = signer.SignedInfo!;
        signedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
        signedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
        var reference = new Reference("#NFe" + accessKey) { DigestMethod = SignedXml.XmlDsigSHA1Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigC14NTransform());
        signer.AddReference(reference);
        signer.KeyInfo = new KeyInfo();
        signer.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
        signer.ComputeSignature();
        note.AppendChild(document.ImportNode(signer.GetXml(), deep: true));
        VerifySignedNote(document, certificate);
    }

    public static (XmlElement Note, string AccessKey) VerifySignedNote(XmlDocument document, X509Certificate2 certificate)
    {
        var (note, info, accessKey) = ValidateNote(document, signed: true);
        var signature = Child(note, "Signature", SignatureNs);
        var embedded = Child(Child(Child(signature, "KeyInfo", SignatureNs), "X509Data", SignatureNs), "X509Certificate", SignatureNs);
        if (!Convert.FromBase64String(embedded.InnerText).AsSpan().SequenceEqual(certificate.RawData))
        {
            throw new ConnectorException("O certificado do XML assinado difere do certificado informado.");
        }

        var verifier = new SignedXml(document);
        verifier.LoadXml(signature);
        ValidateSignature(verifier, accessKey);
        if (!ReferenceEquals(verifier.GetIdElement(document, "NFe" + accessKey), info) || !verifier.CheckSignature(certificate, verifySignatureOnly: true))
        {
            throw new ConnectorException("A assinatura da NF-e não confere com o XML e o certificado informados.");
        }

        return (note, accessKey);
    }

    private static void ValidateSignature(SignedXml verifier, string accessKey)
    {
        var signedInfo = verifier.SignedInfo!;
        var reference = signedInfo.References.Count == 1 ? signedInfo.References[0] as Reference : null;
        if (signedInfo.CanonicalizationMethod != SignedXml.XmlDsigC14NTransformUrl
            || signedInfo.SignatureMethod != SignedXml.XmlDsigRSASHA1Url
            || reference?.Uri != "#NFe" + accessKey
            || reference.DigestMethod != SignedXml.XmlDsigSHA1Url
            || reference.TransformChain.Count != 2
            || reference.TransformChain[0].Algorithm != SignedXml.XmlDsigEnvelopedSignatureTransformUrl
            || reference.TransformChain[1].Algorithm != SignedXml.XmlDsigC14NTransformUrl)
        {
            throw new ConnectorException("A assinatura não está no perfil XMLDSig da NF-e.");
        }
    }

    private static (XmlElement Note, XmlElement Info, string AccessKey) ValidateNote(XmlDocument document, bool signed)
    {
        var note = document.DocumentElement;
        if (note is null || note.LocalName != "NFe" || note.NamespaceURI != Namespace || note.Prefix.Length != 0)
        {
            throw new ConnectorException("Informe um XML unitário com elemento raiz NFe no namespace oficial.");
        }

        var info = Child(note, "infNFe");
        var elements = note.ChildNodes.OfType<XmlElement>().ToArray();
        if (info.GetAttribute("versao") != Version || elements.Length != (signed ? 2 : 1) || elements[0] != info
            || (signed && elements[1] != Child(note, "Signature", SignatureNs)))
        {
            throw new ConnectorException("O XML deve conter apenas infNFe 4.00, seguido da assinatura quando exigida.");
        }

        var identification = Child(info, "ide");
        if (Value(identification, "mod") != "55" || Value(identification, "cUF") != SaoPaulo
            || Value(identification, "tpAmb") != Environment || Value(identification, "tpEmis") != "1")
        {
            throw new ConnectorException("A integração aceita apenas NF-e modelo 55 de São Paulo, emissão normal e tpAmb 2.");
        }

        var id = info.GetAttribute("Id");
        var accessKey = id.StartsWith("NFe", StringComparison.Ordinal) ? id[3..] : "";
        if (!ValidAccessKey(accessKey)) throw new ConnectorException("A chave de acesso da NF-e é inválida.");
        if (!DateTimeOffset.TryParseExact(Value(identification, "dhEmi"), "yyyy-MM-dd'T'HH:mm:sszzz",
                CultureInfo.InvariantCulture, DateTimeStyles.None, out var issuedAt)
            || accessKey[2..6] != issuedAt.ToString("yyMM", CultureInfo.InvariantCulture)
            || accessKey[6..20] != Value(Child(info, "emit"), "CNPJ")
            || accessKey[22..25] != Value(identification, "serie").PadLeft(3, '0')
            || accessKey[25..34] != Value(identification, "nNF").PadLeft(9, '0')
            || accessKey[34] != '1'
            || accessKey[35..43] != Value(identification, "cNF")
            || accessKey[43..] != Value(identification, "cDV"))
        {
            throw new ConnectorException("A chave de acesso não corresponde aos campos do XML.");
        }
        return (note, info, accessKey);
    }

    public static bool ValidAccessKey(string key)
    {
        if (key.Length != 44 || !key.All(char.IsAsciiDigit) || !key.StartsWith(SaoPaulo, StringComparison.Ordinal) || key[20..22] != "55")
        {
            return false;
        }

        var sum = 0;
        for (var index = 42; index >= 0; index--)
        {
            sum += (key[index] - '0') * (2 + (42 - index) % 8);
        }
        var remainder = sum % 11;
        return key[43] - '0' == (remainder < 2 ? 0 : 11 - remainder);
    }

    public static void WriteNew(XmlDocument document, string path)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = XmlWriter.Create(stream, new XmlWriterSettings { Encoding = new UTF8Encoding(false) });
        document.WriteTo(writer);
    }

    public static XmlElement Child(XmlElement parent, string name, string ns = Namespace) =>
        OptionalChild(parent, name, ns) ?? throw new ConnectorException($"Elemento obrigatório ausente: {name}.");

    public static XmlElement? OptionalChild(XmlElement parent, string name, string ns = Namespace)
    {
        var elements = parent.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == name && e.NamespaceURI == ns).Take(2).ToArray();
        if (elements.Length > 1) throw new ConnectorException($"Elemento duplicado: {name}.");
        return elements.FirstOrDefault();
    }

    public static string Value(XmlElement parent, string name)
    {
        var child = Child(parent, name);
        if (child.ChildNodes.OfType<XmlElement>().Any()) throw new ConnectorException($"Elemento inválido: {name}.");
        return child.InnerText;
    }
}
