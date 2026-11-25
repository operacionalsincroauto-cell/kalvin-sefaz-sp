using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalvin.SefazSp;

internal static class CertificateSource
{
    public static X509Certificate2 Load(string? pfx, string? thumbprint, bool forTransport)
    {
        if (thumbprint is not null)
        {
            return ReadWindowsCertificate(thumbprint);
        }

        if (pfx is null || !File.Exists(pfx))
        {
            throw new ConnectorException("Arquivo PFX não encontrado.");
        }

        using var password = ReadPassword();
        // Windows Schannel cannot reliably use ephemeral keys for TLS. UserKeySet
        // without PersistKeySet leaves cleanup of the temporary key to certificate disposal.
        var storage = OperatingSystem.IsWindows() && forTransport
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        return Validate(new X509Certificate2(pfx, password, storage));
    }

    private static X509Certificate2 ReadWindowsCertificate(string thumbprint)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new ConnectorException("A opção --thumbprint requer o repositório de certificados do Windows.");
        }

        var normalized = new string(thumbprint.Where(c => !char.IsWhiteSpace(c) && c != '\u200e').ToArray());
        if (normalized.Length != 40 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ConnectorException("Informe a impressão digital do certificado com 40 caracteres hexadecimais.");
        }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
        if (matches.Count != 1)
        {
            foreach (var item in matches) item.Dispose();
            throw new ConnectorException("O certificado indicado não foi encontrado de forma única em CurrentUser\\My.");
        }

        return Validate(matches[0]);
    }

    private static X509Certificate2 Validate(X509Certificate2 certificate)
    {
        var now = DateTime.Now;
        if (!certificate.HasPrivateKey || now < certificate.NotBefore || now > certificate.NotAfter)
        {
            certificate.Dispose();
            throw new ConnectorException("É necessário um certificado dentro da validade e com chave privada acessível.");
        }

        using var publicKey = certificate.GetRSAPublicKey();
        if (publicKey is null)
        {
            certificate.Dispose();
            throw new ConnectorException("O certificado precisa ter uma chave RSA para a NF-e.");
        }

        return certificate;
    }

    private static SecureString ReadPassword()
    {
        var secret = new SecureString();
        try
        {
            if (Console.IsInputRedirected)
            {
                while (Console.In.Read() is var next && next != -1 && next != '\r' && next != '\n')
                {
                    AppendChar(secret, (char)next);
                }
            }
            else
            {
                Console.Error.Write("Senha do PFX (entrada oculta): ");
                while (Console.ReadKey(intercept: true) is var key && key.Key != ConsoleKey.Enter)
                {
                    if (key.Key == ConsoleKey.Backspace && secret.Length > 0)
                    {
                        secret.RemoveAt(secret.Length - 1);
                    }
                    else if (!char.IsControl(key.KeyChar))
                    {
                        AppendChar(secret, key.KeyChar);
                    }
                }
                Console.Error.WriteLine();
            }

            secret.MakeReadOnly();
            return secret;
        }
        catch
        {
            secret.Dispose();
            throw;
        }
    }

    private static void AppendChar(SecureString secret, char value)
    {
        if (secret.Length >= 1024) throw new ConnectorException("A senha informada é longa demais.");
        secret.AppendChar(value);
    }
}
