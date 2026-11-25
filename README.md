# Kalvin SEFAZ-SP

Conector de linha de comando para homologação de NF-e modelo 55 em São Paulo. Assina XML 4.00 com certificado local, consulta o serviço e envia uma única NF-e de teste mediante confirmação explícita. Use exclusivamente para testes sem valor fiscal.

## Requisitos

- SDK .NET 8 para compilar e executar a partir do código. A saída depende dos runtimes .NET e ASP.NET Core 8. Nenhum pacote NuGet adicional é necessário.
- Certificado ICP-Brasil vigente de emitente credenciado na SEFAZ-SP para testar a comunicação real.
- Para `authorize`, arquivos XSD do pacote vigente do Portal Nacional da NF-e. Extraia o ZIP localmente e indique a pasta que contém `nfe_v4.00.xsd` e os XSDs de que ele depende. As referências são resolvidas apenas nessa pasta. [Esquemas XML oficiais](https://www.nfe.fazenda.gov.br/portal/listaConteudo.aspx?tipoConteudo=BMPFMBoln3w%3D)

No **A1**, indique o caminho até um PFX local. Digite a senha no prompt sem eco. Para automação local, também é possível recebê-la por entrada padrão a partir de um gerenciador de segredos. Mantenha certificados fora do repositório. A assinatura local usa uma chave efêmera. Para o TLS no Windows, o Schannel utiliza um contêiner temporário de chave do usuário, descartado ao liberar o certificado no encerramento normal. [Microsoft Learn](https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting)

No **A3**, instale o middleware do fabricante no Windows e confira se o certificado com chave privada está visível em `Cert:\CurrentUser\My`. Passe a impressão digital como `--thumbprint`. O Windows e o middleware fazem a operação criptográfica e tratam diretamente o PIN. A compatibilidade depende do suporte do driver a assinatura RSA para NF-e e autenticação mútua TLS. A3 em nuvem exige middleware que exponha o certificado nesse repositório ou uma integração própria do provedor. Execute localmente na sessão do usuário que tem acesso ao dispositivo.

## Comandos

Execute na raiz deste pacote. Os caminhos abaixo são exemplos locais.

```text
dotnet run --project src -- status --pfx C:/certificados/empresa.pfx
dotnet run --project src -- status --thumbprint IMPRESSAO_DIGITAL
dotnet run --project src -- sign --pfx C:/certificados/empresa.pfx --xml nota-teste.xml --out nota-teste-assinada.xml
dotnet run --project src -- authorize --pfx C:/certificados/empresa.pfx --xml nota-teste-assinada.xml --schema-dir C:/schemas/nfe --confirm-homologation
dotnet run --project src -- protocol --pfx C:/certificados/empresa.pfx --key CHAVE_DE_ACESSO_DE_44_DIGITOS
```

- `status` consulta o ambiente homologado com autenticação mútua TLS. O código `107` indica operação do serviço.
- `sign` recebe apenas o XML unitário `NFe` 4.00 para SP, modelo 55, emissão normal e `tpAmb=2`. Gere o conteúdo fiscal previamente com o emissor. O conector confere os campos da chave, assina conforme o MOC e cria o arquivo de saída informado. Use dados de destinatário adequados à homologação.
- `authorize` verifica o XML com o XSD local e com o certificado informado, então transmite um lote síncrono com uma nota para a homologação. A confirmação `--confirm-homologation` é obrigatória. O resultado traz `cStat`, `xMotivo`, chave e protocolo quando recebidos. A autorização de teste corresponde a `cStatLote=104` e `cStat=100` ou `150`, com protocolo compatível. Se houver timeout ou resposta indefinida após a transmissão, consulte a chave antes de reenviar.
- `protocol` consulta a situação por uma chave válida de NF-e paulista. A chave identifica a nota e a consulta sempre usa homologação.

A CLI retorna `0` em caso de sucesso, `3` para um retorno SEFAZ fora dos estados de sucesso do comando e `1` em caso de erro local ou de comunicação. O conector usa apenas os [Web Services oficiais de homologação da SEFAZ-SP](https://portal.fazenda.sp.gov.br/servicos/nfe/Paginas/URL-WEBSERVICES.aspx). A [documentação técnica do MOC](https://www.nfe.fazenda.gov.br/portal/exibirArquivo.aspx?conteudo=LrBx7WT9PuA%3D) e as [Notas Técnicas vigentes](https://www.nfe.fazenda.gov.br/portal/listaConteudo.aspx?tipoConteudo=04BIflQt1aY%3D) descrevem o leiaute, a assinatura e o transporte.

A automação de pedidos, geração de conteúdo tributário, guarda de `nfeProc` e eventos fiscais pertencem à futura integração com o ERP. Para homologar no cliente, comece pela consulta de status com o certificado real e confira a autorização de uma NF-e de teste.

## Testes locais

```text
dotnet build src
dotnet run --project tests
```

Os testes usam certificado sintético, XSD reduzido para testar a resolução local e respostas SOAP simuladas, sem transmissão à SEFAZ.
