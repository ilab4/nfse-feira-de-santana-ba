<?php
/**
 * =============================================================================
 * ILAB4.ME
 * NFSe - ABRASF 2.02 - WebISS Feira de Santana/BA
 * Gerar, Consultar e Cancelar
 * =============================================================================
 * 
 * INSTRUÇÕES:
 * 1. Coloque este arquivo na raiz do seu servidor web (htdocs/www)
 * 2. Coloque o certificado digital .pfx na mesma pasta
 * 3. Preencha as configurações abaixo
 * 4. Acesse http://localhost/nfse.php
 * 
 * REQUISITOS: PHP 7.4+, extensões openssl e curl habilitadas
 * =============================================================================
 */

// ======================== CONFIGURAÇÕES ========================
$config = [
    'ambiente'          => 'producao',
    'url_producao'      => 'https://feiradesantanaba.webiss.com.br/ws/nfse.asmx',
    'url_homologacao'   => 'https://homologacao.webiss.com.br/ws/nfse.asmx',
    'certificado_pfx'   => 'certificates/certificado.pfx',
    'certificado_senha' => 'senha-do-certificado',
    'prestador_cnpj'    => 'cnpj-da-empresa',
    'prestador_im'      => 'inscrição-municipal-da-empresa',
    'rps_numero'        => '1',
    'rps_serie'         => 'A1',
    'rps_tipo'          => '1',
    'valor_servicos'    => '1.00',
    'aliquota_iss'      => '0.0500',
    'item_lista'        => '1706',
    'codigo_cnae'       => '4759899',
    'codigo_tributacao'  => '1706',
    'discriminacao'     => 'Servico de teste - desenvolvimento de software',
    'codigo_municipio'  => '2910800',
    'exigibilidade_iss' => '1',
    'municipio_incidencia' => '2910800',
    'iss_retido'        => '2',
    'optante_simples'   => '2',
    'incentivo_fiscal'  => '2',
    'tomador_cnpj'      => '99999999999',
    'tomador_razao'     => 'JOSE DA SILVA',
    'tomador_endereco'  => 'Rua Exemplo',
    'tomador_numero'    => '100',
    'tomador_bairro'    => 'Centro',
    'tomador_cep'       => '44001000',
    'tomador_uf'        => 'BA',
    'tomador_cod_mun'   => '2910800',
    'tomador_email'     => 'tomador@email.com',
    'tomador_telefone'  => '7530001234',
    // Cancelamento
    'cancelar_numero_nfse' => '',
    'cancelar_codigo'      => '1', // 1=Erro emissão, 2=Serviço não prestado, 3=Duplicidade, 4=Erro assinatura
    // Consulta por RPS
    'consultar_rps_numero' => '',
    'consultar_rps_serie'  => 'A1',
    'consultar_rps_tipo'   => '1',
];

// ======================== FUNÇÕES ========================

/**
 * Extrai certificado e chave privada do .pfx
 */
function extrairCertificado($pfxPath, $senha) {
    if (!file_exists($pfxPath)) {
        throw new Exception("Arquivo de certificado não encontrado: $pfxPath");
    }
    $pfxContent = file_get_contents($pfxPath);
    $certs = [];
    if (!openssl_pkcs12_read($pfxContent, $certs, $senha)) {
        throw new Exception("Erro ao ler certificado PFX. Verifique a senha. OpenSSL: " . openssl_error_string());
    }
    $certPem = tempnam(sys_get_temp_dir(), 'cert_');
    $keyPem  = tempnam(sys_get_temp_dir(), 'key_');
    file_put_contents($certPem, $certs['cert']);
    file_put_contents($keyPem, $certs['pkey']);
    return [
        'cert'     => $certs['cert'],
        'pkey'     => $certs['pkey'],
        'certFile' => $certPem,
        'keyFile'  => $keyPem,
    ];
}

/**
 * Assina XML com certificado digital (XML-DSig)
 */
function assinarXml($xml, $certPem, $pkeyPem, $tagToSign = 'InfDeclaracaoPrestacaoServico') {
    $doc = new DOMDocument('1.0', 'UTF-8');
    $doc->preserveWhiteSpace = false;
    $doc->formatOutput = false;
    $doc->loadXML($xml);

    $node = $doc->getElementsByTagName($tagToSign)->item(0);
    if (!$node) {
        throw new Exception("Tag '$tagToSign' não encontrada no XML para assinatura.");
    }

    $id = $node->getAttribute('Id');
    if (empty($id)) {
        $id = 'rps' . uniqid();
        $node->setAttribute('Id', $id);
    }

    $canonicalizado = $node->C14N(false, false, null, null);
    $digestValue = base64_encode(hash('sha1', $canonicalizado, true));

    $signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        . '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        . '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        . '<Reference URI="#' . $id . '">'
        . '<Transforms>'
        . '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        . '<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        . '</Transforms>'
        . '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        . '<DigestValue>' . $digestValue . '</DigestValue>'
        . '</Reference>'
        . '</SignedInfo>';

    $docSI = new DOMDocument('1.0', 'UTF-8');
    $docSI->loadXML($signedInfo);
    $signedInfoCanon = $docSI->documentElement->C14N(false, false, null, null);

    $privateKey = openssl_pkey_get_private($pkeyPem);
    if (!$privateKey) {
        throw new Exception("Erro ao carregar chave privada: " . openssl_error_string());
    }

    $signature = '';
    if (!openssl_sign($signedInfoCanon, $signature, $privateKey, OPENSSL_ALGO_SHA1)) {
        throw new Exception("Erro ao assinar: " . openssl_error_string());
    }
    $signatureValue = base64_encode($signature);

    $x509 = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $certPem);

    $signatureXml = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
        . $signedInfo
        . '<SignatureValue>' . $signatureValue . '</SignatureValue>'
        . '<KeyInfo>'
        . '<X509Data>'
        . '<X509Certificate>' . $x509 . '</X509Certificate>'
        . '</X509Data>'
        . '</KeyInfo>'
        . '</Signature>';

    $docSig = new DOMDocument('1.0', 'UTF-8');
    $docSig->loadXML($signatureXml);
    $signatureNode = $doc->importNode($docSig->documentElement, true);
    $node->parentNode->appendChild($signatureNode);

    return $doc->saveXML($doc->documentElement);
}

/**
 * Monta XML GerarNfseEnvio
 */
function montarXmlGerarNfse($config) {
    $ns = 'http://www.abrasf.org.br/nfse.xsd';
    $dataEmissao = date('Y-m-d');
    $competencia = date('Y-m-d');

    $xml  = '<GerarNfseEnvio xmlns="' . $ns . '">';
    $xml .= '<Rps>';
    $xml .= '<InfDeclaracaoPrestacaoServico Id="rps' . $config['rps_numero'] . '">';

    $xml .= '<Rps>';
    $xml .= '<IdentificacaoRps>';
    $xml .= '<Numero>' . $config['rps_numero'] . '</Numero>';
    $xml .= '<Serie>' . $config['rps_serie'] . '</Serie>';
    $xml .= '<Tipo>' . $config['rps_tipo'] . '</Tipo>';
    $xml .= '</IdentificacaoRps>';
    $xml .= '<DataEmissao>' . $dataEmissao . '</DataEmissao>';
    $xml .= '<Status>1</Status>';
    $xml .= '</Rps>';

    $xml .= '<Competencia>' . $competencia . '</Competencia>';

    $xml .= '<Servico>';
    $xml .= '<Valores>';
    $xml .= '<ValorServicos>' . $config['valor_servicos'] . '</ValorServicos>';

    // E221: Alíquota só deve ser informada quando:
    // 1. ISS retido (IssRetido=1) em prestador Simples Nacional, OU
    // 2. ISS devido a outro município (MunicipioIncidencia != município do prestador)
    $deveEnviarAliquota = false;
    if ($config['iss_retido'] == '1' && $config['optante_simples'] == '1') {
        $deveEnviarAliquota = true;
    }
    if (!empty($config['municipio_incidencia']) && $config['municipio_incidencia'] != $config['codigo_municipio']) {
        $deveEnviarAliquota = true;
    }
    if ($deveEnviarAliquota && !empty($config['aliquota_iss'])) {
        $xml .= '<Aliquota>' . $config['aliquota_iss'] . '</Aliquota>';
    }

    $xml .= '</Valores>';
    $xml .= '<IssRetido>' . $config['iss_retido'] . '</IssRetido>';
    $xml .= '<ItemListaServico>' . $config['item_lista'] . '</ItemListaServico>';
    if (!empty($config['codigo_cnae'])) {
        $xml .= '<CodigoCnae>' . $config['codigo_cnae'] . '</CodigoCnae>';
    }
    if (!empty($config['codigo_tributacao'])) {
        $xml .= '<CodigoTributacaoMunicipio>' . $config['codigo_tributacao'] . '</CodigoTributacaoMunicipio>';
    }
    $xml .= '<Discriminacao>' . htmlspecialchars($config['discriminacao']) . '</Discriminacao>';
    $xml .= '<CodigoMunicipio>' . $config['codigo_municipio'] . '</CodigoMunicipio>';
    $xml .= '<ExigibilidadeISS>' . $config['exigibilidade_iss'] . '</ExigibilidadeISS>';
    if (!empty($config['municipio_incidencia'])) {
        $xml .= '<MunicipioIncidencia>' . $config['municipio_incidencia'] . '</MunicipioIncidencia>';
    }
    $xml .= '</Servico>';

    $xml .= '<Prestador>';
    $xml .= '<CpfCnpj><Cnpj>' . $config['prestador_cnpj'] . '</Cnpj></CpfCnpj>';
    if (!empty($config['prestador_im'])) {
        $xml .= '<InscricaoMunicipal>' . $config['prestador_im'] . '</InscricaoMunicipal>';
    }
    $xml .= '</Prestador>';

    if (!empty($config['tomador_cnpj'])) {
        $xml .= '<Tomador>';
        $xml .= '<IdentificacaoTomador>';
        $xml .= '<CpfCnpj>';
        if (strlen($config['tomador_cnpj']) == 14) {
            $xml .= '<Cnpj>' . $config['tomador_cnpj'] . '</Cnpj>';
        } else {
            $xml .= '<Cpf>' . $config['tomador_cnpj'] . '</Cpf>';
        }
        $xml .= '</CpfCnpj>';
        $xml .= '</IdentificacaoTomador>';
        $xml .= '<RazaoSocial>' . htmlspecialchars($config['tomador_razao']) . '</RazaoSocial>';
        $xml .= '<Endereco>';
        $xml .= '<Endereco>' . htmlspecialchars($config['tomador_endereco']) . '</Endereco>';
        $xml .= '<Numero>' . $config['tomador_numero'] . '</Numero>';
        $xml .= '<Bairro>' . htmlspecialchars($config['tomador_bairro']) . '</Bairro>';
        $xml .= '<CodigoMunicipio>' . $config['tomador_cod_mun'] . '</CodigoMunicipio>';
        $xml .= '<Uf>' . $config['tomador_uf'] . '</Uf>';
        $xml .= '<Cep>' . $config['tomador_cep'] . '</Cep>';
        $xml .= '</Endereco>';
        $xml .= '<Contato>';
        if (!empty($config['tomador_telefone'])) {
            $xml .= '<Telefone>' . $config['tomador_telefone'] . '</Telefone>';
        }
        if (!empty($config['tomador_email'])) {
            $xml .= '<Email>' . $config['tomador_email'] . '</Email>';
        }
        $xml .= '</Contato>';
        $xml .= '</Tomador>';
    }

    $xml .= '<OptanteSimplesNacional>' . $config['optante_simples'] . '</OptanteSimplesNacional>';
    $xml .= '<IncentivoFiscal>' . $config['incentivo_fiscal'] . '</IncentivoFiscal>';

    $xml .= '</InfDeclaracaoPrestacaoServico>';
    $xml .= '</Rps>';
    $xml .= '</GerarNfseEnvio>';

    return $xml;
}

/**
 * Monta XML ConsultarNfseRpsEnvio
 */
function montarXmlConsultarRps($config) {
    $ns = 'http://www.abrasf.org.br/nfse.xsd';
    $xml  = '<ConsultarNfseRpsEnvio xmlns="' . $ns . '">';
    $xml .= '<IdentificacaoRps>';
    $xml .= '<Numero>' . $config['consultar_rps_numero'] . '</Numero>';
    $xml .= '<Serie>' . $config['consultar_rps_serie'] . '</Serie>';
    $xml .= '<Tipo>' . $config['consultar_rps_tipo'] . '</Tipo>';
    $xml .= '</IdentificacaoRps>';
    $xml .= '<Prestador>';
    $xml .= '<CpfCnpj><Cnpj>' . $config['prestador_cnpj'] . '</Cnpj></CpfCnpj>';
    if (!empty($config['prestador_im'])) {
        $xml .= '<InscricaoMunicipal>' . $config['prestador_im'] . '</InscricaoMunicipal>';
    }
    $xml .= '</Prestador>';
    $xml .= '</ConsultarNfseRpsEnvio>';
    return $xml;
}

/**
 * Monta XML CancelarNfseEnvio
 */
function montarXmlCancelarNfse($config) {
    $ns = 'http://www.abrasf.org.br/nfse.xsd';
    $xml  = '<CancelarNfseEnvio xmlns="' . $ns . '">';
    $xml .= '<Pedido>';
    $xml .= '<InfPedidoCancelamento Id="cancel' . $config['cancelar_numero_nfse'] . '">';
    $xml .= '<IdentificacaoNfse>';
    $xml .= '<Numero>' . $config['cancelar_numero_nfse'] . '</Numero>';
    $xml .= '<CpfCnpj><Cnpj>' . $config['prestador_cnpj'] . '</Cnpj></CpfCnpj>';
    if (!empty($config['prestador_im'])) {
        $xml .= '<InscricaoMunicipal>' . $config['prestador_im'] . '</InscricaoMunicipal>';
    }
    $xml .= '<CodigoMunicipio>' . $config['codigo_municipio'] . '</CodigoMunicipio>';
    $xml .= '</IdentificacaoNfse>';
    $xml .= '<CodigoCancelamento>' . $config['cancelar_codigo'] . '</CodigoCancelamento>';
    $xml .= '</InfPedidoCancelamento>';
    $xml .= '</Pedido>';
    $xml .= '</CancelarNfseEnvio>';
    return $xml;
}

/**
 * Monta o cabeçalho XML (nfseCabecMsg)
 */
function montarCabecalho() {
    return '<cabecalho xmlns="http://www.abrasf.org.br/nfse.xsd" versao="2.02">'
         . '<versaoDados>2.02</versaoDados>'
         . '</cabecalho>';
}

/**
 * Envia requisição SOAP via cURL
 * 
 * FORMATO CORRETO PARA WebISS (.asmx):
 * - Request no namespace http://nfse.abrasf.org.br
 * - nfseCabecMsg e nfseDadosMsg com xmlns="" (sem namespace)
 * - Conteúdo como string pura (não CDATA, não XML-escaped)
 */
function enviarSoap($url, $cabecalho, $dados, $certFile, $keyFile, $operacao = 'GerarNfse') {
    $soapAction = "http://nfse.abrasf.org.br/$operacao";

    // FORMATO EXATO conforme documentação WebISS .asmx:
    // Os parâmetros nfseCabecMsg e nfseDadosMsg devem ter xmlns=""
    // e o conteúdo deve ser string (o .asmx faz o parse)
    $soapEnvelope = '<?xml version="1.0" encoding="utf-8"?>'
        . '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        . 'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        . 'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        . '<soap:Body>'
        . '<' . $operacao . 'Request xmlns="http://nfse.abrasf.org.br">'
        . '<nfseCabecMsg xmlns="">' . htmlspecialchars($cabecalho, ENT_XML1, 'UTF-8') . '</nfseCabecMsg>'
        . '<nfseDadosMsg xmlns="">' . htmlspecialchars($dados, ENT_XML1, 'UTF-8') . '</nfseDadosMsg>'
        . '</' . $operacao . 'Request>'
        . '</soap:Body>'
        . '</soap:Envelope>';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $soapEnvelope,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: text/xml; charset=utf-8',
            'SOAPAction: "' . $soapAction . '"',
            'Content-Length: ' . strlen($soapEnvelope),
        ],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_SSLCERT        => $certFile,
        CURLOPT_SSLKEY         => $keyFile,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_CONNECTTIMEOUT => 30,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error    = curl_error($ch);
    $errno    = curl_errno($ch);
    curl_close($ch);

    return [
        'response'  => $response,
        'http_code' => $httpCode,
        'error'     => $error,
        'errno'     => $errno,
        'request'   => $soapEnvelope,
    ];
}

/**
 * Formata XML para exibição
 */
function formatarXml($xml) {
    if (empty($xml)) return '';
    $doc = new DOMDocument('1.0', 'UTF-8');
    $doc->preserveWhiteSpace = false;
    $doc->formatOutput = true;
    @$doc->loadXML($xml);
    return $doc->saveXML();
}

/**
 * Extrai conteúdo da resposta SOAP
 */
function extrairRespostaSoap($soapResponse) {
    if (empty($soapResponse)) return '';
    $doc = new DOMDocument();
    @$doc->loadXML($soapResponse);

    // Tentar outputXML
    $outputs = $doc->getElementsByTagName('outputXML');
    if ($outputs->length > 0) {
        $content = $outputs->item(0)->nodeValue;
        if (!empty(trim($content))) return $content;
    }

    // Tentar *Result (GerarNfseResult, CancelarNfseResult, etc)
    foreach (['GerarNfseResult', 'CancelarNfseResult', 'ConsultarNfsePorRpsResult',
              'ConsultarNfseServicoPrestadoResult', 'ConsultarNfseServicoTomadoResult'] as $tag) {
        $results = $doc->getElementsByTagName($tag);
        if ($results->length > 0) {
            $content = $results->item(0)->nodeValue;
            if (!empty(trim($content))) return $content;
        }
    }

    // Tentar *Resposta
    foreach (['GerarNfseResposta', 'CancelarNfseResposta', 'ConsultarNfseRpsResposta',
              'ConsultarNfseServicoPrestadoResposta'] as $tag) {
        $results = $doc->getElementsByTagName($tag);
        if ($results->length > 0) {
            return $doc->saveXML($results->item(0));
        }
    }

    // Body
    $body = $doc->getElementsByTagNameNS('http://schemas.xmlsoap.org/soap/envelope/', 'Body');
    if ($body->length > 0) {
        return $doc->saveXML($body->item(0));
    }

    return $soapResponse;
}

/**
 * Analisa erros da resposta NFSe
 */
function analisarErrosResposta($xmlResposta) {
    $erros = [];
    if (empty($xmlResposta)) return $erros;
    $doc = new DOMDocument();
    @$doc->loadXML($xmlResposta);
    $mensagens = $doc->getElementsByTagName('MensagemRetorno');
    foreach ($mensagens as $msg) {
        $codigo = $mensagem = $correcao = '';
        $codNode = $msg->getElementsByTagName('Codigo')->item(0);
        if ($codNode) $codigo = $codNode->nodeValue;
        $msgNode = $msg->getElementsByTagName('Mensagem')->item(0);
        if ($msgNode) $mensagem = $msgNode->nodeValue;
        $corNode = $msg->getElementsByTagName('Correcao')->item(0);
        if ($corNode) $correcao = $corNode->nodeValue;
        $erros[] = ['codigo' => $codigo, 'mensagem' => $mensagem, 'correcao' => $correcao];
    }
    return $erros;
}

/**
 * Verifica se resposta contém NFSe gerada com sucesso
 */
function extrairDadosNfse($xmlResposta) {
    if (empty($xmlResposta)) return null;
    $doc = new DOMDocument();
    @$doc->loadXML($xmlResposta);
    $nfse = $doc->getElementsByTagName('Nfse')->item(0);
    if (!$nfse) return null;
    $dados = [];
    $tags = ['Numero', 'CodigoVerificacao', 'DataEmissao', 'ValorLiquidoNfse', 'BaseCalculo', 'ValorIss'];
    foreach ($tags as $tag) {
        $el = $doc->getElementsByTagName($tag)->item(0);
        $dados[$tag] = $el ? $el->nodeValue : '';
    }
    return $dados;
}

// ======================== PROCESSAMENTO ========================

$resultado = null;
$erro = null;
$xmlEnviado = '';
$xmlResposta = '';
$xmlRespostaFormatado = '';
$soapEnvelopeEnviado = '';
$errosNfse = [];
$dadosNfse = null;
$operacaoExecutada = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Atualizar config com dados do formulário
        foreach ($_POST as $key => $value) {
            if (isset($config[$key]) && !in_array($key, ['emitir', 'consultar', 'cancelar'])) {
                $config[$key] = trim($value);
            }
        }

        // Extrair certificado
        $cert = extrairCertificado($config['certificado_pfx'], $config['certificado_senha']);

        // Determinar URL
        $url = ($config['ambiente'] === 'producao') ? $config['url_producao'] : $config['url_homologacao'];

        // Cabeçalho
        $cabecalho = montarCabecalho();

        // ---- GERAR NFSe ----
        if (isset($_POST['emitir'])) {
            $operacaoExecutada = 'GerarNfse';
            $xmlDados = montarXmlGerarNfse($config);
            $xmlAssinado = assinarXml($xmlDados, $cert['cert'], $cert['pkey'], 'InfDeclaracaoPrestacaoServico');
            $xmlEnviado = $xmlAssinado;
            $result = enviarSoap($url, $cabecalho, $xmlAssinado, $cert['certFile'], $cert['keyFile'], 'GerarNfse');
        }
        // ---- CONSULTAR POR RPS ----
        elseif (isset($_POST['consultar'])) {
            $operacaoExecutada = 'ConsultarNfsePorRps';
            $xmlDados = montarXmlConsultarRps($config);
            $xmlEnviado = $xmlDados;
            $result = enviarSoap($url, $cabecalho, $xmlDados, $cert['certFile'], $cert['keyFile'], 'ConsultarNfsePorRps');
        }
        // ---- CANCELAR NFSe ----
        elseif (isset($_POST['cancelar'])) {
            $operacaoExecutada = 'CancelarNfse';
            $xmlDados = montarXmlCancelarNfse($config);
            $xmlAssinado = assinarXml($xmlDados, $cert['cert'], $cert['pkey'], 'InfPedidoCancelamento');
            $xmlEnviado = $xmlAssinado;
            $result = enviarSoap($url, $cabecalho, $xmlAssinado, $cert['certFile'], $cert['keyFile'], 'CancelarNfse');
        }

        // Limpar temporários
        @unlink($cert['certFile']);
        @unlink($cert['keyFile']);

        // Processar resposta
        if ($result['errno'] !== 0) {
            $erro = "Erro cURL ({$result['errno']}): {$result['error']}";
        } else {
            $soapEnvelopeEnviado = $result['request'];
            $xmlResposta = $result['response'];
            $conteudoResposta = extrairRespostaSoap($xmlResposta);
            $xmlRespostaFormatado = formatarXml($conteudoResposta);

            $errosNfse = analisarErrosResposta($conteudoResposta);
            if (empty($errosNfse)) {
                $errosNfse = analisarErrosResposta($xmlResposta);
            }

            $dadosNfse = extrairDadosNfse($conteudoResposta);
            if (!$dadosNfse) {
                $dadosNfse = extrairDadosNfse($xmlResposta);
            }

            if ($result['http_code'] !== 200) {
                $erro = "HTTP {$result['http_code']}";
            }

            $resultado = ['http_code' => $result['http_code'], 'conteudo' => $conteudoResposta];
        }
    } catch (Exception $e) {
        $erro = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>NFSe - ABRASF 2.02 - Feira de Santana/BA</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; padding: 20px; }
        .container { max-width: 960px; margin: 0 auto; }
        h1 { color: #1a5276; margin-bottom: 5px; font-size: 22px; }
        .subtitle { color: #666; margin-bottom: 20px; font-size: 13px; }
        .card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { color: #2c3e50; font-size: 16px; margin-bottom: 12px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
        .field { margin-bottom: 8px; }
        .field label { display: block; font-size: 12px; color: #555; margin-bottom: 2px; font-weight: 600; }
        .field input, .field select, .field textarea { width: 100%; padding: 7px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }
        .field textarea { height: 60px; resize: vertical; }
        .field input:focus, .field select:focus { border-color: #3498db; outline: none; }
        .btn { color: #fff; border: none; padding: 12px 30px; border-radius: 5px; font-size: 14px; cursor: pointer; font-weight: bold; margin: 5px; }
        .btn-gerar { background: #27ae60; } .btn-gerar:hover { background: #219a52; }
        .btn-consultar { background: #2980b9; } .btn-consultar:hover { background: #2471a3; }
        .btn-cancelar { background: #e74c3c; } .btn-cancelar:hover { background: #c0392b; }
        .alert { padding: 12px 15px; border-radius: 5px; margin-bottom: 15px; font-size: 13px; }
        .alert-error { background: #fce4e4; color: #c0392b; border: 1px solid #e74c3c; }
        .alert-success { background: #d5f5e3; color: #1e8449; border: 1px solid #27ae60; }
        .alert-warning { background: #fef9e7; color: #9a7d0a; border: 1px solid #f1c40f; }
        .alert-info { background: #d6eaf8; color: #1a5276; border: 1px solid #3498db; }
        .xml-box { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }
        .toggle-btn { background: #3498db; color: #fff; border: none; padding: 5px 12px; border-radius: 3px; cursor: pointer; font-size: 12px; margin-bottom: 8px; }
        .full-width { grid-column: 1 / -1; }
        .env-badge { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .env-prod { background: #e74c3c; color: #fff; }
        .env-hom { background: #f39c12; color: #fff; }
        .erro-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        .erro-table th { background: #e74c3c; color: #fff; padding: 8px; text-align: left; }
        .erro-table td { padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }
        .nfse-dados { background: #d5f5e3; border: 2px solid #27ae60; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        .nfse-dados h3 { color: #1e8449; margin-bottom: 10px; }
        .nfse-dados table { width: 100%; font-size: 14px; }
        .nfse-dados td { padding: 5px 10px; }
        .nfse-dados td:first-child { font-weight: bold; color: #555; width: 200px; }
        .tabs { display: flex; gap: 0; margin-bottom: 0; }
        .tab { padding: 10px 20px; background: #ecf0f1; border: 1px solid #bdc3c7; border-bottom: none; cursor: pointer; font-size: 13px; font-weight: 600; border-radius: 5px 5px 0 0; }
        .tab.active { background: #fff; border-bottom: 1px solid #fff; color: #2980b9; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
    <script>
    function showTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
        document.getElementById('tab-' + tabName).classList.add('active');
        document.querySelector('[onclick="showTab(\'' + tabName + '\')"]').classList.add('active');
    }
    function toggleEl(id) {
        var el = document.getElementById(id);
        el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }
    </script>
</head>
<body>
<div class="container">
    <h1>🧾 NFSe - ABRASF 2.02 - Feira de Santana/BA</h1>
    <p class="subtitle">
        WebISS - Feira de Santana/BA (IBGE: 2910800) |
        <span class="env-badge <?= $config['ambiente'] === 'producao' ? 'env-prod' : 'env-hom' ?>">
            <?= strtoupper($config['ambiente']) ?>
        </span>
        <?php if ($operacaoExecutada): ?>
        | Operação: <strong><?= $operacaoExecutada ?></strong>
        <?php endif; ?>
    </p>

    <?php if ($erro): ?>
        <div class="alert alert-error">⚠️ <strong>Erro:</strong> <?= htmlspecialchars($erro) ?></div>
    <?php endif; ?>

    <?php if ($dadosNfse): ?>
        <div class="nfse-dados">
            <h3>✅ NFSe Processada com Sucesso!</h3>
            <table>
                <?php foreach ($dadosNfse as $campo => $valor): ?>
                <?php if (!empty($valor)): ?>
                <tr><td><?= $campo ?></td><td><?= htmlspecialchars($valor) ?></td></tr>
                <?php endif; ?>
                <?php endforeach; ?>
            </table>
        </div>
    <?php elseif ($resultado && empty($errosNfse) && !$erro): ?>
        <div class="alert alert-success">✅ Requisição processada com sucesso (HTTP <?= $resultado['http_code'] ?>)</div>
    <?php elseif ($resultado && !empty($errosNfse)): ?>
        <div class="alert alert-warning">⚠️ Retornou <?= count($errosNfse) ?> erro(s)</div>
    <?php endif; ?>

    <?php if (!empty($errosNfse)): ?>
    <div class="card">
        <h2>❌ Erros Retornados</h2>
        <table class="erro-table">
            <thead><tr><th style="width:70px;">Código</th><th>Mensagem</th><th>Correção</th></tr></thead>
            <tbody>
            <?php foreach ($errosNfse as $e): ?>
            <tr>
                <td style="font-weight:bold;color:#c0392b;"><?= htmlspecialchars($e['codigo']) ?></td>
                <td><?= htmlspecialchars($e['mensagem']) ?></td>
                <td><?= htmlspecialchars($e['correcao']) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <form method="POST">
        <!-- AMBIENTE E CERTIFICADO -->
        <div class="card">
            <h2>🔐 Ambiente e Certificado</h2>
            <div class="grid">
                <div class="field">
                    <label>Ambiente</label>
                    <select name="ambiente">
                        <option value="producao" <?= $config['ambiente'] === 'producao' ? 'selected' : '' ?>>🔴 Produção</option>
                        <option value="homologacao" <?= $config['ambiente'] === 'homologacao' ? 'selected' : '' ?>>🟡 Homologação</option>
                    </select>
                </div>
                <div class="field">
                    <label>Arquivo Certificado (.pfx)</label>
                    <input type="text" name="certificado_pfx" value="<?=htmlspecialchars($config['certificado_pfx']) ?>">
                </div>
                <div class="field full-width">
                    <label>Senha do Certificado</label>
                    <input type="password" name="certificado_senha" value="<?=htmlspecialchars($config['certificado_senha']) ?>">
                </div>
            </div>
        </div>

        <!-- PRESTADOR -->
        <div class="card">
            <h2>🏢 Prestador</h2>
            <div class="grid">
                <div class="field">
                    <label>CNPJ (14 dígitos)</label>
                    <input type="text" name="prestador_cnpj" value="<?=htmlspecialchars($config['prestador_cnpj']) ?>" maxlength="14">
                </div>
                <div class="field">
                    <label>Inscrição Municipal</label>
                    <input type="text" name="prestador_im" value="<?=htmlspecialchars($config['prestador_im']) ?>">
                </div>
            </div>
        </div>

        <!-- ABAS -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('gerar')">🚀 Gerar NFSe</div>
            <div class="tab" onclick="showTab('consultar')">🔍 Consultar por RPS</div>
            <div class="tab" onclick="showTab('cancelar')">❌ Cancelar NFSe</div>
        </div>

        <!-- ABA GERAR -->
        <div id="tab-gerar" class="tab-content active">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>📄 RPS</h2>
                <div class="grid-3">
                    <div class="field"><label>Número</label><input type="text" name="rps_numero" value="<?=htmlspecialchars($config['rps_numero']) ?>"></div>
                    <div class="field"><label>Série</label><input type="text" name="rps_serie" value="<?=htmlspecialchars($config['rps_serie']) ?>" maxlength="5"></div>
                    <div class="field"><label>Tipo</label>
                        <select name="rps_tipo">
                            <option value="1" <?= $config['rps_tipo'] == '1' ? 'selected' : '' ?>>1 - RPS</option>
                            <option value="2" <?= $config['rps_tipo'] == '2' ? 'selected' : '' ?>>2 - NF Conjugada</option>
                            <option value="3" <?= $config['rps_tipo'] == '3' ? 'selected' : '' ?>>3 - Cupom</option>
                        </select>
                    </div>
                </div>

                <h2 style="margin-top:15px;">🔧 Serviço</h2>
                <div class="grid">
                    <div class="field"><label>Valor (R$)</label><input type="text" name="valor_servicos" value="<?=htmlspecialchars($config['valor_servicos']) ?>"></div>
                    <div class="field"><label>Alíquota ISS (0.0500=5%)</label><input type="text" name="aliquota_iss" value="<?=htmlspecialchars($config['aliquota_iss']) ?>"></div>
                    <div class="field"><label>Item Lista (LC 116/03)</label><input type="text" name="item_lista" value="<?=htmlspecialchars($config['item_lista']) ?>"></div>
                    <div class="field"><label>CNAE</label><input type="text" name="codigo_cnae" value="<?=htmlspecialchars($config['codigo_cnae']) ?>"></div>
                    <div class="field"><label>Cód. Tributação Municipal</label><input type="text" name="codigo_tributacao" value="<?=htmlspecialchars($config['codigo_tributacao']) ?>"></div>
                    <div class="field"><label>Exigibilidade ISS</label>
                        <select name="exigibilidade_iss">
                            <option value="1" <?= $config['exigibilidade_iss'] == '1' ? 'selected' : '' ?>>1 - Exigível</option>
                            <option value="2" <?= $config['exigibilidade_iss'] == '2' ? 'selected' : '' ?>>2 - Não Incidência</option>
                            <option value="3" <?= $config['exigibilidade_iss'] == '3' ? 'selected' : '' ?>>3 - Isenção</option>
                            <option value="4" <?= $config['exigibilidade_iss'] == '4' ? 'selected' : '' ?>>4 - Exportação</option>
                            <option value="5" <?= $config['exigibilidade_iss'] == '5' ? 'selected' : '' ?>>5 - Imunidade</option>
                            <option value="6" <?= $config['exigibilidade_iss'] == '6' ? 'selected' : '' ?>>6 - Susp. Judicial</option>
                            <option value="7" <?= $config['exigibilidade_iss'] == '7' ? 'selected' : '' ?>>7 - Susp. Administrativo</option>
                        </select>
                    </div>
                    <div class="field"><label>ISS Retido</label><select name="iss_retido"><option value="2" <?= $config['iss_retido'] == '2' ? 'selected' : '' ?>>2 - Não</option><option value="1" <?= $config['iss_retido'] == '1' ? 'selected' : '' ?>>1 - Sim</option></select></div>
                    <div class="field"><label>Simples Nacional</label><select name="optante_simples"><option value="2" <?= $config['optante_simples'] == '2' ? 'selected' : '' ?>>2 - Não</option><option value="1" <?= $config['optante_simples'] == '1' ? 'selected' : '' ?>>1 - Sim</option></select></div>
                    <div class="field"><label>Incentivo Fiscal</label><select name="incentivo_fiscal"><option value="2" <?= $config['incentivo_fiscal'] == '2' ? 'selected' : '' ?>>2 - Não</option><option value="1" <?= $config['incentivo_fiscal'] == '1' ? 'selected' : '' ?>>1 - Sim</option></select></div>
                    <div class="field"><label>Município Incidência</label><input type="text" name="municipio_incidencia" value="<?=htmlspecialchars($config['municipio_incidencia']) ?>"></div>
                    <div class="field full-width"><label>Discriminação</label><textarea name="discriminacao"><?= htmlspecialchars($config['discriminacao']) ?></textarea></div>
                </div>

                <h2 style="margin-top:15px;">👤 Tomador</h2>
                <div class="grid">
                    <div class="field"><label>CNPJ/CPF</label><input type="text" name="tomador_cnpj" value="<?=htmlspecialchars($config['tomador_cnpj']) ?>"></div>
                    <div class="field"><label>Razão Social</label><input type="text" name="tomador_razao" value="<?=htmlspecialchars($config['tomador_razao']) ?>"></div>
                    <div class="field"><label>Endereço</label><input type="text" name="tomador_endereco" value="<?=htmlspecialchars($config['tomador_endereco']) ?>"></div>
                    <div class="field"><label>Número</label><input type="text" name="tomador_numero" value="<?=htmlspecialchars($config['tomador_numero']) ?>"></div>
                    <div class="field"><label>Bairro</label><input type="text" name="tomador_bairro" value="<?=htmlspecialchars($config['tomador_bairro']) ?>"></div>
                    <div class="field"><label>CEP</label><input type="text" name="tomador_cep" value="<?=htmlspecialchars($config['tomador_cep']) ?>" maxlength="8"></div>
                    <div class="field"><label>UF</label><input type="text" name="tomador_uf" value="<?=htmlspecialchars($config['tomador_uf']) ?>" maxlength="2"></div>
                    <div class="field"><label>Cód. Município</label><input type="text" name="tomador_cod_mun" value="<?=htmlspecialchars($config['tomador_cod_mun']) ?>"></div>
                    <div class="field"><label>Email</label><input type="text" name="tomador_email" value="<?=htmlspecialchars($config['tomador_email']) ?>"></div>
                    <div class="field"><label>Telefone</label><input type="text" name="tomador_telefone" value="<?=htmlspecialchars($config['tomador_telefone']) ?>"></div>
                </div>

                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="emitir" value="1" class="btn btn-gerar" onclick="return confirm('Confirma emissão no ambiente de <?= $config['ambiente'] ?>?');">🚀 EMITIR NFSe</button>
                </div>
            </div>
        </div>

        <!-- ABA CONSULTAR -->
        <div id="tab-consultar" class="tab-content">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>🔍 Consultar NFSe por RPS</h2>
                <div class="grid-3">
                    <div class="field"><label>Número do RPS</label><input type="text" name="consultar_rps_numero" value="<?=htmlspecialchars($config['consultar_rps_numero']) ?>"></div>
                    <div class="field"><label>Série</label><input type="text" name="consultar_rps_serie" value="<?=htmlspecialchars($config['consultar_rps_serie']) ?>"></div>
                    <div class="field"><label>Tipo</label>
                        <select name="consultar_rps_tipo">
                            <option value="1" <?= $config['consultar_rps_tipo'] == '1' ? 'selected' : '' ?>>1 - RPS</option>
                            <option value="2" <?= $config['consultar_rps_tipo'] == '2' ? 'selected' : '' ?>>2 - NF Conjugada</option>
                            <option value="3" <?= $config['consultar_rps_tipo'] == '3' ? 'selected' : '' ?>>3 - Cupom</option>
                        </select>
                    </div>
                </div>
                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="consultar" value="1" class="btn btn-consultar">🔍 CONSULTAR</button>
                </div>
            </div>
        </div>

        <!-- ABA CANCELAR -->
        <div id="tab-cancelar" class="tab-content">
            <div class="card" style="border-radius: 0 8px 8px 8px;">
                <h2>❌ Cancelar NFSe</h2>
                <div class="grid">
                    <div class="field"><label>Número da NFSe</label><input type="text" name="cancelar_numero_nfse" value="<?=htmlspecialchars($config['cancelar_numero_nfse']) ?>"></div>
                    <div class="field"><label>Motivo do Cancelamento</label>
                        <select name="cancelar_codigo">
                            <option value="1" <?= $config['cancelar_codigo'] == '1' ? 'selected' : '' ?>>1 - Erro na emissão</option>
                            <option value="2" <?= $config['cancelar_codigo'] == '2' ? 'selected' : '' ?>>2 - Serviço não prestado</option>
                            <option value="3" <?= $config['cancelar_codigo'] == '3' ? 'selected' : '' ?>>3 - Duplicidade</option>
                            <option value="4" <?= $config['cancelar_codigo'] == '4' ? 'selected' : '' ?>>4 - Erro de assinatura</option>
                        </select>
                    </div>
                </div>
                <div style="text-align:center;margin-top:15px;">
                    <button type="submit" name="cancelar" value="1" class="btn btn-cancelar" onclick="return confirm('⚠️ ATENÇÃO: Confirma o CANCELAMENTO da NFSe?');">❌ CANCELAR NFSe</button>
                </div>
            </div>
        </div>
    </form>

    <!-- RESULTADOS -->
    <?php if ($soapEnvelopeEnviado): ?>
    <div class="card">
        <h2>📨 Envelope SOAP Enviado</h2>
        <button class="toggle-btn" onclick="toggleEl('soapEnv')">Mostrar/Ocultar</button>
        <div id="soapEnv" class="xml-box" style="display:none;"><?= htmlspecialchars(formatarXml($soapEnvelopeEnviado)) ?></div>
    </div>
    <?php endif; ?>

    <?php if ($xmlEnviado): ?>
    <div class="card">
        <h2>📤 XML Enviado (nfseDadosMsg)</h2>
        <button class="toggle-btn" onclick="toggleEl('xmlEnv')">Mostrar/Ocultar</button>
        <div id="xmlEnv" class="xml-box" style="display:block;"><?= htmlspecialchars(formatarXml($xmlEnviado)) ?></div>
    </div>
    <?php endif; ?>

    <?php if ($xmlResposta): ?>
    <div class="card">
        <h2>📥 Resposta SOAP Completa</h2>
        <button class="toggle-btn" onclick="toggleEl('xmlResp')">Mostrar/Ocultar</button>
        <div id="xmlResp" class="xml-box" style="display:none;"><?= htmlspecialchars(formatarXml($xmlResposta)) ?></div>
    </div>
    <div class="card">
        <h2>📋 Conteúdo Extraído</h2>
        <div class="xml-box"><?= htmlspecialchars($xmlRespostaFormatado ?: 'Sem conteúdo') ?></div>
    </div>
    <?php endif; ?>

    <!-- REFERÊNCIA -->
    <div class="card" style="background: #eaf2f8;">
        <h2>ℹ️ Referência</h2>
        <div style="font-size: 12px; color: #555; line-height: 1.8;">
            <strong>Produção:</strong> <code>https://feiradesantanaba.webiss.com.br/ws/nfse.asmx</code><br>
            <strong>Homologação:</strong> <code>https://homologacao.webiss.com.br/ws/nfse.asmx</code><br>
            <strong>Namespace Request:</strong> <code>http://nfse.abrasf.org.br</code><br>
            <strong>Namespace Dados:</strong> <code>http://www.abrasf.org.br/nfse.xsd</code><br>
            <strong>Versão:</strong> 2.02 | <strong>IBGE:</strong> 2910800<br><br>
            <strong>Formato SOAP correto (WebISS .asmx):</strong><br>
        </div>
    </div>
</div>
</body>
</html>