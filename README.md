# Cleans Java keystore file

Suppose that you need to authenticate clients by trusting in a certificate authorities chain. Maybe you can download every single certificate from each authority, but the chances to do a mistake are very big. Depending on the case, you don't have an unique place with all certificates that you need. From time to time, new authorities are created, certificates expire, etc.

Maybe you have the option to get a single Java _keystore_ file, generated by a _root CA_, with the complete chain that you need. But imagine that this _keystore_ has another authorities that you don't need or don't want to trust. Well, this is the case if you __only__ need to authenticate Brazilian individual or legal entity with _e-CPF_ or _e-CNPJ_ digital certificates. Actually, these Brazilian electronic documents are tokens with private and public keys for client authentication.

Therefore I developed a `cleans_java_keystore_file.sh` shellscript to clean a Java _keystore_ file, preserving only the required _CA's_ certificates.

If you need to require a Brazilian individual or legal entity authentication, you need to trust in a _CA_ chain issued by <sub>\[1\]</sub> [ICP-Brasil](http://www.iti.gov.br/icp-brasil), which belongs to <sub>\[2\]</sub> [ITI](http://www.iti.gov.br). ICP-Brasil releases a Java [_keystore_](http://www.iti.gov.br/navegadores/java/95-navegadores/java/452-versao-linux) file with the _CA's_ chain for client authentication in a Java application.

  1. ICP-Brasil - Infraestrutura de Chaves Públicas Brasileira - In a free translation, it would be: "Brazilian Public Keys Infrastructure"
  2. ITI - Instituto Nacional de Tecnologia da Informação - In a free translation, it would be: "National Institute of Information Technology"

## About the script

This script generates a copy of a _keystore_ file, removing authorities which does not belong to the chain of a specific authority. All you have to do is to properly configure `cleans_java_keystore_file.conf` file. It also generates the same _keystore_ in a PEM format file. To generate it, just pass `-p` or `--pem` parameter on the command line.

## Download
You can download it in my GitHub repository at [https://github.com/nmoura/cleans_java_keystore_file](https://github.com/nmoura/cleans_java_keystore_file). This repository also contains the _keystore_ from ICP-Brasil to serve as an example.

## How it works?

All configuration variables in `cleans_java_keystore_file.conf` are mandatory, but `keystore_issuer` has a fundamental role. It's the _CN_ issuer that you want to trust. So, the script will preserve in the _keystore_ only hierarchically _CA's_ above and below of this issuer, no mattering the depth.

For example, imagine a _keystore_ file with this hierarchically chain:

```
root CA
    \_ intermediate CA1
        \_ second intermediate CA1 A
            \_ CA1 AA
            \_ CA1 AB
            \_ CA1 AC
        \_ second intermediate CA1 B
            \_ CA1 BA
            \_ CA1 BB
            \_ CA1 BC
    \_ intermediate CA2
        \_ second intermediate CA2 A
            \_ CA2 AA
            \_ CA2 AB
            \_ CA2 AC
        \_ second intermediate CA2 B
            \_ CA2 BA
            \_ CA2 BB
            \_ CA2 BC      
```

Now imagine that the CA responsible for creation, deletion and etc., of _CA's_ that are important to you, is the ```second intermediate CA2 A```. All you have to do is to run the script with ```keystore_issuer``` variable configured like this:

```
keystore_issuer="second intermediate CA2 A"
```

And the new _keystore_ generated will contain the following:

```
root CA
    \_ intermediate CA2
        \_ second intermediate CA2 A
            \_ CA2 AA
            \_ CA2 AB
            \_ CA2 AC
```

### A real example
As a real example, let's see what happens when we execute this script with the mentioned _keystore_ from ICP-Brasil. At the table below, the first column is a list of all _CA's_ before the execution. The second column is a list of the preserved _CA's_ after the execution of the script. For this, it was enough to set the ```keystore_issuer``` variable like this:

```
keystore_issuer="AC Secretaria da Receita Federal do Brasil*"
```

<table>
  <tr width="100%">
    <td align="center" width="50%"><b>Before</b></td>
    <td align="center" width="50%"><b>After</b></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon RFB G2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon RFB G2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
    Owner: CN=AC Certisign Tempo G2<br/>
    Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Tempo G1<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
    Owner: CN=SERASA Autoridade Certificadora Principal v5<br/>
    Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Autoridade Certificadora Principal v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Autoridade Certificadora Principal v1<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SAFEWEB RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SAFEWEB RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Secretaria da Receita Federal do Brasil<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA SPB<br/>
      Issuer: CN=AC CAIXA v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC ONLINE RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC ONLINE RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID v5<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Autoridade Certificadora v5<br/>
      Issuer: CN=SERASA Autoridade Certificadora Principal v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA CD SSL V5<br/>
      Issuer: CN=SERASA Autoridade Certificadora Principal v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora do SERPRO Final SSL<br/>
      Issuer: CN=Autoridade Certificadora SERPRO v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC VALID RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRO v4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign SPB G5<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRO v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon G3<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRO v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Instituto Fenacon G2<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora do PRODERJ<br/>
      Issuer: CN=Autoridade Certificadora SERPRO v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora Raiz Brasileira v5<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora Raiz Brasileira v5<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CERTISIGN-JUS G5<br/>
      Issuer: CN=Autoridade Certificadora da Justica v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora Raiz Brasileira v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora Raiz Brasileira v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Multipla G7<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Multipla G6<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Multipla G5<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC DIGITALSIGN<br/>
      Issuer: CN=AC DIGITALSIGN ACP
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign-JUS G3<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC OAB G3<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR G4<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign-JUS G2<br/>
      Issuer: CN=Autoridade Certificadora da Justica v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora Raiz Brasileira v1<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC OAB G2<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR G3<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Presidencia da Republica v4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Presidencia da Republica v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Presidencia da Republica v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Casa da Moeda do Brasil<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RIO RFB G1<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RIO RFB G1<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC FENACON Certisign RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC FENACON Certisign RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP G4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP G3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial SP G2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PRODEST RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC PRODEST RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID PLUS<br/>
      Issuer: CN=AC VALID
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA-JUS v2<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA-JUS v1<br/>
      Issuer: CN=Autoridade Certificadora da Justica v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora do PRODERJ v2<br/>
      Issuer: CN=Autoridade Certificadora SERPRO v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Multipla CodeSigning<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SINCOR RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SOLUTI<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC DIGITALSIGN ACP<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID SPB<br/>
      Issuer: CN=AC VALID
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRORFBv4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRORFBv4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRORFB v3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora SERPRORFB v3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Justica v5<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Justica v4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC DIGITALSIGN RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC DIGITALSIGN RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERASA RFB v5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SERASA RFB v5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Justica v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PETROBRAS G3<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERASA RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SERASA RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora do SERPRO Final v4<br/>
      Issuer: CN=Autoridade Certificadora SERPRO v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CERTISIGN-JUS SSL G5<br/>
      Issuer: CN=Autoridade Certificadora da Justica v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CERTISIGN-JUS CODESIGNING G5<br/>
      Issuer: CN=Autoridade Certificadora da Justica v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora do SERPRO Final v3<br/>
      Issuer: CN=Autoridade Certificadora SERPRO v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign Multipla SSL<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC DOCCLOUD RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC DOCCLOUD RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC LINK RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC LINK RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Autoridade Certificadora v2<br/>
      Issuer: CN=SERASA Autoridade Certificadora Principal v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC BOA VISTA RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC BOA VISTA RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Secretaria da Receita Federal do Brasil v4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Secretaria da Receita Federal do Brasil v4<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Secretaria da Receita Federal do Brasil v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Secretaria da Receita Federal do Brasil v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA PF v2<br/>
      Issuer: CN=AC CAIXA v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SOLUTI-JUS v1<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC EGBA Multipla<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CNDL RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC CNDL RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC BOA VISTA<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Certificadora Digital v5<br/>
      Issuer: CN=SERASA Autoridade Certificadora Principal v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC BR RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC BR RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC BR RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC BR RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CNDL RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC CNDL RFB v2<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA PJ v2<br/>
      Issuer: CN=AC CAIXA v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SOLUTI Multipla<br/>
      Issuer: CN=AC SOLUTI
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign G7<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign G6<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SOLUTI RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC SOLUTI RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Casa da Moeda do Brasil v3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign G3<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v1
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=Autoridade Certificadora da Casa da Moeda do Brasil v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC BOA VISTA CERTIFICADORA<br/>
      Issuer: CN=AC BOA VISTA
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC ONLINE BRASIL<br/>
      Issuer: CN=AC VALID
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Notarial RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Notarial RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Notarial RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Notarial RFB G3<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE G4<br/>
      Issuer: CN=AC Certisign G7
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CACB RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC CACB RFB<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC PRODEMGE G3<br/>
      Issuer: CN=AC Certisign G6
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID-JUS v4<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERPRO-JUS v5<br/>
      Issuer: CN=Autoridade Certificadora da Justica v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERPRO-JUS v4<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERPRO-JUS v3<br/>
      Issuer: CN=Autoridade Certificadora da Justica v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign RFB G5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Certisign RFB G5<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v4
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC VALID BRASIL<br/>
      Issuer: CN=AC VALID
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=SERASA Certificadora Digital v2<br/>
      Issuer: CN=SERASA Autoridade Certificadora Principal v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC DIGITAL<br/>
      Issuer: CN=AC SOLUTI
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Certisign RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
    <td valign="top"><sub>
      Owner: CN=AC Certisign RFB G4<br/>
      Issuer: CN=AC Secretaria da Receita Federal do Brasil v3
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERASA-JUS v5<br/>
      Issuer: CN=Autoridade Certificadora da Justica v5
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial G4<br/>
      Issuer: CN=AC Imprensa Oficial SP G4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERASA-JUS v2<br/>
      Issuer: CN=Autoridade Certificadora da Justica v4
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial G3<br/>
      Issuer: CN=AC Imprensa Oficial SP G3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC SERASA-JUS v1<br/>
      Issuer: CN=Autoridade Certificadora da Justica v3
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC CAIXA v2<br/>
      Issuer: CN=Autoridade Certificadora Raiz Brasileira v2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
  <tr>
    <td valign="top"><sub>
      Owner: CN=AC Imprensa Oficial G2<br/>
      Issuer: CN=AC Imprensa Oficial SP G2
    </sub></td>
    <td valign="top"><sub>
      -
    </sub></td>
  </tr>
</table>
