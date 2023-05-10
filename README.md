# pa-file-server-g6

O projeto proposto, definido de agora em diante como “pa-file-server”, tem como objetivo a criação de um servidor de ficheiros de texto com encriptação de modo a que todas as trocas de mensagens e ficheiros sejam seguras e íntegras.

De uma forma geral, o pa-file-server deverá ser composto por um servidor, ao qual um ou mais clientes se poderão ligar. O servidor segue o paradigma request-reply, no qual cada cliente, após se autenticar no servidor, poderá solicitar ficheiros de texto que serão devolvidos pelo servidor.

A confidencialidade e integridade dos dados serão a maior prioridade do servidor. Por essa razão, toda a comunicação com o servidor deverá ser encriptada e todos os ficheiros retornados pelo servidor deverão ser encriptados e íntegros.

O servidor possui um diretório server/files, que deverá guardar todos os ficheiros servidos pelo servidor. Quando o servidor é iniciado, deverá ser gerado um par de chaves (uma pública e uma privada). O servidor deverá guardar a sua chave privada em memória, enquanto que a chave pública deverá ficar guardada com o nome serverPUk.key no diretório pki/public_keys.

## Instalação

Para instalar esta simples aplicação basta fazer o clone deste repositório para a máquina local.

```bash
git clone https://github.com/pedrojaques21/pa-file-server-G6
```

## Utilização

Para utilizar este projeto basta abrir o repositório com o seu IDE perferido e correr primeiramente o MainServer de forma a iniciar o servidor. Após o servidor ser iniciado, na configuração do MainClient é necessário habilitar a inicialização de várias instâncias, depois podemos iniciar os clientes selecionado o MainClient e correndo.

No cliente é necessário providenciar o nome e posteriormente selecionar os algoritmos de encriptação e algoritmo de hash.

Depois o cliente pode requisitar ficheiros que estejam no servidor utilizando o comando "GET : <nome-do-ficheiro>.<extenção-do-ficheiro>".
  
## Observações
  
Por questões de testes unitários existem valores pré-definidos no ficheiro numOfRequestsMap.txt
