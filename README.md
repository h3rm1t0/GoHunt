# GoHunt

<img width="641" height="226" alt="Captura de tela de 2026-10-20 11-20-42" src="https://github.com/user-attachments/assets/87495a07-9f34-432b-a7c3-580ce095c2a8" />


Uma ferramenta desenvolvida em Go para reconhecimento e triagem em programas de bug bounty e avaliações de segurança autorizadas. Seu objetivo é organizar a superfície descoberta, reduzir resultados repetidos e apoiar a validação manual com evidências rastreáveis.

Desenvolvido por **h3rm1t0**, como projeto independente de pesquisa e engenharia de software aplicada à segurança.

## Funcionalidades

- **Escopo explícito:** domínios, subdomínios e URLs, com controle de autorização por hostname.
- **Reconhecimento público:** integração com crt.sh, AlienVault OTX, Wayback Machine e Common Crawl.
- **Mapeamento de páginas:** perfis reduzido, equilibrado e aprofundado, com limites de profundidade e páginas por host.
- **Wordlists opcionais:** descoberta de subdomínios, diretórios e arquivos.
- **Controle de requisições:** jitter configurável, timeouts, limite de resposta e tratamento de falhas.
- **Tecnologias e versões:** identificação por fingerprints, cabeçalhos e marcas HTML, distinguindo indícios de versões declaradas.
- **Superfície de entrada:** coleta de links, parâmetros, formulários e inputs, agrupando estruturas semelhantes.
- **Deduplicação:** agrupamento de rotas históricas por parâmetros, preservação de amostras e comparação com históricos anteriores.
- **Triagem de autorização:** controles negativos e comparação de respostas para reduzir falsos positivos em candidatos a bypass.
- **Triagem de takeover:** coleta de evidências DNS/HTTP e indicação de URLs para validação posterior.
- **Análise dirigida de CVEs:** correlação com catálogo revisado, pré-condições documentadas, referências e seleção explícita de verificadores ativos.
- **Consulta opcional ao OSV:** análise de pacotes informados em inventário, com cache e conferência local dos resultados.
- **Retomada de execução:** persistência da fila e dos resultados em JSONL, com recuperação após interrupções.
- **Painel web local:** disponível antes do início da coleta, com filtros, prioridades, evidências, relações da superfície e árvore de caminhos por host.
- **Revisão manual:** comentários, confirmação, descarte e acompanhamento dos pontos já analisados.

## Organização dos resultados

Os resultados são apresentados de **P1 a P5**, conforme os critérios internos de triagem. Essas prioridades orientam a investigação e não equivalem, por si só, a uma classificação definitiva de severidade.

A avaliação distingue os seguintes estados:

- Produto observado.
- Correlação possível.
- Pré-condições atendidas.
- Evidência reproduzida.
- Confirmado manualmente.
- Descartado.
- Inconclusivo.

A árvore de caminhos organiza as URLs por domínio e subdomínio, reunindo parâmetros sem repetir ramos para cada valor GET. Níveis intermediários inferidos são identificados separadamente dos caminhos registrados.

## Arquitetura e armazenamento

O projeto possui um único executável e módulos separados para coleta passiva e ativa, extração, fuzzing, autorização, vulnerabilidades, DNS, takeover, persistência e interface web.

O journal JSONL concentra tarefas e resultados. Revisões manuais e cache utilizam arquivos auxiliares. O painel funciona em loopback, sem exigir banco de dados ou servidor web externo.

## Requisitos e compilação

Requer **Linux e Go 1.24 ou superior**. Execute na pasta que contém `go.mod`:

```bash
go mod download
mkdir -p bin
go build -buildvcs=false -o bin/gohunt .
./bin/gohunt --help
```

Exemplo de execução:

```bash
./bin/gohunt --scope escopo.txt \
  --state output/programa.jsonl \
  --jitter-min 300ms \
  --jitter-max 1200ms \
  --crawl-mode balanced
```

O painel inicia, por padrão, em `http://127.0.0.1:8080`. Para continuar uma coleta interrompida, repita as opções de exploração e adicione `--resume`.

## Limitações

O GoHunt está em desenvolvimento. A cobertura de CVEs e verificadores ativos é limitada; a presença de uma tecnologia ou versão compatível exige investigação adicional.

A ferramenta não executa JavaScript nem automatiza sessões autenticadas. A exploração de formulários GET exige habilitação explícita; formulários POST, senhas e uploads não são enviados automaticamente.

Heurísticas podem produzir falsos positivos e falsos negativos. Candidatos a bypass e takeover exigem validação de impacto. Caminhos históricos ou inferidos não comprovam disponibilidade atual.

A execução é sequencial, e consultas ao painel ainda percorrem o journal. Estados grandes podem apresentar maior custo de leitura. Tarefas interrompidas podem repetir requisições durante a retomada.

## Uso ético e autorização

O GoHunt foi desenvolvido para pesquisa, aprendizado e avaliações de segurança **expressamente autorizadas**.

Utilize a ferramenta somente em ativos próprios ou mediante autorização válida do responsável. Em programas de bug bounty, respeite o escopo publicado, as técnicas permitidas, os limites de requisições, as restrições de automação e as regras de divulgação.

A configuração de escopo da ferramenta é um controle técnico; a autorização deve ser obtida e verificada pelo operador. Antes da execução, considere que as regras do GoHunt são por hostname e não implementam exclusões de caminhos ou portas.

O operador é responsável pelos alvos, parâmetros, wordlists e verificadores selecionados, bem como pelo tratamento dos dados coletados e pelo cumprimento da legislação e dos termos aplicáveis.

Evite interrupções de serviço, acesso desnecessário a dados pessoais, alteração de informações e qualquer atividade além da autorização concedida. Caso identifique exposição sensível, limite a coleta ao necessário para demonstrar o problema e siga o processo de divulgação responsável.

Resultados devem ser revisados antes de qualquer reporte. A ausência de achados não constitui garantia de segurança. Não publique credenciais, dados pessoais, evidências sensíveis ou resultados de terceiros sem autorização.

Este aviso não concede permissão para testar sistemas de terceiros. O autor não autoriza nem endossa usos ilegais ou fora do escopo permitido.
