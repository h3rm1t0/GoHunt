# Árvore de caminhos descobertos

No painel, abra **Árvore de caminhos**. Em **Todo o escopo**, expanda um domínio ou subdomínio; ao selecionar um host na lateral, a árvore começa na sua raiz. Clique nos caminhos para visualizar descendentes, URLs, códigos HTTP observados e parâmetros/campos.

- Um host aparece uma vez. Cada caminho aparece uma vez dentro de seu ramo, mesmo se coletado por diferentes fontes, tarefas ou achados.
- Valores GET e fragmentos não criam novos ramos. Os nomes dos parâmetros são reunidos; os registros originais e exemplos históricos continuam no estado e na aba de achados.
- HTTP/HTTPS, portas e caminhos com/sem barra final compartilham o nó visual, mas suas URLs sem query ficam discriminadas nos detalhes. Isso não afirma que tenham o mesmo comportamento.
- Maiúsculas/minúsculas e separadores codificados como `%2F` permanecem distintos. A representação hexadecimal dos escapes é normalizada.
- “Caminho registrado” significa que existe um registro da URL, inclusive histórico ou com erro. “Nível inferido” significa apenas um ancestral necessário para organizar um descendente. Nenhum deles comprova diretório físico, acesso autorizado ou vulnerabilidade.
- Hosts conhecidos apenas por DNS aparecem mesmo sem caminhos HTTP. A árvore usa os registros do estado, ignora entradas explicitamente marcadas fora do escopo e não incorpora destinos externos de redirecionamentos/CNAME como novos hosts.

A busca filtra URLs e preserva os ancestrais dos caminhos correspondentes. Prioridade, tipo, fonte e revisão filtram a lista de achados, não a árvore. A aba, a busca e o host selecionado permanecem na URL do painel. Ramos expandidos e páginas dos ramos permanecem durante atualizações automáticas na mesma sessão; recarregar toda a página reinicia as expansões.

Cada ramo é carregado sob demanda, com até 100 filhos por página e navegação para os demais, sem corte silencioso em 150 URLs. A consulta é local e não gera novas requisições aos alvos. Não exige migração nem uma nova coleta: funciona com estados JSONL existentes.

API local: `GET /api/directory-tree?host=app.example.com&path=/api&offset=0&q=`. Sem host, retorna hosts; com host e sem path, retorna a raiz; com path, retorna filhos imediatos. Resposta: `items`, `total`, `offset`, `limit`. Os detalhes pertencem ao nó exato, não são herdados dos descendentes.

Limitação de desempenho: cada abertura ou atualização de ramo lê um snapshot do journal. A resposta e a renderização são paginadas, mas o custo de leitura ainda cresce com o estado; esta implementação não adiciona um índice persistente. Em coletas grandes, use o filtro de host e mantenha apenas os ramos necessários abertos.
