# Base revisada do GoHunt

`advisories.json` é o catálogo operacional (schema 2; leitura compatível com schema 1), incorporado ao binário por `catalog.go`. Cada aviso possui produto canônico, faixa numérica [introduced, fixed), referência primária, condições e, opcionalmente, um identificador de verificador implementado e testado em Go. Um JSON não pode criar payloads ou executar novos verificadores. A leitura rejeita campos desconhecidos, IDs duplicados, referências inválidas, faixas inválidas e verificadores não reconhecidos.

Cobertura: 14 CVEs — Node.js (3), Next.js (2), nginx (3), Apache HTTP Server (5) e Joomla (1). Somente Joomla possui verificador ativo. Faixas separadas por ramo e condições documentadas evitam confundir uma versão corrigida com afetada. Consulte `docs/MODELO-VALIDACAO.md` para fontes e limites.

`favhashes.json` foi preservado para compatibilidade com módulos antigos; favicon não prova versão ou vulnerabilidade.

`legacy-manifest.json` registra arquivos antigos, contagens e SHA-256. Os nove arquivos foram preservados no arquivo `GoHunt-Db-legado-2026-10-17.tar.gz`, na pasta de trabalho acima do projeto, fora do pacote de publicação. Antes de removê-los de Db, cada membro do arquivo foi conferido contra seu SHA-256. Os indicadores de campos ausentes referem-se ao schema atual; versões antigas tinham schemas diferentes. Não representam uma auditoria individual de cada template.

As conversões não são automaticamente promovidas ao catálogo: faltam semânticas de DSL, encadeamento, extratores e pré-condições que um conjunto simples de matchers não representa. A CLI antiga em cmd/legacy requer os arquivos legados restaurados para executar sua antiga rotina de vulnerabilidades; ela não utiliza este catálogo e não é o fluxo recomendado.
