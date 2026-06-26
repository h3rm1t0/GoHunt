# GoHunt

O **GoHunt** é uma ferramenta customizada de Segurança Ofensiva desenvolvida em Go, focada em automação de *Bug Bounty*, descoberta de *Information Disclosure* e *Fuzzing* furtivo. 
Ao contrário de scanners comerciais ruidosos, o GoHunt foi arquitetado para se comportar como um navegador real, conversando com a infraestrutura alvo no ritmo adequado para evitar bloqueios, enquanto busca ativamente por falhas lógicas, painéis expostos e vazamento de credenciais.

---

## 🚧 Status do Projeto
**Em desenvolvimento ativo (BETA).** O GoHunt é funcional para varreduras de escopos pequenos e médios (incluindo *wildcards*), mas seu motor central (`VulnChecker`) e o banco de dados de assinaturas (`arsenal.json`) estão passando por aprimoramentos e refatorações contínuas de gerenciamento de memória e concorrência.

---

## Diferenciais Arquiteturais

A ferramenta foi construída sob a ótica de alta precisão (High Signal / Low Noise) para minimizar a fadiga de falsos positivos comum em *hunting*:

* **Calibração Dinâmica de Soft-404:** O scanner realiza uma análise prévia do alvo, aprendendo como o servidor responde a páginas inexistentes. Isso elimina Falsos Positivos causados por redirecionamentos cegos e páginas de erro customizadas.
* **Fuzzing com Evasão de WAF:** Gerenciamento nativo de *timing* nas requisições e falsificação de assinatura (*User-Agent*), evitando banimentos prematuros por *Rate Limit* (429/403) em infraestruturas como Cloudflare e Akamai.
* **Caçador de Redirecionamentos:** O motor HTTP não para no primeiro `301/302`. Ele persegue os saltos lógicos da aplicação para varrer o destino final.
* **Extração de Segredos Baseada em Regex Estrita:** Módulo equipado com expressões regulares calibradas (RE2) para vasculhar respostas HTTP (Status `200` e erros `500`) em busca de chaves sensíveis (GitHub PATs, JWTs, AWS Keys), com mitigação contra dados ofuscados e capturas acidentais.
* **Concorrência Segura (Goroutines & Mutex):** Arquitetura multi-thread que lida de forma segura com o disco e APIs de terceiros.
* **Alertas Assíncronos:** Integração direta com a API do Telegram, contando com sistema de *Retry* e gerenciamento de filas para contornar *Rate Limits* da própria rede social.

---

## Objetivos futuros (O que vem a seguir)

- [x] Otimização de *Timing* para evasão de WAF.
- [x] Sincronização segura de arquivos de laudo usando `sync.Mutex`.
- [x] Mecanismo de confirmação para respostas `403 Forbidden`.
- [ ] Criação de arquivos de estado (`.gohunt_state`) para evitar repetição de *recon* no mesmo dia.
- [ ] Refinamento do `arsenal.json` focado em vazamentos de CI/CD e ambientes em nuvem.
- [ ] Módulo interno de *Proof of Concept* (PoC) para validação ativa de JWTs e Tokens encontrados.

---

## ⚠️ Disclaimer Educacional e Ético

O GoHunt foi criado **estritamente para uso educacional, pesquisa de segurança cibernética e operações autorizadas** (programas de *Bug Bounty* oficiais, *Red Teaming* contratual e auditorias com consentimento explícito). 
O desenvolvedor não encoraja, apoia ou assume qualquer responsabilidade pelo uso indevido desta ferramenta em redes, sistemas ou aplicações sem autorização prévia por escrito de seus proprietários. Ao utilizar o GoHunt, você assume total responsabilidade por suas ações e concorda em operar dentro dos limites das leis aplicáveis.
