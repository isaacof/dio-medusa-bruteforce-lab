# 07 — Conclusão

## O que foi entregue

O desafio foi concluído com a implementação de um laboratório completo e reproduzível:

- Duas VMs em rede host-only (Kali Linux e Metasploitable 2).
- Reconhecimento com Nmap.
- Força bruta em **FTP** com Medusa.
- **Enumeração SMB** e **password spraying** com Medusa.
- Força bruta em **formulário web (DVWA)** com o módulo `web-form`.
- Validação independente dos três acessos.
- Documentação técnica, scripts, wordlists e evidências.
- Propostas de mitigação e detecção.

## Resultados

| Vetor | Credencial | Tentativas | Validação |
|---|---|---:|---|
| FTP | `msfadmin:msfadmin` | 16 | Listagem do diretório `vulnerable` |
| SMB | `msfadmin:msfadmin` | 1 | Listagem de `/tmp` + `ADMIN$` |
| DVWA | `admin:password` | 1 | “Welcome to the password protected area admin” |

Os três serviços caíram por **credenciais padrão**. Isso mostra que, antes de qualquer técnica avançada, o básico continua sendo o maior risco.

## Principais aprendizados

### Técnicos

- **Medusa é versátil:** o mesmo conceito (usuário × senha) se aplica a protocolos diferentes, mudando apenas o módulo (`ftp`, `smbnt`, `web-form`).
- **Enumeração reduz o espaço de busca:** 35 usuários descobertos via SMB transformaram a força bruta em uma tentativa certeira.
- **Spraying ≠ força bruta:** a escolha da técnica depende do mecanismo de bloqueio do alvo.
- **Validação é obrigatória:** o Medusa pode dar falso positivo quando o `DENY-SIGNAL` não corresponde à aplicação.
- **O tempo varia por serviço:** FTP levou ~45 s; SMB e DVWA responderam em menos de 1 s.

### Práticos

- Wordlists com linhas de comentário (`#`) são interpretadas como credenciais pelo Medusa. Mantenha as listas **limpas**, com uma entrada por linha.
- O `-f` do Medusa não garante parada imediata com múltiplas threads; use `-t 1` quando precisar de execução determinística.
- O DVWA exige **cookie de sessão** e nível de segurança `low`; sem isso, o módulo `web-form` falha ou gera falso positivo.
- Capturas de tela e logs brutos valem mais que descrições genéricas.

### Defensivos

- **MFA** teria interrompido os três ataques.
- **Bloqueio de conta** e **rate limiting** teriam tornado a força bruta inviável.
- **Remoção de credenciais padrão** teria evitado o comprometimento inicial.
- **Sessão nula desabilitada** teria escondido os 35 usuários.
- **Monitoramento** teria detectado o comportamento barulhento.

## Dificuldades encontradas

| Dificuldade | Solução |
|---|---|
| Wordlists com comentários viravam “usuários” | Remover linhas `#` das listas |
| FTP lento entre tentativas | Reduzir escopo e usar `-t 1` para log limpo |
| DVWA redirecionava para login | Manter cookie e `security=low` em todas as requisições |
| `DENY-SIGNAL` incorreto | Inspecionar a resposta real da aplicação antes do ataque |
| Sessão SMB lenta | Testar com poucos usuários e uma senha (spraying) |

## Próximos passos

- Comparar Medusa com **Hydra** e **Ncrack**.
- Testar cenários com **bloqueio de conta** para medir a eficácia do spraying.
- Explorar outros módulos do Metasploitable (MySQL, PostgreSQL, Tomcat).
- Automatizar a coleta de evidências com scripts.
- Estudar **MITRE ATT&CK** (T1110 — Brute Force).
- Praticar relatórios de pentest com classificação de risco.

## Reflexão final

Segurança não é sobre uma ferramenta específica. O Medusa foi apenas o meio; o aprendizado real está em entender **por que** uma senha padrão derruba três serviços diferentes e **o que** fazer para que isso não aconteça.

Um ambiente seguro assume que o atacante tem tempo, ferramentas e uma wordlist. A defesa precisa tornar cada tentativa **cara, lenta e detectável** — e, idealmente, desnecessária, porque a credencial correta nunca deveria ser óbvia.

> “A diferença entre um teste de intrusão e um crime é a autorização.”

---

Anterior: [06 — Mitigações](06-mitigacoes.md) · Voltar ao [README](../README.md)
