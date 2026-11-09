# Detecções

Regras prontas para levar o laboratório para um SIEM. As regras são **ponto de partida**: ajuste limiares à linha de base do ambiente antes de usar em produção.

| Arquivo | Técnica | MITRE | Fonte de log |
|---|---|---|---|
| [`sigma/ftp-brute-force.yml`](sigma/ftp-brute-force.yml) | Força bruta em FTP | T1110.001 | vsftpd / auth.log |
| [`sigma/smb-password-spraying.yml`](sigma/smb-password-spraying.yml) | Password spraying em SMB | T1110.003 | Windows Security 4625 |
| [`sigma/web-brute-force.yml`](sigma/web-brute-force.yml) | Força bruta em formulário web | T1110.001 | Apache access.log / WAF |
| [`wazuh/dvwa-brute-force.xml`](wazuh/dvwa-brute-force.xml) | Força bruta no DVWA | T1110 | Wazuh |

## Como usar

### Sigma

```bash
# Validar/consultar com sigma-cli (opcional)
sigma check detections/sigma/

# Converter para Splunk
sigma convert -t splunk detections/sigma/ftp-brute-force.yml

# Converter para Elastic
sigma convert -t elasticsearch detections/sigma/smb-password-spraying.yml
```

### Wazuh

Copie o XML para o diretório de regras customizadas do Wazuh, valide a sintaxe e reinicie o manager:

```bash
sudo cp detections/wazuh/dvwa-brute-force.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
```

## Boas práticas

- Ajuste `timeframe` e os limiares ao volume normal do ambiente.
- Monitore **usuários distintos** por IP para separar spraying de força bruta.
- Inclua contexto de ativo, criticidade e horário na triagem.
- Teste cada regra com tráfego controlado antes de habilitar em produção.
- Revise falsos positivos periodicamente.

## Contexto

- [`docs/08-soc-e-automacao.md`](../docs/08-soc-e-automacao.md) — explicação, consultas SPL/KQL e triagem com IA.
- [`reports/soc-triage.md`](../reports/soc-triage.md) — exemplo de relatório gerado a partir das evidências.
- [`scripts/06-soc-triage.py`](../scripts/06-soc-triage.py) — automação da triagem.

> Este repositório é um laboratório educacional. Não use estas regras como única fonte de decisão em um SOC real.
