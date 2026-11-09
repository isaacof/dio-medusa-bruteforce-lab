# 01 — Montagem do ambiente

## Visão geral

O laboratório usa duas máquinas virtuais no VirtualBox, conectadas por uma rede **host-only**. Isso garante que o Metasploitable 2 fique acessível apenas pelo host e pelo Kali, sem qualquer rota para a internet.

| VM | Papel | IP | Memória sugerida |
|---|---|---|---|
| Kali Linux | Atacante | `192.168.56.101` | 2 GB |
| Metasploitable 2 | Alvo | `192.168.56.102` | 512 MB–1 GB |

## 1. Rede host-only

No VirtualBox:

1. **Arquivo → Ferramentas → Gerenciador de Rede**
2. Aba **Redes somente host**
3. Selecione `VirtualBox Host-Only Ethernet Adapter`
4. Configure:
   - IPv4: `192.168.56.1`
   - Máscara: `255.255.255.0`
   - DHCP: desabilitado (IPs fixos simplificam o laboratório)

No host Windows, confirme:

```powershell
ipconfig
```

A interface deve mostrar `192.168.56.1`.

## 2. Configuração das VMs

### Kali Linux

- Adaptador 1: **Somente host** (`vboxnet0`)
- IP estático `192.168.56.101/24` (ou DHCP do host-only, se preferir)

Dentro do Kali:

```bash
ip -4 -o addr show eth0
ping -c 2 192.168.56.102
```

### Metasploitable 2

- Adaptador 1: **Somente host**
- IP `192.168.56.102/24`

O Metasploitable 2 já vem com diversos serviços vulneráveis habilitados: FTP, SSH, Telnet, HTTP, SMB, MySQL e PostgreSQL.

> ⚠️ O banner do próprio Metasploitable avisa: *“Never expose this VM to an untrusted network!”*. Nunca use adaptador **NAT** ou **Bridged** neste alvo.

## 3. Ferramentas no Kali

```bash
sudo apt update
sudo apt install -y medusa nmap enum4linux smbclient curl
```

Verificação:

```bash
medusa -V
nmap --version
enum4linux -h | head
smbclient --version
```

Versões usadas neste projeto:

| Ferramenta | Versão |
|---|---|
| Kali Linux | Rolling (kernel 7.1.5) |
| Medusa | 2.3 |
| Nmap | 7.99 |
| Samba client | 4.x |
| DVWA | versão padrão do Metasploitable 2 |

## 4. DVWA

O Metasploitable 2 já traz o DVWA em:

```text
http://192.168.56.102/dvwa/
```

Credenciais padrão:

```text
admin / password
```

O banco do DVWA normalmente já está criado. Se aparecer a tela de setup:

1. Acesse `http://192.168.56.102/dvwa/setup.php`
2. Clique em **Create / Reset Database**
3. Faça login com `admin:password`

## 5. Snapshot recomendado

Antes de qualquer teste, tire um snapshot das duas VMs:

```text
VirtualBox → Máquina → Tirar snapshot → "lab-limpo"
```

Isso permite restaurar o estado inicial após os exercícios.

## 6. Checklist antes de atacar

- [ ] As duas VMs estão na rede host-only.
- [ ] O Kali alcança o Metasploitable (`ping`).
- [ ] O Metasploitable **não** tem rota para a internet.
- [ ] O snapshot foi criado.
- [ ] O alvo é `192.168.56.102` (confirme com `ip a`).
- [ ] Você tem autorização para testar (neste caso, as VMs são suas).

## 7. Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `ping` não responde | Adaptador em NAT/Bridged | Trocar para host-only |
| IP diferente de `192.168.56.x` | DHCP de outra rede | Fixar IP ou ajustar o adaptador |
| DVWA retorna 404 | Caminho errado | Acessar `/dvwa/` (com barra) |
| DVWA pede setup | Banco não criado | Rodar `setup.php` |
| Medusa não encontra o módulo | Pacote incompleto | `sudo apt install medusa` |
| SMB recusa conexão | Serviço parado | Reiniciar o Metasploitable |

---

Voltar ao [README](../README.md) · Próximo: [02 — Reconhecimento](02-reconhecimento.md)
