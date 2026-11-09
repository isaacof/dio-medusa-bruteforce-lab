#!/usr/bin/env python3
"""06 — Triagem SOC automatizada do laboratório Medusa.

Lê as evidências já coletadas (logs do Medusa, Nmap e enumeração SMB),
normaliza os achados, mapeia para MITRE ATT&CK e gera:

  reports/soc-triage.md        relatório de triagem em Markdown
  reports/soc-triage.json      versão estruturada para SIEM/SOAR
  reports/ai-triage-prompt.md  prompt sanitizado para análise assistida por IA

Uso:
    python3 scripts/06-soc-triage.py
    python3 scripts/06-soc-triage.py --source evidencias --out reports
    python3 scripts/06-soc-triage.py --show-credentials

Sem dependências externas. Credenciais são redigidas por padrão.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {
    "critical": "🔴 Crítica",
    "high": "🟠 Alta",
    "medium": "🟡 Média",
    "low": "🟢 Baixa",
}

FOUND_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"ACCOUNT FOUND: \[(?P<module>[^\]]+)\] Host: (?P<host>\S+) "
    r"User: (?P<user>.+?) Password: (?P<password>.+?) "
    r"\[(?P<status>[^\]]+)\]"
)
NMAP_RE = re.compile(r"^(?P<port>\d+)/tcp\s+open\s+(?P<service>\S+)\s*(?P<version>.*)$")

MODULE_INFO = {
    "ftp": {"service": "FTP", "port": 21, "log_source": "vsftpd / auth.log"},
    "smbnt": {"service": "SMB", "port": 445, "log_source": "Samba / Windows 4625"},
    "web-form": {"service": "HTTP", "port": 80, "log_source": "Apache access.log / WAF"},
}

RISK_NOTES = [
    ("vsftpd 2.3.4", "Backdoor conhecido (CVE-2011-2523) e protocolo sem criptografia"),
    ("Samba 3.0.20", "SMBv1, sessão nula e versão obsoleta"),
    ("Apache httpd 2.2.8", "Versão sem suporte"),
    ("OpenSSH 4.7", "Versão antiga; autenticação por senha habilitada"),
    ("telnet", "Protocolo em texto claro"),
    ("MySQL 5.0", "Versão antiga exposta na rede"),
    ("PostgreSQL 8.3", "Versão antiga exposta na rede"),
]

DETECTIONS = {
    "ftp": {
        "signal": "Múltiplas falhas de autenticação FTP do mesmo IP em curto intervalo.",
        "splunk": (
            'index=linux sourcetype=vsftpd OR sourcetype=linux_secure '
            '"authentication failure" OR "FAIL LOGIN" '
            "| stats count by src_ip, user | where count > 5"
        ),
        "kql": (
            'event.dataset:(vsftpd.log or system.auth) and '
            'event.outcome:"failure" | stats count by source.ip, user.name '
            "| where count > 5"
        ),
    },
    "smb_spray": {
        "signal": "Mesmo IP falhando em muitos usuários diferentes (padrão de spraying).",
        "splunk": (
            "index=windows EventCode=4625 "
            "| stats dc(TargetUserName) as usuarios, count by IpAddress "
            "| where usuarios > 5"
        ),
        "kql": (
            "event.code:4625 | stats users=dcount(user.name) by source.ip "
            "| where users > 5"
        ),
    },
    "smb_brute": {
        "signal": "Muitas falhas para o mesmo usuário em curto intervalo.",
        "splunk": (
            "index=windows EventCode=4625 "
            "| stats count by TargetUserName, IpAddress | where count > 10"
        ),
        "kql": (
            "event.code:4625 | stats count by user.name, source.ip "
            "| where count > 10"
        ),
    },
    "web": {
        "signal": "Picos de requisições ao endpoint de login, muitas com resposta 200/401.",
        "splunk": (
            'index=web sourcetype=apache_access '
            '"/dvwa/vulnerabilities/brute/" '
            "| stats count by clientip, status | where count > 20"
        ),
        "kql": (
            'url.path:"/dvwa/vulnerabilities/brute/" '
            "| stats count by source.ip, http.response.status_code "
            "| where count > 20"
        ),
    },
}


@dataclass
class Finding:
    id: str
    timestamp: str
    host: str
    user: str
    password: str
    module: str
    service: str
    port: int
    technique: str
    mitre: list[str]
    severity: str
    status: str
    evidence: str


def redact(value: str, show_credentials: bool) -> str:
    """Nunca grava a senha no relatório, exceto em modo explícito de laboratório."""
    return value if show_credentials else "<redacted>"


def classify(path: Path, module: str, status: str, user: str) -> tuple[str, str, list[str]]:
    """Retorna (técnica, severidade, IDs MITRE) a partir do módulo e do contexto."""
    lowered = status.lower()
    if module == "smbnt" and "spray" in path.name:
        technique = "Password spraying"
        mitre = ["T1110.003"]
    elif module == "smbnt":
        technique = "Força bruta direcionada"
        mitre = ["T1110.001"]
    elif module == "web-form":
        technique = "Força bruta em formulário web"
        mitre = ["T1110.001"]
    elif module == "ftp":
        technique = "Força bruta de credenciais"
        mitre = ["T1110.001"]
    else:
        technique = "Tentativa de autenticação"
        mitre = ["T1110"]

    # Todo ACCOUNT FOUND é um login válido; T1078 cobre o uso da conta.
    mitre.append("T1078")

    if "admin$" in lowered or user.lower() in {"root", "admin"}:
        severity = "critical"
    elif user:
        severity = "high"
    else:
        severity = "medium"
    return technique, severity, mitre


def parse_medusa(path: Path, source_root: Path, show_credentials: bool) -> list[Finding]:
    findings: list[Finding] = []
    if not path.exists():
        return findings

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = FOUND_RE.match(line.strip())
        if not match:
            continue
        module = match.group("module")
        info = MODULE_INFO.get(module, {"service": module, "port": 0})
        technique, severity, mitre = classify(
            path, module, match.group("status"), match.group("user")
        )
        findings.append(
            Finding(
                id="",  # preenchido depois, após a ordenação
                timestamp=match.group("timestamp"),
                host=match.group("host"),
                user=match.group("user"),
                password=redact(match.group("password"), show_credentials),
                module=module,
                service=info["service"],
                port=info["port"],
                technique=technique,
                mitre=mitre,
                severity=severity,
                status=match.group("status"),
                evidence=str(path.relative_to(source_root)).replace("\\", "/"),
            )
        )
    return findings


def parse_nmap(path: Path) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    if not path.exists():
        return services

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = NMAP_RE.match(line.strip())
        if not match:
            continue
        version = match.group("version").strip()
        risk = next((note for needle, note in RISK_NOTES if needle.lower() in version.lower()), "")
        services.append(
            {
                "port": int(match.group("port")),
                "service": match.group("service"),
                "version": version,
                "risk": risk,
            }
        )
    return services


def parse_enumeration(source_root: Path) -> dict[str, Any]:
    users_file = source_root / "smb" / "03-smb-users.txt"
    shares_file = source_root / "smb" / "03-smb-shares.txt"

    users = []
    if users_file.exists():
        users = [line.strip() for line in users_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

    shares = []
    if shares_file.exists():
        for line in shares_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if re.search(r"\b(Disk|IPC)\b", line):
                name = line.split()[0]
                if name.lower() not in {"sharename", "---------"}:
                    shares.append(name)

    return {"users_count": len(users), "users_sample": users[:10], "shares": shares}


def build_markdown(
    findings: list[Finding],
    services: list[dict[str, Any]],
    enumeration: dict[str, Any],
    generated_at: str,
    source_label: str,
    show_credentials: bool,
) -> str:
    total = len(findings)
    hosts = sorted({f.host for f in findings})
    services_affected = sorted({f.service for f in findings})
    highest = min((f.severity for f in findings), key=SEVERITY_ORDER.get) if findings else "low"

    lines: list[str] = []
    lines.append("# Relatório de Triagem SOC — Laboratório Medusa")
    lines.append("")
    lines.append(f"> Gerado automaticamente em **{generated_at}** a partir de `{source_label}`.")
    lines.append("> Laboratório isolado em rede host-only. Nenhum alvo real foi consultado.")
    lines.append("")
    lines.append("## Resumo executivo")
    lines.append("")
    lines.append(f"- **{total}** evento(s) de autenticação bem-sucedida identificado(s) nas evidências.")
    lines.append(f"- **{len(hosts)}** host(s) envolvido(s): {', '.join(f'`{h}`' for h in hosts) or '—'}.")
    lines.append(f"- **{len(services_affected)}** serviço(s) comprometido(s): {', '.join(services_affected) or '—'}.")
    lines.append(f"- **{enumeration['users_count']}** usuário(s) enumerado(s) via SMB e **{len(enumeration['shares'])}** compartilhamento(s) listado(s).")
    lines.append(f"- Severidade mais alta: **{SEVERITY_LABEL.get(highest, highest)}**.")
    lines.append("- Credenciais: redigidas neste relatório." if not show_credentials else "- Credenciais: **exibidas** (modo explícito de laboratório).")
    lines.append("")
    lines.append("## Achados")
    lines.append("")
    lines.append("| ID | Horário | Host | Usuário | Técnica | MITRE | Severidade | Evidência |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f.id} | {f.timestamp} | `{f.host}` | `{f.user}` | {f.technique} | "
            f"{', '.join(f.mitre)} | {SEVERITY_LABEL.get(f.severity, f.severity)} | `{f.evidence}` |"
        )
    if not findings:
        lines.append("| — | — | — | — | Nenhum login válido encontrado | — | — | — |")
    lines.append("")
    lines.append("## Linha do tempo")
    lines.append("")
    for f in findings:
        lines.append(f"- `{f.timestamp}` — {f.technique} em **{f.service}:{f.port}** (`{f.host}`), usuário `{f.user}`.")
    if not findings:
        lines.append("- Nenhum evento de sucesso encontrado.")
    lines.append("")
    lines.append("## Serviços observados no reconhecimento")
    lines.append("")
    lines.append("| Porta | Serviço | Versão | Risco |")
    lines.append("|---:|---|---|---|")
    for s in services:
        lines.append(f"| {s['port']} | {s['service']} | {s['version'] or '—'} | {s['risk'] or '—'} |")
    if not services:
        lines.append("| — | — | — | Nmap não encontrado |")
    lines.append("")
    lines.append("## Enumeração SMB")
    lines.append("")
    lines.append(f"- Usuários enumerados: **{enumeration['users_count']}**")
    if enumeration["users_sample"]:
        lines.append(f"- Amostra: {', '.join(f'`{u}`' for u in enumeration['users_sample'])}")
    lines.append(f"- Compartilhamentos: {', '.join(f'`{s}`' for s in enumeration['shares']) or '—'}")
    lines.append("")
    lines.append("## Cobertura MITRE ATT&CK")
    lines.append("")
    lines.append("| Técnica | ID | Achados |")
    lines.append("|---|---|---:|")
    mitre_counts: dict[str, int] = {}
    for f in findings:
        for technique_id in f.mitre:
            mitre_counts[technique_id] = mitre_counts.get(technique_id, 0) + 1
    mitre_names = {
        "T1110": "Brute Force",
        "T1110.001": "Password Guessing",
        "T1110.003": "Password Spraying",
        "T1078": "Valid Accounts",
        "T1087": "Account Discovery",
        "T1135": "Network Share Discovery",
    }
    for technique_id, count in sorted(mitre_counts.items()):
        lines.append(f"| {mitre_names.get(technique_id, '—')} | {technique_id} | {count} |")
    if not mitre_counts:
        lines.append("| — | — | 0 |")
    lines.append("")
    lines.append("## Recomendações de detecção")
    lines.append("")
    seen: set[str] = set()
    for f in findings:
        key = "smb_spray" if f.technique == "Password spraying" else (
            "smb_brute" if f.module == "smbnt" else ("web" if f.module == "web-form" else "ftp")
        )
        if key in seen:
            continue
        seen.add(key)
        detection = DETECTIONS[key]
        lines.append(f"### {f.technique} ({f.service})")
        lines.append("")
        lines.append(f"**Sinal:** {detection['signal']}")
        lines.append("")
        lines.append("```spl")
        lines.append(detection["splunk"])
        lines.append("```")
        lines.append("")
        lines.append("```kql")
        lines.append(detection["kql"])
        lines.append("```")
        lines.append("")
    lines.append("## Perguntas de triagem")
    lines.append("")
    lines.append("1. O IP de origem é conhecido e pertence ao inventário?")
    lines.append("2. Quantas contas foram tentadas e quantas obtiveram sucesso?")
    lines.append("3. Houve acesso a compartilhamentos administrativos ou dados sensíveis?")
    lines.append("4. O mesmo IP aparece em outros serviços no mesmo intervalo?")
    lines.append("5. Existe MFA, lockout ou rate limiting no serviço afetado?")
    lines.append("6. A conta comprometida é privilegiada ou de serviço?")
    lines.append("")
    lines.append("## Limitações")
    lines.append("")
    lines.append("- Análise baseada apenas nas evidências versionadas; não há telemetria de endpoint.")
    lines.append("- Os horários refletem o relógio da VM atacante.")
    lines.append("- Falsos positivos são possíveis; toda detecção deve ser validada por um analista.")
    lines.append("- O laboratório usa credenciais padrão e não representa um ambiente de produção.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Gerado por [`scripts/06-soc-triage.py`](../scripts/06-soc-triage.py).")
    return "\n".join(lines) + "\n"


def build_ai_prompt(findings: list[Finding], services: list[dict[str, Any]], enumeration: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {f.id} | {f.timestamp} | {f.host} | {f.user} | {f.service} | {f.technique} | {', '.join(f.mitre)} | {f.severity} |"
        for f in findings
    )
    service_rows = "\n".join(
        f"| {s['port']} | {s['service']} | {s['version']} | {s['risk']} |" for s in services
    )
    return f"""# Prompt de triagem assistida por IA

> Gerado automaticamente pelo laboratório. **Não contém credenciais.**
> Para logs reais, sanitize IPs, usuários e nomes de host antes de enviar a qualquer LLM.

## Contexto

Você é um assistente de análise de SOC. Receberá evidências normalizadas de um
laboratório isolado de força bruta. Sua função é apoiar a triagem, **não substituir**
a validação humana.

## Evidências

| ID | Horário | Host | Usuário | Serviço | Técnica | MITRE | Severidade |
|---|---|---|---|---|---|---|---|
{rows or '| — | — | — | — | — | — | — | — |'}

### Serviços observados

| Porta | Serviço | Versão | Risco |
|---:|---|---|---|
{service_rows or '| — | — | — | — |'}

### Enumeração

- Usuários enumerados via SMB: {enumeration['users_count']}
- Compartilhamentos: {', '.join(enumeration['shares']) or '—'}

## Tarefa

1. Resuma o incidente em até 5 linhas.
2. Confirme ou reclassifique a severidade de cada achado, justificando.
3. Mapeie cada achado para MITRE ATT&CK.
4. Proponha três regras de detecção (Sigma, Splunk SPL ou KQL).
5. Liste cinco perguntas de triagem que faltam responder.
6. Sugira contenção, erradicação e recuperação em ordem de prioridade.

## Formato de saída (JSON)

```json
{{
  "resumo": "...",
  "achados": [
    {{"id": "SOC-001", "severidade": "critical|high|medium|low", "justificativa": "...", "mitre": ["T1110.001"]}}
  ],
  "regras_deteccao": [{{"nome": "...", "linguagem": "sigma|spl|kql", "regra": "..."}}],
  "perguntas_triagem": ["..."],
  "resposta": {{"contencao": ["..."], "erradicacao": ["..."], "recuperacao": ["..."]}}
}}
```

## Guardrails

- Use **somente** os dados fornecidos; não invente IPs, horários ou usuários.
- Não solicite nem reproduza credenciais.
- Marque hipóteses como hipóteses e indique o que precisa de validação.
- Se faltar evidência, diga explicitamente o que falta.
- Responda em português do Brasil.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Triagem SOC automatizada do laboratório Medusa.")
    parser.add_argument("--source", default="evidencias", help="Diretório de evidências (padrão: evidencias)")
    parser.add_argument("--out", default="reports", help="Diretório de saída (padrão: reports)")
    parser.add_argument(
        "--show-credentials",
        action="store_true",
        help="Exibe as senhas no relatório (apenas para laboratório isolado).",
    )
    args = parser.parse_args()

    source_root = Path(args.source).resolve()
    out_dir = Path(args.out).resolve()
    if not source_root.exists():
        parser.error(f"diretório de evidências não encontrado: {source_root}")

    findings: list[Finding] = []
    for relative, hint in [
        ("ftp/02-ftp-medusa.log", "ftp"),
        ("smb/04-smb-spray.log", "smbnt"),
        ("smb/04-smb-brute.log", "smbnt"),
        ("dvwa/05-dvwa-medusa.log", "web-form"),
    ]:
        findings.extend(parse_medusa(source_root / relative, source_root, args.show_credentials))

    findings.sort(key=lambda f: (f.timestamp, SEVERITY_ORDER.get(f.severity, 9)))
    for index, finding in enumerate(findings, start=1):
        finding.id = f"SOC-{index:03d}"

    services = parse_nmap(source_root / "nmap" / "01-nmap-servicos.txt")
    enumeration = parse_enumeration(source_root)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    markdown = build_markdown(
        findings, services, enumeration, generated_at, args.source, args.show_credentials
    )
    ai_prompt = build_ai_prompt(findings, services, enumeration)

    payload = {
        "report": "soc-triage",
        "generated_at": generated_at,
        "source": args.source,
        "scope": "laboratório isolado (host-only); nenhum alvo real",
        "summary": {
            "findings": len(findings),
            "hosts": sorted({f.host for f in findings}),
            "services": sorted({f.service for f in findings}),
            "users_enumerated": enumeration["users_count"],
            "shares": enumeration["shares"],
            "highest_severity": min((f.severity for f in findings), key=SEVERITY_ORDER.get) if findings else None,
        },
        "findings": [asdict(f) for f in findings],
        "services": services,
        "enumeration": enumeration,
        "limitations": [
            "Análise baseada apenas nas evidências versionadas.",
            "Horários refletem o relógio da VM atacante.",
            "Falsos positivos são possíveis; validação humana é obrigatória.",
        ],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "soc-triage.md").write_text(markdown, encoding="utf-8")
    (out_dir / "soc-triage.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "ai-triage-prompt.md").write_text(ai_prompt, encoding="utf-8")

    print(f"[ok] {len(findings)} achado(s) normalizado(s)")
    print(f"[ok] relatório: {out_dir / 'soc-triage.md'}")
    print(f"[ok] json:      {out_dir / 'soc-triage.json'}")
    print(f"[ok] prompt IA: {out_dir / 'ai-triage-prompt.md'}")
    if not args.show_credentials:
        print("[ok] credenciais redigidas (use --show-credentials apenas no laboratório)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
