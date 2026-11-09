#!/usr/bin/env python3
"""07 — Valida links relativos em README.md e docs/*.md.

Ignora links externos (http/https/mailto) e âncoras internas. Retorna código 1
quando encontra um caminho quebrado, o que permite usar em CI.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FILES = [ROOT / "README.md"]
if (ROOT / "README.en.md").exists():
    FILES.append(ROOT / "README.en.md")
FILES += sorted((ROOT / "docs").glob("*.md"))


def main() -> int:
    missing: list[tuple[str, str]] = []
    checked = 0

    for file in FILES:
        if not file.exists():
            continue
        text = file.read_text(encoding="utf-8", errors="replace")
        for match in LINK_RE.finditer(text):
            target = match.group(1).strip().strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            checked += 1
            resolved = (file.parent / unquote(target)).resolve()
            if not resolved.exists():
                missing.append((str(file.relative_to(ROOT)), target))

    print(f"[ok] {checked} link(s) relativo(s) verificado(s) em {len(FILES)} arquivo(s)")
    if missing:
        print("[erro] links quebrados:")
        for file, target in missing:
            print(f"  - {file}: {target}")
        return 1
    print("[ok] nenhum link quebrado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
