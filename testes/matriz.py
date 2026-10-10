"""Corre o Suricata offline contra cada pcap e imprime a matriz cenário x SID.

Suricata: procura no PATH, ou define a variável de ambiente SURI.
    SURI=/opt/suri8/bin/suricata python3 -I testes/matriz.py ...
"""
import collections
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Antes: SURI = "/opt/suri8/bin/suricata" (caminho fixo, reescrito pelo Makefile em cada execução)
# Agora: lido do ambiente, com fallback para o PATH. `python3 -I` só ignora
# variáveis PYTHON*, por isso os.environ continua a funcionar.
SURI = os.environ.get("SURI", "suricata")
CONF = Path(__file__).with_name("suricata-lab.yaml")


def correr(regras: Path, pcap: Path, logdir: Path) -> collections.Counter:
    logdir.mkdir(parents=True, exist_ok=True)
    for f in logdir.glob("*"):
        f.unlink()
    r = subprocess.run([SURI, "-c", str(CONF), "-S", str(regras), "-r", str(pcap),
                        "-l", str(logdir), "-k", "none", "--runmode", "single"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"Suricata falhou em {pcap.name}:\n{r.stderr[-2000:]}")
    c = collections.Counter()
    fast = logdir / "fast.log"
    if fast.exists():
        for sid in re.findall(r"\[1:(\d+):\d+\]", fast.read_text()):
            c[sid] += 1
    return c


if __name__ == "__main__":
    regras, pcaps, saida = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    res = {}
    total = 0
    for p in sorted(pcaps.glob("*.pcap")):
        res[p.stem] = dict(correr(regras, p, Path("/tmp/suri-log") / p.stem))
        n = sum(res[p.stem].values())
        total += n
        print(f"{p.stem:24s} {n:>3}  {res[p.stem]}")
    print(f"{'TOTAL':24s} {total:>3}")
    saida.write_text(json.dumps(res, indent=1))
