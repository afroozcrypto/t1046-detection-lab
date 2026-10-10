"""Gera pcaps sintéticos por cenário, calibrados com o que foi medido no lab.

Atacante 192.168.1.133 (Kali), alvo 192.168.1.1 (OPNsense), portas filtradas
(sem resposta), 2 tentativas por porta como o nmap faz em portas filtradas.
Cliente benigno 192.168.1.50 a navegar para servidores externos.
"""
import random
import sys
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

random.seed(42)
ATK, ALVO, BENIGNO = "192.168.1.133", "192.168.1.1", "192.168.1.50"
MAC_A, MAC_B = "52:54:00:ec:53:02", "52:54:00:1b:1a:22"
T0 = 1_760_000_000.0
LINUX_OPTS = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
              ("NOP", None), ("WScale", 9)]
COMUNS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
EXCL_SS = {21, 22, 23, 25, 53, 80, 88, 110, 135, 137, 138, 139, 143, 161, 389,
           443, 445, 465, 514, 587, 636, 853, 993, 995, 1194, 1433, 1720, 3306,
           3389, 8080, 8443, 11211, 27017, 51820}
TOP1000 = [4444] + sorted(EXCL_SS)[:20] + random.sample(
    [p for p in range(1000, 65000) if p not in EXCL_SS and p != 4444], 979)


def pkt(t, src, dst, sport, dport, flags, window, opts):
    p = (Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst, ttl=64) /
         TCP(sport=sport, dport=dport, flags=flags, window=window,
             options=opts, seq=random.randint(1, 2**32 - 1)))
    p.time = t
    return p


def scan(ports, flags, window, opts, raw=True, sport=None, intervalo=0.002, tent=2):
    """raw=True imita o nmap (porta de origem fixa); raw=False imita connect()."""
    out, t, sp = [], T0, sport or 55317
    for _ in range(tent):
        for dp in ports:
            out.append(pkt(t, ATK, ALVO, sp, dp, flags, window, opts))
            if not raw:
                sp += 1
            t += intervalo
    return out


def navegacao(n_ligacoes=200, segundos=60, servidores=40):
    """Tráfego normal: SYN de kernel Linux para 443/80 em muitos servidores."""
    out, sp = [], 40000
    ips = [f"203.0.113.{i}" for i in range(1, servidores + 1)]
    for i in range(n_ligacoes):
        t = T0 + segundos * i / n_ligacoes
        dst = random.choice(ips)
        dport = 443 if random.random() < 0.9 else 80
        out.append(pkt(t, BENIGNO, dst, sp, dport, "S", 64240, LINUX_OPTS))
        sp += 1
    return out


def rajada_mesmo_servidor(n=8):
    """Browser com HTTP/1.1 a abrir n ligações paralelas ao mesmo servidor."""
    return [pkt(T0 + i * 0.01, BENIGNO, "203.0.113.200", 41000 + i, 443, "S",
                64240, LINUX_OPTS) for i in range(n)]


def ssh_admin(n=6):
    """Admin a abrir n sessões SSH ao mesmo servidor num minuto."""
    return [pkt(T0 + i * 10, BENIGNO, ALVO, 42000 + i, 22, "S", 64240, LINUX_OPTS)
            for i in range(n)]


def rajada_servico(dport, n, segundos, dst=ALVO):
    """Cliente legítimo a abrir n ligações ao mesmo serviço em poucos segundos."""
    return [pkt(T0 + segundos * i / n, BENIGNO, dst, 43000 + i, dport, "S",
                64240, LINUX_OPTS) for i in range(n)]


def decoys(ports, n_falsos=5):
    """nmap -D RND:5: cada sonda sai do IP real e de 5 IPs falsos."""
    falsos = [f"192.168.1.{200 + i}" for i in range(n_falsos)]
    out, t = [], T0
    for _ in range(2):
        for dp in ports:
            for src in falsos + [ATK]:
                p = pkt(t, src, ALVO, 55317, dp, "S", 1024, [("MSS", 1460)])
                out.append(p)
            t += 0.002
    return out


NMAP_OPTS = [("MSS", 1460)]
CENARIOS = {
    "ataque_sS": scan(TOP1000, "S", 1024, NMAP_OPTS),
    "ataque_sT": scan(TOP1000, "S", 64240, LINUX_OPTS, raw=False),
    "ataque_sS_comuns": scan(COMUNS, "S", 1024, NMAP_OPTS),
    "ataque_sT_comuns": scan(COMUNS, "S", 64240, LINUX_OPTS, raw=False),
    "ataque_sN": scan(TOP1000, "", 1024, NMAP_OPTS),
    "ataque_sF": scan(TOP1000, "F", 1024, NMAP_OPTS),
    "ataque_sX": scan(TOP1000, "FPU", 1024, NMAP_OPTS),
    "ataque_sS_g53": scan(TOP1000, "S", 1024, NMAP_OPTS, sport=53),
    "ataque_atomic_bash": scan(list(range(1000, 1101)), "S", 64240, LINUX_OPTS,
                               raw=False, intervalo=0.2, tent=1),
    "benigno_navegacao": navegacao(),
    "benigno_rajada_8": rajada_mesmo_servidor(8),
    "benigno_ssh_admin": ssh_admin(6),
    # Casos difíceis: serviços legítimos com rajadas para o mesmo destino
    "benigno_dns_tcp_20em30s": rajada_servico(53, 20, 30),
    "benigno_smb_12em30s": rajada_servico(445, 12, 30, dst="192.168.1.20"),
    "benigno_imap_5": rajada_servico(993, 5, 5, dst="203.0.113.9"),
    # Limites de velocidade: -T2 (0,4 s entre sondas) e -T1 (15 s)
    "ataque_sS_T2": scan(TOP1000, "S", 1024, NMAP_OPTS, intervalo=0.4, tent=1),
    "ataque_sS_comuns_T1": scan(COMUNS, "S", 1024, NMAP_OPTS, intervalo=15, tent=1),
    # Evasão: decoys (IPs falsos) e atraso de 3 s entre sondas em 100 portas
    "ataque_sS_decoys": decoys(TOP1000),
    "ataque_sS_delay3s_100p": scan(TOP1000[:100], "S", 1024, NMAP_OPTS, intervalo=3, tent=1),
}

if __name__ == "__main__":
    d = Path(sys.argv[1])
    d.mkdir(parents=True, exist_ok=True)
    for nome, pkts in CENARIOS.items():
        wrpcap(str(d / f"{nome}.pcap"), pkts)
        print(f"{nome}: {len(pkts)} pacotes")
