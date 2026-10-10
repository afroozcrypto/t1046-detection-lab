# Bateria real n4 · 2026-10-09 (19:39 a 20:06)

OPNsense 26.7.6, Suricata 8.0.7, n4.rules (20 alertas, sha256 fe97743c…903b6). Atacante Kali 192.168.1.133, alvo 192.168.1.1.

## Saída bruta (contagem por SID)
```
sS          2 3400001  278 3400002  2 3400020  1 3400102  1 3400120  1 3400130  1 3400133
sT          2 3400020  98 3400103  1 3400113  1 3400120  1 3400130  1 3400133
sS_comuns   1 3400001  1 3400130
sT_comuns   1 3400130
sN          2 3400020  1 3400131
sF          2 3400020  1 3400132
sX          666 3400005  2 3400020  1 3400105
sS_g53      2 3400001  278 3400002  1 3400102  1 3400130  1 3400133
atomic_bash 5 3400103  1 3400113
```

## Real vs offline (regras silenciosas, sem porta 4444)
| Cenário | Antigas | Silenciosas real | Offline previsto |
|---|---|---|---|
| sS | 280 | 2 | 2 |
| sT | 98 | 2 | 2 |
| sS_comuns | 1 | 1 | 1 |
| sT_comuns | 0 | 1 | 1 |
| sN | 0 | 1 | 1 |
| sF | 0 | 1 | 1 |
| sX | 666 | 1 | 1 |
| sS_g53 | 280 | 2 | 2 |
| atomic_bash | 5 | 1 | 1 |
| **Total** | **1330** | **12** | **12** |

9/9 iguais. Offline é preditivo do lab real.

## Porta 4444
- 3400020 dispara 2x por scan, exceto com -g 53 (ponto cego).
- 3400120 dispara 1x, exceto com -g 53.
- 3400133 dispara 1x em todos, incluindo -g 53.

## A desligar (pendente confirmação do Conde)
3400002, 3400103, 3400005, 3400004, 3400020, 3400120.
Ficam: 3400001 (1 a 2 alertas, cobre comuns), 3400102, 3400113, 3400130 a 3400133, 3400105, 3400104, UDP e frag.
