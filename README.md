# t1046-detection-lab

Deteção de port scans (nmap) com Suricata em OPNsense, testada em laboratório. MITRE ATT&CK T1046 (Network Service Discovery).

**TL;DR (EN):** Suricata 8 ruleset for detecting nmap scans (-sS, -sT, -sN, -sF, -sX, -g 53, port 4444) with synthetic pcaps (scapy) and a reproducible offline test matrix. Noisy defaults gave 1330 alerts over 9 scan scenarios; the tuned set gives 12, and the offline result matched the real lab 9/9. Use only on equipment you own.

## Resultados

| Cenário | Regras antigas | Regras silenciosas (real) | Offline previsto |
|---|---|---|---|
| sS | 280 | 2 | 2 |
| sT | 98 | 2 | 2 |
| sS portas comuns | 1 | 1 | 1 |
| sT portas comuns | 0 | 1 | 1 |
| sN | 0 | 1 | 1 |
| sF | 0 | 1 | 1 |
| sX | 666 | 1 | 1 |
| sS -g 53 | 280 | 2 | 2 |
| atomic bash | 5 | 1 | 1 |
| **Total** | **1330** | **12** | **12** |

Detalhe em `resultados/bateria-real-2026-10-09.md`.

## Estrutura
- `regras/n4.rules`: 20 regras (SID 34000xx e 34001xx). É o ficheiro completo; as 6 regras ruidosas (SID 3400002, 3400005, 3400020, 3400103, 3400113, 3400120) foram desativadas na GUI do OPNsense, não no ficheiro.
- `regras/n3-base-anterior.rules`, `regras/n4-novas.rules`: base anterior e delta.
- `cenarios/gen_cenarios.py`: gera 19 pcaps sintéticos (13 de ataque, 6 benignos) com scapy.
- `testes/matriz.py`: corre o Suricata offline sobre cada pcap e conta alertas por SID.
- `testes/bateria.sh`: bateria real, corre no atacante contra o alvo.
- `resultados/`: matrizes offline (JSON) e bateria real.
- `docs/`: write-ups.

## Reproduzir
```
pip install scapy        # Suricata 8.0.7 no PATH, ou SURI=/opt/suri8/bin/suricata
make validar             # suricata -T às regras
make pcaps               # regenera os pcaps
make matriz              # alertas por SID e cenário
```

## Limites conhecidos
- `nmap -sS -T1` em portas comuns passa despercebido. Precisa de `detection_filter unique_on dst_port` (Suricata 9.0, previsto 1 jul 2027) ou de Zeek.
- Decoys (`-D`) são detetados, mas cada origem falsa gera alertas. Separação por ARP não testada.
- Só offline: T2, T1, decoys, delay 3 s e os 6 cenários benignos.
- SID 3400001 continua ativa: cerca de 2 alertas por scan.
- No OPNsense, `EXTERNAL_NET = !HOME_NET`: regras `$EXTERNAL_NET -> $HOME_NET` nunca disparam para um atacante interno. Usar `any`.
- A regra 3400130 v1 (count 10) dava falsos positivos em DNS sobre TCP e SMB. A v2 usa count 15 e exclui as portas 53, 80 e 443.

## Aviso
Só em equipamento e redes teus. Licença MIT (ver `LICENSE`). Regras derivadas de aleksibovellan/opnsense-suricata-nmaps: ver `NOTICE`.
