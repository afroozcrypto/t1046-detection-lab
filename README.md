# t1046-detection-lab

[![regras](https://github.com/afroozcrypto/t1046-detection-lab/actions/workflows/regras.yml/badge.svg)](https://github.com/afroozcrypto/t1046-detection-lab/actions/workflows/regras.yml) ![licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue) ![Suricata 8.0.7](https://img.shields.io/badge/Suricata-8.0.7-orange)

Deteção de port scans (nmap) com Suricata em OPNsense, testada em laboratório.
MITRE ATT&CK **T1046 — Network Service Discovery** (referência: ATT&CK **v19.2**, agosto 2026).

**TL;DR (EN):** Suricata 8 ruleset for detecting nmap scans (-sS, -sT, -sN, -sF, -sX, -g 53, port 4444) with synthetic pcaps (scapy) and a reproducible offline test matrix. Noisy defaults gave 1330 alerts over 9 scan scenarios; the tuned set gives 12 in the live lab. The offline harness is fully reproducible from a clean clone. Zero alerts across 6 benign scenarios. Use only on equipment you own.

## Resultados

| Cenário | Regras antigas | Afinadas (lab) | Offline medido |
|---|---|---|---|
| sS | 280 | 2 | 5 |
| sT | 98 | 2 | 2 |
| sS portas comuns | 1 | 1 | 2 |
| sT portas comuns | 0 | 1 | 1 |
| sN | 0 | 1 | 1 |
| sF | 0 | 1 | 1 |
| sX | 666 | 1 | 1 |
| sS -g 53 | 280 | 2 | 5 |
| atomic bash | 5 | 1 | 0 |
| **Total** | **1330** | **12** | **18** |

Nos 19 pcaps (incluindo T2, decoys e delay 3s): **59 alertas**.
Nos **6 cenários benignos: 0 alertas** — a afirmação de zero falsos positivos está verificada.

> ⚠️ **Nota de honestidade — a coluna offline não coincide com a do lab.**
> A coluna *Afinadas (lab)* foi medida na bateria real; a coluna *Offline medido* é
> o que o harness produz hoje com o ficheiro de regras publicado. **Não são iguais**
> (18 vs 12), pelo que **não se afirma concordância 9/9**. As diferenças concentram-se
> onde entram as regras n4 (3400130, 3400102, 3400133) e no `atomic bash` (0 offline).
> Hipóteses em investigação: a coluna do lab terá sido medida antes de as regras n4
> estarem finalizadas, e/ou o mapeamento cenário-a-cenário entre a bateria real e o
> gerador de pcaps não ser 1:1. Detalhe por SID em `resultados/`.

## Estrutura

- `regras/n4.rules` — **autocontido.** 14 regras ativas; as 6 ruidosas estão **comentadas
  no ficheiro**, marcadas `# --- DESATIVADA --- sid:...`. `make matriz` reproduz o
  resultado publicado **sem passos manuais na GUI do OPNsense**.
- `regras/n4-ruidosas.rules` — as 6 excluídas, documentadas uma a uma: regra original,
  porque é ruidosa, e o que a substituiu.
- `regras/n3-base-anterior.rules`, `regras/n4-novas.rules` — base anterior e delta.
- `cenarios/gen_cenarios.py` — gera 19 pcaps sintéticos (13 de ataque, 6 benignos) com scapy.
- `testes/matriz.py` — corre o Suricata offline sobre cada pcap e conta alertas por SID.
- `testes/suricata-lab.yaml` — config do Suricata usada pelo harness (caminhos portáteis).
- `testes/bateria.sh` — bateria real. **Corre no atacante contra o alvo**, com o lab montado.
- `resultados/` — matrizes offline (JSON) e bateria real.
- `docs/` — write-ups.

## Reproduzir

```bash
sudo apt install suricata python3-scapy make   # precisa da série 8.x
git clone https://github.com/afroozcrypto/t1046-detection-lab.git
cd t1046-detection-lab

make validar   # 14 regras carregadas, 0 falhas
make pcaps     # 19 pcaps
make matriz    # total 59 (18 nos 9 cenários de ataque)
```

- Sem Suricata no PATH: `make validar SURI=/caminho/para/suricata`
- Requer **`/etc/suricata/classification.config`** (vem do pacote `suricata`). O `make validar`
  verifica-o e diz-te se faltar.
- O `SURI` passa por variável de ambiente — **nada é escrito em ficheiros versionados**.
- `make lint` verifica contagem e SIDs duplicados sem precisar de Suricata nenhum.

## Limites conhecidos

- `nmap -sS -T1` em portas comuns passa despercebido a assinaturas.
  **`detection_filter unique_on dst_port` está merged em master e tem como target o `9.0.0-beta1`**
  ([Redmine #7928](https://redmine.openinfosecfoundation.org/issues/7928) — a discussão descreve
  exatamente este caso: *"We want to detect port scan in the network, however there are a lot of
  communications to the same port in a short time which gives us false positives"*).
  A data de release **não está confirmada**.
  Alternativa imediata: camada comportamental (**Zeek + RITA**), que não depende de assinaturas.
- Decoys (`-D`) são detetados, mas cada origem falsa gera alertas. Separação por ARP não testada.
- Só offline (sem bateria real): T2, T1, decoys, delay 3 s e os 6 cenários benignos.
- SID 3400001 continua ativa: cerca de 2 alertas por scan.
- **No OPNsense, `EXTERNAL_NET = !HOME_NET`**: regras `$EXTERNAL_NET -> $HOME_NET`
  **nunca disparam para um atacante interno.** Usar `any`.
- A regra 3400130 v1 (count 10) dava falsos positivos em DNS sobre TCP e SMB.
  A v2 usa count 15 e exclui as portas 53, 80 e 443.
- **`atomic bash` não produz alerta offline (0)** — lacuna medida, que a tabela anterior não registava.

## Integração contínua

`.github/workflows/regras.yml` corre em cada push e pull request:

1. `make lint` — contagem e SIDs duplicados, sem Suricata
2. `make validar` — versão e sintaxe
3. `make matriz` — e publica o JSON como artefacto
4. **Falha se o total divergir do documentado** — impede a tabela deste README de ficar stale
5. **Falha se algum ficheiro versionado for alterado durante os testes**

> Fixa a versão do Suricata no CI. Reprodutibilidade sem versão fixa não é reprodutibilidade.

## Scans lentos: Zeek

O Suricata 8 conta pacotes, não portas distintas. O `detection_filter unique_on dst_port` só chega na 9.0 (GA prevista para Jul 2027). Por isso um `nmap -sS -T1` passa sem alertas.

O script `zeek/t1046-port-scan.zeek` (Zeek 8, SumStats) alerta quando uma origem falha ligações TCP a **10 portas únicas** do mesmo alvo em 5 minutos. O workflow `zeek` valida-o em CI.

| Teste | Resultado |
|---|---|
| Offline, 13 pcaps de ataque (incluindo T1, T2, delay 3s, decoys) | 13 de 13 alertam |
| Offline, 6 pcaps benignos | 0 alertas (máximo: 2 portas únicas falhadas) |
| Live, `nmap -sS -T1` a 14 portas comuns contra o OPNsense | Suricata 8.0.6: 0 alertas. Zeek 8.0.10: 1 alerta, aos 4m47s |

Limites:
- Pcaps sintéticos e um único alvo. Em rede real, varrimentos legítimos (monitorização, descoberta) dão falsos positivos.
- Janela fixa de 5 min: um scan lento pode ser cortado entre duas janelas.
- Só TCP. O limiar por omissão do antigo `scan.zeek` (15 portas) falharia o cenário T1, que tem 14.

Correr localmente: `zeek -C -r cenarios/pcaps/ataque_sS_comuns_T1.pcap zeek/t1046-port-scan.zeek` e ver `notice.log`.

## Aviso

Só em equipamento e redes tuas. Licença MIT (ver `LICENSE`).
Regras derivadas de aleksibovellan/opnsense-suricata-nmaps — ver `NOTICE`.

## Próximo

- Camada comportamental para o `-T1`: Zeek feito (ver acima). Falta RITA.
- Camada de endpoint: raw sockets criados por `-sS` são invisíveis à monitorização normal,
  mas visíveis por eBPF (Tetragon, Apache-2.0).
