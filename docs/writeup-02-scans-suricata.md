# Write-up 02: Quanto barulho faz um port scan no Suricata, e porque o `-sT` era invisível

Laboratório pessoal, rede isolada. Atacante e alvo são máquinas minhas.

## Objetivo

Medir quantos alertas cada tipo de scan do nmap gera num OPNsense com Suricata, perceber porque um deles não gerava nenhum, e reduzir o ruído para 1 alerta por scan.

## Ambiente

| Peça | Versão |
|---|---|
| Hipervisor | KVM / virt-manager, Linux Mint 22.3 |
| Firewall | OPNsense 26.7 Community, FreeBSD 15 |
| IDS | Suricata 8.0.6, modo IDS (PCAP live) na LAN |
| Atacante | Kali 2026.2, nmap 7.99 |
| Regras | ET Open + 10 regras comunitárias para nmap (aleksibovellan/opnsense-suricata-nmaps v2.1) |

Rede: LAN 192.168.1.0/24 isolada, OPNsense em .1, Kali em .133. Os alertas saem do OPNsense por syslog (UDP) para o Kali, onde são contados por SID.

## Baseline: alertas por corrida (`-T4`, alvo 192.168.1.1)

| Scan | Alertas por SID | Total |
|---|---|---|
| `-sS` | 278 (3400002) + 2 (3400001) + 2 (3400020) | 282 |
| `-sT` (antes da correção) | 0 na regra `-sT` (3400003) | 0 |
| `-sT` (depois da correção) | 99 (3400103) + 2 (3400020) | 101 |
| `-sX` | 666 (3400005) + 2 (3400020) | 668 |
| `-sV -p 80` | 4 (2024364, ET SCAN Possible Nmap User-Agent) | 4 |
| `-sV -p 443` | 0 | 0 |
| `-sn` | 0 | 0 |

Repetível: o `-sT` deu 99 em seis corridas seguidas.

Leituras:
- O `-sS` dispara 1 alerta por cada 7 SYN (`threshold: type threshold, count 7`). Cerca de 980 portas x 2 tentativas = 1960 SYN; 1960 / 7 = 280.
- O `-sV` em HTTPS não gera nada: o User-Agent do nmap vai cifrado.
- O `-sn` na mesma sub-rede usa ARP, que o Suricata não inspeciona.
- A porta 4444 (regra 3400020) dispara em todos os scans: qualquer pacote para essa porta, sem limiar.

## O problema: `-sT` com zero alertas

A regra comunitária para `-sT` (SID 3400003) exige `window:32120`.

Captura no Kali durante o `-sT`:

```
sudo tcpdump -ni any -c 5 'tcp[tcpflags] == tcp-syn and dst host 192.168.1.1'
... Flags [S], seq ..., win 64240, options [mss 1460,sackOK,TS ...,nop,wscale 9]
```

O `-sT` não fabrica pacotes. Usa o `connect()` do kernel, por isso a janela TCP é a do sistema operativo: 64240 num Linux atual. A regra nunca casava.

O `-sS`, pelo contrário, fabrica o SYN com janela 1024, e é isso que a regra dele procura.

**Lição:** um SYN de `-sT` é igual a um SYN legítimo de qualquer Linux. Não existe assinatura por pacote. Só se deteta por comportamento: muitas portas diferentes em pouco tempo.

Correção: regra nova ao lado da original (SID 3400103), igual mas com `window:64240`. Resultado: 0 para 99 alertas por scan. Em rede real esta regra dá falsos positivos; no laboratório serve.

## Reduzir o ruído: de 280 para 1

Na documentação do Suricata 8.0.6 há quatro modos de `threshold`:

| Modo | Comportamento | Serve para scans? |
|---|---|---|
| `threshold` | 1 alerta a cada N ocorrências | É o que gera 280 |
| `limit` | No máximo N alertas por janela, a partir da 1.ª ocorrência | Perde o critério "N em T segundos" |
| `both` | No máximo 1 alerta por janela, só depois de N ocorrências | Sim |
| `backoff` | Só funciona com `track by_flow` | Não: um scan são muitos fluxos |

O `unique_on dst_port` (contar portas distintas) só existe na versão em desenvolvimento. Não está na 8.0.6.

Regras de teste, lado a lado com as originais:

```
alert tcp any any -> any ![portas comuns] (msg:"POSSBL PORT SCAN (NMAP -sS) BOTH"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type both, track by_src, count 7, seconds 135; classtype:attempted-recon; sid:3400102; rev:1;)
alert tcp any any -> any ![portas comuns] (msg:"LAB PORT SCAN (NMAP -sT win 64240) BOTH"; flow:to_server; flags:S; window:64240; threshold:type both, track by_src, count 20, seconds 70; classtype:attempted-recon; sid:3400113; rev:1;)
```

### Validação fora do laboratório

Antes de instalar, gerei um pcap sintético (scapy) que imita os dois scans medidos: SYN com janela 1024 e MSS 1460 para o `-sS`, SYN com janela 64240 e opções de kernel Linux para o `-sT`, 1000 portas, 2 tentativas cada. Corri o Suricata 7.0.3 em modo offline contra esse pcap:

| SID | Regra | Alertas |
|---|---|---|
| 3400002 | `-sS` original | 280 |
| 3400102 | `-sS` com `type both` | 1 |
| 3400103 | `-sT` corrigida | 99 |
| 3400113 | `-sT` com `type both` | 1 |
| 3400120 | porta 4444 com `type limit` | 1 por scan |

O pcap sintético reproduz os números reais (280 e 99), o que dá confiança no modelo. A confirmação no OPNsense está no write-up 03.

## Problemas encontrados pelo caminho

- A caixa de pesquisa de Alertas do OPNsense procura no texto da mensagem, não no SID.
- A hora dos alertas na interface vem em UTC; no syslog vem em hora local.
- O recetor de syslog morreu quando a sessão SSH caiu e deu falsos zeros. Solução: `setsid nohup`.
- A rede de casa e a do laboratório usavam a mesma gama 192.168.1.0/24. A partir do anfitrião, 192.168.1.1 era o router de casa.
- O `-sV -p 80` demora cerca de 60 s porque o nmap não reconhece a resposta HTTP do OPNsense e esgota todas as sondas.

## Fontes

- Suricata 8.0.6, Thresholding Keywords: https://docs.suricata.io/en/suricata-8.0.6/rules/thresholding.html
- Regras comunitárias: https://github.com/aleksibovellan/opnsense-suricata-nmaps
- Suricata 8.0.7: https://forum.suricata.io/t/suricata-8-0-7-released/6467
- OPNsense 26.7 changelog: https://docs.opnsense.org/releases/CE_26.7.html
