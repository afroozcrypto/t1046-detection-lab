# Write-up 03: confirmação no lab real

Lab: OPNsense 26.7.6, Suricata 8.0.7, Kali 192.168.1.133 como atacante, alvo 192.168.1.1. Bateria de 9 out 2026, 19:39 a 20:06.

## Resultado
- Alertas totais: 1330 (regras antigas) para 12 (regras silenciosas).
- Offline e real coincidem nos 9 cenários.
- Única diferença: 3400103 deu 98 reais contra 99 offline. É uma regra ruidosa, já desativada.

## Pontos cegos fechados
1. `-sN` e `-sF`: sem regra própria antes. Agora 3400131 e 3400132.
2. `-sT` em portas comuns: coberto por 3400130.
3. `-g 53`: a regra 3400133 (porta 4444) é a única que dispara com porta de origem 53.
4. Ruído: 6 regras desativadas sem perder cobertura dos 9 cenários.

## Achados
- `EXTERNAL_NET = !HOME_NET` no template do OPNsense. Regras ET de scan com `$EXTERNAL_NET -> $HOME_NET` não disparam para o Kali interno. [verificado]
- Falso positivo da 3400130 v1 (count 10) em DNS sobre TCP e SMB. Corrigido na v2. [verificado offline]
- Alterações às regras só carregam após "Aplicar". [verificado]

## Limites
Ver README. Principal: `-sS -T1` em portas comuns não é detetado.

## Próximos passos
1. EVE syslog em vez de syslog (deprecated).
2. Pcaps reais com dumpcap para substituir os sintéticos.
3. SIEM: Wazuh 4.14.8 estável contra esperar o 5.0 (sem correlação por frequência nativa).
4. Zeek 9.0 LTS para o ponto cego -T1.

## Fontes
- https://docs.suricata.io (thresholding)
- https://docs.opnsense.org/manual/ips.html
- https://github.com/aleksibovellan/opnsense-suricata-nmaps
- https://attack.mitre.org/techniques/T1046/
