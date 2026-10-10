#!/usr/bin/env bash
# Bateria de deteção T1046 no lab real (correr no Kali, sem sudo).
# Repete no OPNsense os mesmos cenários que foram validados offline.
# Espera 150 s entre cenários porque as regras "type both" só alertam 1 vez
# por janela (até 135 s). Demora cerca de 30 minutos.
# Uso: ./testes/bateria.sh > resultados/AAAA-MM-DD-bateria.txt
set -u
F=~/suricata-syslog.log
ALVO=192.168.1.1
COMUNS=21,22,23,25,53,80,110,135,139,143,443,445,3389,8080

pgrep -x socat >/dev/null || { echo "FALHA: recetor socat parado"; exit 1; }

medir () {  # $1 = nome, resto = comando
  local nome="$1"; shift
  local s; s=$(stat -c %s "$F")
  "$@" >/dev/null 2>&1
  sleep 15
  # Conta SIDs nos dois formatos: fast log "[1:SID:REV]" e EVE JSON "signature_id":SID
  printf '%-22s %s\n' "$nome" "$(tail -c +$((s+1)) "$F" | grep -aoE '\[1:[0-9]+:|"signature_id":[0-9]+' | grep -oE '[0-9]{5,}' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
  sleep 150
}

echo "# Bateria $(date '+%F %T')"
medir sS          nmap -sS -T4 "$ALVO"
medir sT          nmap -sT -T4 "$ALVO"
medir sS_comuns   nmap -sS -p "$COMUNS" "$ALVO"
medir sT_comuns   nmap -sT -p "$COMUNS" "$ALVO"
medir sN          nmap -sN -T4 "$ALVO"
medir sF          nmap -sF -T4 "$ALVO"
medir sX          nmap -sX -T4 "$ALVO"
medir sS_g53      nmap -sS -T4 -g 53 "$ALVO"
medir atomic_bash bash -c "for p in \$(seq 1000 1100); do timeout 0.2 bash -c \"echo > /dev/tcp/$ALVO/\$p\" 2>/dev/null; done"
echo "# Fim $(date '+%F %T')"
