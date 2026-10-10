# Reprodução offline. Requer Suricata 8.0.7 e scapy.
# Uso: make validar | make pcaps | make matriz   (SURI=/caminho/suricata)
SURI ?= suricata
LOG  ?= /tmp/t1046-log

validar:
	mkdir -p $(LOG)
	$(SURI) -T -c testes/suricata-lab.yaml -S regras/n4.rules -l $(LOG)

pcaps:
	python3 -I cenarios/gen_cenarios.py cenarios/pcaps

matriz:
	sed -i 's#^SURI = .*#SURI = "$(shell command -v $(SURI))"#' testes/matriz.py
	python3 -I testes/matriz.py regras/n4.rules cenarios/pcaps resultados/matriz-offline-n4.json
