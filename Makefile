# Reprodução offline. Requer Suricata 8 (medido em 8.0.7) e scapy.
# Uso: make validar | make pcaps | make matriz      (SURI=/caminho/suricata)
SURI ?= suricata
LOG  ?= /tmp/t1046-log

.PHONY: validar pcaps matriz tudo

tudo: validar pcaps matriz

validar:
	@$(SURI) -V 2>/dev/null | grep -q 'Suricata version 8' \
	  || { echo "⚠️  Isto foi medido em Suricata 8.0.7. Encontrei:"; \
	       $(SURI) -V 2>/dev/null || echo "   (suricata não encontrado — usa SURI=...)"; \
	       echo "   Instala a série 8 ou corre com SURI=/caminho/para/suricata-8"; exit 1; }
	@test -f /etc/suricata/classification.config \
	  || { echo "⚠️  Falta /etc/suricata/classification.config."; \
	       echo "   Vem do pacote do sistema: apt install suricata"; exit 1; }
	mkdir -p $(LOG)
	$(SURI) -T -c testes/suricata-lab.yaml -S regras/n4.rules -l $(LOG)

pcaps:
	python3 -I cenarios/gen_cenarios.py cenarios/pcaps

# O SURI vai por ambiente — já não se escreve em testes/matriz.py,
# por isso `git status` fica limpo depois de correr a matriz.
matriz:
	SURI="$(shell command -v $(SURI))" python3 -I testes/matriz.py \
	  regras/n4.rules cenarios/pcaps resultados/matriz-offline-n4.json

# Verificação rápida sem Suricata nenhum (roda no CI e à mão).
lint:
	@echo -n "regras ativas: "; grep -c '^alert' regras/n4.rules
	@echo -n "SIDs duplicados (tem de estar vazio): "
	@grep '^alert' regras/n4.rules | grep -o 'sid:[0-9]*' | sort | uniq -d
	@echo -n "regras sem msg: "; grep '^alert' regras/n4.rules | grep -vc 'msg:' || true
	@echo -n "regras sem sid: "; grep '^alert' regras/n4.rules | grep -vc 'sid:' || true
