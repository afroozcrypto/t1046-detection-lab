# Deteção de port scan (MITRE T1046) por contagem de portas únicas com falha.
# Cobre o que o Suricata 8 não faz (unique_on dst_port só chega na 9.0):
# scans lentos (-T1, -T2, delay) e scans de poucas portas.
#
# Critério: uma origem com >= port_threshold portas TCP distintas com ligações
# falhadas contra o mesmo alvo, dentro de port_interval.
# Janela tumbling (SumStats epoch): um scan lento pode ser cortado entre
# duas janelas. Ajustar port_interval ao scan mais lento que se quer apanhar.

@load base/frameworks/notice
@load base/frameworks/sumstats

module T1046;

export {
	redef enum Notice::Type += { Port_Scan };

	## Portas únicas falhadas por origem e alvo que disparam o alerta.
	const port_threshold: double = 10.0 &redef;

	## Janela de contagem.
	const port_interval: interval = 5min &redef;

	## Estados de ligação tratados como falha.
	const failed_states: set[string] = { "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "OTH" } &redef;
}

event zeek_init()
	{
	local r1 = SumStats::Reducer($stream="t1046.failed", $apply=set(SumStats::UNIQUE));

	SumStats::create([$name="t1046.port-scan",
	                  $epoch=port_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["t1046.failed"]$unique + 0.0;
	                  	},
	                  $threshold=port_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["t1046.failed"];
	                  	NOTICE([$note=Port_Scan,
	                  	        $src=key$host,
	                  	        $msg=fmt("T1046 port scan: %s tocou %d portas unicas em %s (janela %s)",
	                  	                 key$host, r$unique, key$str, port_interval),
	                  	        $sub=key$str,
	                  	        $identifier=cat(key$host, key$str)]);
	                  	}]);
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$conn || ! c$conn?$conn_state )
		return;

	if ( get_port_transport_proto(c$id$resp_p) != tcp )
		return;

	if ( c$conn$conn_state !in failed_states )
		return;

	SumStats::observe("t1046.failed",
	                  SumStats::Key($host=c$id$orig_h, $str=cat(c$id$resp_h)),
	                  SumStats::Observation($num=port_to_count(c$id$resp_p)));
	}
