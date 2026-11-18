"""``hermes-assess``: verifica che le difese del server reggano.

Il preflight (``mcp_server.doctor``) risponde a «l'installazione è conforme?».
Questo pacchetto risponde a un'altra domanda — **le difese reggono?** — e per
farlo, minaccia per minaccia, *tenta l'operazione che la difesa deve
impedire* e registra se viene impedita.

In questa milestone (M0) il pacchetto contiene soltanto il **contratto**:

* :mod:`mcp_server.assess.catalogo` — le minacce, dichiarate come dati;
* :mod:`mcp_server.assess.referto` — lo schema di ciò che un giro produce.

Le prove arrivano in M1. Il design è in ``docs/assess.md``.
"""
