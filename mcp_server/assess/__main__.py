"""``python -m mcp_server.assess CONFIG`` — normalmente via ``sudo bin/hermes-assess``.

Il lanciatore ``bin/hermes-assess`` mette il giro in un'unità senza rete;
chiamato così, direttamente, il giro gira dove capita. Serve ai test e allo
sviluppo, e il referto non lo nasconde: senza root le prove sotto altre
identità risultano non applicabili.
"""

from __future__ import annotations

import argparse
import sys

from mcp_server.assess import giro
from mcp_server.assess.catalogo import Natura, per_id
from mcp_server.assess.contesto import costruisci
from mcp_server.assess.referto import (
    CodiceUscita,
    EsitoProva,
    Referto,
    codice_uscita,
    in_json,
)
from mcp_server.config import ConfigError

_ETICHETTE = {
    EsitoProva.TIENE: "TIENE",
    EsitoProva.CEDE: "CEDE",
    EsitoProva.NON_VERIFICABILE: "NON VERIFICABILE",
    EsitoProva.NON_APPLICABILE: "NON APPLICABILE",
    EsitoProva.ACCETTATO: "ACCETTATO",
}


def stampa(referto: Referto, destinazione=sys.stdout) -> None:
    catalogo = per_id()
    scrivi = lambda testo="": print(testo, file=destinazione)  # noqa: E731
    scrivi(f"hermes-assess · {referto.host} · {referto.generato}")
    scrivi(f"config {referto.config} · commit {referto.commit[:12]}")
    scrivi()
    for limite in referto.limiti:
        scrivi(f"  limite: {limite}")
    scrivi()
    larghezza = max(len(e) for e in _ETICHETTE.values())
    for v in referto.voci:
        etichetta = _ETICHETTE[v.esito].ljust(larghezza)
        scrivi(f"[ {etichetta} ] {v.minaccia}  {catalogo[v.minaccia].titolo}")
        if v.nota:
            scrivi(f"    {v.nota}")
        misura = catalogo[v.minaccia].natura is Natura.MISURA
        for e in v.evidenze:
            segno = "positivo" if e.controllo_positivo else ("misura" if misura else "tentativo")
            stato = "riuscita" if e.riuscita else ("rifiutata" if e.eseguita else "senza risposta")
            dettaglio = f" — {e.dettaglio}" if e.dettaglio else ""
            scrivi(f"      {segno}: {e.operazione} {e.oggetto} come {e.identita}: {stato}{dettaglio}")
        if v.esito in (EsitoProva.CEDE, EsitoProva.ACCETTATO):
            scrivi(f"    rimedio: {catalogo[v.minaccia].rimedio}")
    scrivi()
    scrivi(f"esito: {codice_uscita(referto.voci).name.lower().replace('_', ' ')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hermes-assess",
        description="Verifica che le difese del server reggano. Vedere docs/assess.md.",
    )
    parser.add_argument("config", help="percorso di hermes.toml")
    parser.add_argument("--json", action="store_true", help="referto JSON su stdout")
    parser.add_argument(
        "--solo", default="", help="solo queste minacce, separate da virgole (AS-03,AS-05)"
    )
    args = parser.parse_args(argv)

    solo = frozenset(x.strip() for x in args.solo.split(",") if x.strip()) or None
    if solo is not None and (ignote := solo - set(per_id())):
        print(f"hermes-assess: minacce sconosciute: {', '.join(sorted(ignote))}", file=sys.stderr)
        return CodiceUscita.NON_ESEGUITO

    try:
        ctx = costruisci(args.config)
    except (ConfigError, OSError) as err:
        print(f"hermes-assess: configurazione non caricabile: {err}", file=sys.stderr)
        return CodiceUscita.NON_ESEGUITO

    referto = giro.esegui(ctx, solo=solo)
    try:
        if args.json:
            print(in_json(referto))
        else:
            stampa(referto)
    except BrokenPipeError:
        pass
    return codice_uscita(referto.voci)


if __name__ == "__main__":
    raise SystemExit(main())
