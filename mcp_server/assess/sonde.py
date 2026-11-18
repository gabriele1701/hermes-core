"""Le sonde: un'operazione sola, eseguita sotto un'identità, che dice com'è andata.

Una sonda è un programma Python di poche righe lanciato con ``-I -S`` e
l'interprete dei tool, sotto l'identità da mettere alla prova. Stampa una
riga JSON e niente altro. La prova non interpreta testo libero: confronta
campi.

Tre operazioni, e nessuna scrive
--------------------------------

* ``leggi`` — apre e legge un byte;
* ``apri_scrittura`` — apre con ``O_WRONLY|O_APPEND`` e chiude **senza
  scrivere**. Se l'apertura riesce la difesa ha già ceduto, e un byte in più
  aggiungerebbe solo un danno;
* ``crea`` — apre una directory con ``O_TMPFILE``: un file senza nome, che
  sparisce alla chiusura. Prova la creabilità senza lasciare tracce.

Tutte con ``O_NOFOLLOW``: una sonda che segue un link misura il bersaglio del
link, non il percorso chiesto. Se il percorso legittimo è un link, il
controllo positivo fallisce e la prova lo dice (*non verificabile*) invece di
contare un ``ELOOP`` come un rifiuto.

Tre esiti, non due
------------------

Riuscita, rifiutata, **non eseguita**. Un wrapper che rifiuta, un timeout,
un output che non è JSON: lì la sonda non ha risposto, e trattarlo come
«l'operazione è fallita» farebbe dire *tiene* a una prova che non ha provato
niente. È la forma già pagata di un'interrogazione che non sa rispondere e
ne fabbrica una plausibile.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

from mcp_server.assess.contesto import Contesto, come_utente
from mcp_server.assess.referto import Evidenza
from mcp_server.executor import PREFISSO_UNITA

OPERAZIONI = ("leggi", "apri_scrittura", "crea")

SONDA = """\
import errno, json, os, sys
op, oggetto = sys.argv[1], sys.argv[2]
NF = os.O_NOFOLLOW | os.O_NONBLOCK
try:
    if op == "leggi":
        fd = os.open(oggetto, os.O_RDONLY | NF)
        try:
            os.read(fd, 1)
        finally:
            os.close(fd)
    elif op == "apri_scrittura":
        os.close(os.open(oggetto, os.O_WRONLY | os.O_APPEND | NF))
    elif op == "crea":
        os.close(os.open(oggetto, os.O_TMPFILE | os.O_WRONLY, 0o600))
    else:
        raise SystemExit(2)
except OSError as err:
    nome = errno.errorcode.get(err.errno, str(err.errno))
    print(json.dumps({"riuscita": False, "errno": nome, "messaggio": err.strerror or ""}))
else:
    print(json.dumps({"riuscita": True, "errno": None, "messaggio": ""}))
"""

#: Tempo concesso alla sonda dentro l'unità, e tetto locale che comprende
#: l'avvio dell'unità: gli stessi valori della sonda di lettura del preflight.
TEMPO_NELL_UNITA = 10
TIMEOUT_LOCALE = 30


def argv_sonda(ctx: Contesto, operazione: str, oggetto: Path) -> list[str]:
    if operazione not in OPERAZIONI:
        raise ValueError(f"operazione di sonda sconosciuta: {operazione!r}")
    return [
        str(ctx.cfg.tool_python),
        *ctx.cfg.tool_python_flags,
        "-c",
        SONDA,
        operazione,
        str(oggetto),
    ]


def interpreta(
    esito: subprocess.CompletedProcess[str] | None,
    *,
    operazione: str,
    oggetto: Path,
    identita: str,
    controllo_positivo: bool,
    motivo: str = "",
) -> Evidenza:
    """L'evidenza di una sonda. ``esito`` ``None`` = non è nemmeno partita."""
    base = dict(
        operazione=operazione,
        identita=identita,
        oggetto=str(oggetto),
        controllo_positivo=controllo_positivo,
    )
    if esito is None:
        return Evidenza(**base, riuscita=False, eseguita=False, dettaglio=motivo)
    righe = (esito.stdout or "").strip().splitlines()
    try:
        dati = json.loads(righe[-1]) if righe else None
    except json.JSONDecodeError:
        dati = None
    if esito.returncode != 0 or not isinstance(dati, dict) or "riuscita" not in dati:
        errore = (esito.stderr or "").strip().splitlines()
        return Evidenza(
            **base,
            riuscita=False,
            eseguita=False,
            dettaglio=(
                f"la sonda non ha risposto (esito {esito.returncode}): "
                f"{errore[-1] if errore else 'nessun messaggio'}"
            ),
        )
    if dati["riuscita"]:
        return Evidenza(**base, riuscita=True)
    return Evidenza(
        **base,
        riuscita=False,
        dettaglio=f"{dati.get('errno')}: {dati.get('messaggio', '')}",
    )


def _lancia(argv: list[str]) -> tuple[subprocess.CompletedProcess[str] | None, str]:
    try:
        return (
            subprocess.run(  # noqa: S603 - argv esplicito, shell=False
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_LOCALE,
                check=False,
            ),
            "",
        )
    except subprocess.TimeoutExpired:
        return None, f"nessuna risposta entro {TIMEOUT_LOCALE}s"
    except OSError as err:
        return None, f"{type(err).__name__}: {err}"


def come(
    ctx: Contesto,
    utente: str,
    operazione: str,
    oggetto: Path,
    *,
    controllo_positivo: bool = False,
) -> Evidenza:
    """La sonda eseguita come ``utente``, con ``setpriv``."""
    argv = come_utente(utente, argv_sonda(ctx, operazione, oggetto))
    esito, motivo = _lancia(argv)
    return interpreta(
        esito,
        operazione=operazione,
        oggetto=oggetto,
        identita=utente,
        controllo_positivo=controllo_positivo,
        motivo=motivo,
    )


def dal_wrapper(
    ctx: Contesto,
    operazione: str,
    oggetto: Path,
    *,
    opzione: str | None = None,
) -> Evidenza:
    """La sonda eseguita dal wrapper installato, come vi girerebbe un tool.

    Stesso wrapper, stesso uid, stessa unità e stessi limiti di un tool vero:
    cambia solo l'ultimo anello. Da root si chiama direttamente: ``sudo`` è il
    modo in cui il servizio arriva a root, e qui ci siamo già.
    """
    if ctx.cfg.tool_runner is None:
        raise ValueError("tool_runner non configurato")
    argv = [
        str(ctx.cfg.tool_runner),
        f"{PREFISSO_UNITA}-{uuid.uuid4()}",
        str(TEMPO_NELL_UNITA),
        *((opzione,) if opzione else ()),
        "--",
        *argv_sonda(ctx, operazione, oggetto),
    ]
    esito, motivo = _lancia(argv)
    return interpreta(
        esito,
        operazione=operazione,
        oggetto=oggetto,
        identita=f"{ctx.utente_tool} (unità del wrapper{', ' + opzione if opzione else ''})",
        controllo_positivo=False,
        motivo=motivo,
    )


__all__ = ["OPERAZIONI", "SONDA", "argv_sonda", "come", "dal_wrapper", "interpreta"]
