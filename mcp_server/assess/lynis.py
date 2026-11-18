"""Adattatore per il referto di lynis (M1.5, anticipato).

Legge il file che lynis scrive alla fine di un audit, di norma
``/var/log/lynis-report.dat``, e ne porta nel referto di hermes-assess i soli
gruppi concordati: **SSH** (``SSH-*``) e **autenticazione e account**
(``AUTH-*``).

Cosa non fa
-----------

* **Non lancia lynis e non lo installa.** Eseguire un audit e installare
  pacchetti sono scelte dell'operatore; questo modulo legge un file.
* **Non trasforma le segnalazioni in esiti di prova.** Una voce di lynis dice
  «lo strumento segnala questo», non «la difesa cede»: sta in un elenco a
  parte del referto e non entra nel codice d'uscita.
* **Non si fida del file.** Sta sull'host sorvegliato: ogni campo passa da
  ``dato_non_fidato``, e le righe che non hanno la forma attesa si saltano e
  si contano.

Il formato
----------

Righe ``chiave=valore``. Le segnalazioni sono ``warning[]=`` e
``suggestion[]=``, con il valore diviso da ``|``: codice del test, messaggio,
dettaglio, soluzione. ``lynis_version`` e ``report_datetime_start`` danno
versione e data dell'audit.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from pathlib import Path

from mcp_server.assess.referto import VoceEsterna

PREDEFINITO = Path("/var/log/lynis-report.dat")

#: I gruppi di test concordati: SSH, autenticazione e account.
GRUPPI = ("SSH-", "AUTH-")

#: Oltre questa età il referto di lynis descrive una macchina che potrebbe
#: non esistere più: lo si dice nei limiti, non lo si scarta.
VECCHIO_GIORNI = 7

#: Tetto sul file: un referto di lynis è di qualche decina di KB.
TETTO_BYTE = 4 * 1024 * 1024

_TIPI = {"warning[]": "avviso", "suggestion[]": "suggerimento"}
_CODICE = re.compile(r"^[A-Z]{2,8}-[0-9]{3,5}$")


@dataclass(frozen=True, slots=True)
class Lettura:
    voci: tuple[VoceEsterna, ...]
    #: Righe dei limiti da aggiungere al referto: età, righe scartate, assenza.
    limiti: tuple[str, ...]


def _vuoto(valore: str) -> str:
    return "" if valore.strip() in {"", "-"} else valore.strip()


def interpreta(testo: str, *, adesso: _dt.datetime | None = None) -> Lettura:
    """Le voci dei gruppi concordati e i limiti della lettura."""
    versione, data = "versione sconosciuta", None
    voci: list[VoceEsterna] = []
    scartate = 0
    for riga in testo.splitlines():
        chiave, sep, valore = riga.partition("=")
        if not sep:
            continue
        if chiave == "lynis_version":
            versione = valore.strip() or versione
        elif chiave == "report_datetime_start":
            data = valore.strip()
        elif chiave in _TIPI:
            campi = (valore.split("|") + ["", "", "", ""])[:4]
            codice = campi[0].strip()
            if not _CODICE.fullmatch(codice) or not _vuoto(campi[1]):
                scartate += 1
                continue
            if not codice.startswith(GRUPPI):
                continue
            voci.append(
                VoceEsterna(
                    origine="",  # si completa sotto, quando la versione è nota
                    test=codice,
                    tipo=_TIPI[chiave],
                    messaggio=_vuoto(campi[1]),
                    dettaglio=_vuoto(campi[2]),
                    soluzione=_vuoto(campi[3]),
                )
            )

    origine = f"lynis {versione}"
    voci = [
        VoceEsterna(origine, v.test, v.tipo, v.messaggio, v.dettaglio, v.soluzione)
        for v in voci
    ]
    limiti = [f"{origine}: solo i gruppi SSH e autenticazione/account (SSH-*, AUTH-*)"]
    limiti.append(_eta(data, adesso or _dt.datetime.now()))
    if scartate:
        limiti.append(f"{origine}: {scartate} righe di segnalazione senza la forma attesa, ignorate")
    return Lettura(tuple(voci), tuple(limiti))


def _eta(data: str | None, adesso: _dt.datetime) -> str:
    if not data:
        return "lynis: data dell'audit non dichiarata nel referto"
    try:
        quando = _dt.datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "lynis: data dell'audit illeggibile nel referto"
    giorni = (adesso - quando).days
    if giorni > VECCHIO_GIORNI:
        return (
            f"lynis: audit del {data}, {giorni} giorni fa — descrive la "
            f"macchina di allora; rilanciare lynis per un quadro attuale"
        )
    return f"lynis: audit del {data}"


def leggi(percorso: Path = PREDEFINITO) -> Lettura:
    """Legge il referto. Assente o illeggibile: nessuna voce, e il limite lo dice."""
    try:
        with percorso.open("rb") as fh:
            dati = fh.read(TETTO_BYTE + 1)
    except FileNotFoundError:
        return Lettura((), (f"lynis: nessun referto in {percorso} — fonte non applicabile",))
    except OSError as err:
        return Lettura((), (f"lynis: referto in {percorso} non leggibile ({type(err).__name__})",))
    limiti: tuple[str, ...] = ()
    if len(dati) > TETTO_BYTE:
        dati = dati[:TETTO_BYTE]
        limiti = (f"lynis: referto oltre {TETTO_BYTE} byte, letto solo l'inizio",)
    lettura = interpreta(dati.decode("utf-8", errors="replace"))
    return Lettura(lettura.voci, lettura.limiti + limiti)


__all__ = ["GRUPPI", "PREDEFINITO", "Lettura", "interpreta", "leggi"]
