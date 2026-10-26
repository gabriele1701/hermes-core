"""Persistenza degli innalzamenti di tier.

Gli override di tier vivevano in un dizionario del processo, e l'host MCP avvia
un processo **per connessione**: un tool innalzato a Rosso tornava al proprio
tier dichiarato alla connessione successiva. Chi alza un tier dopo un incidente
si aspetta il contrario, e il log continuava a mostrare l'``override_set``
anche quando non era più in vigore — un controllo che decade in silenzio è
peggio di un controllo assente.

Tre fonti, nessuna che possa abbassare
--------------------------------------

Dopo questa patch il tier effettivo di un tool è il massimo di tre fonti:

1. il **tier dichiarato** nella spec, che resta un pavimento: nessun override
   lo tocca;
2. il campo ``override_tier`` in ``[[tool]]``, **versionato**, per gli
   innalzamenti che devono restare e che si vedono in review;
3. questo **store**, scritto a runtime quando l'innalzamento arriva via MCP.

Nessuna fonte può abbassare le altre, e cancellare una riga dello store non
declassa nulla: resta il massimo delle rimanenti, con il tier dichiarato come
pavimento.

Perché non serve ruotarlo
-------------------------

Il file è append-only come il log d'audit, ma a differenza di quello **non
cresce**: si scrive una riga soltanto quando il tier **sale davvero**. Dello
store importa solo il massimo per tool, e un tier può salire al massimo due
volte (verde → giallo → rosso), quindi il numero di righe ha un tetto
strutturale pari al doppio dei tool registrati.

Un modello che chiama ``raise_tool_tier("rosso")`` diecimila volte produce
**una** riga, non diecimila. Le altre 9999 richieste restano nel log d'audit,
dove è giusto che si vedano: in audit conta sapere che qualcuno ha insistito.

Questo elimina il problema che una rotazione avrebbe dovuto gestire — e che
una rotazione fatta male creerebbe, perché troncare questo file significherebbe
**perdere dei tier innalzati**, cioè provocare un declassamento silenzioso
tramite manutenzione.

Illeggibile non è vuoto
-----------------------

Le due condizioni di guasto sono trattate in modo opposto, di proposito.

* **Il file esiste e non si riesce a leggerlo** → :class:`OverrideStoreError`,
  e l'avvio non completa. Proseguire significherebbe applicare tier più bassi
  di quelli registrati, cioè allentare dei controlli perché un file non si
  apriva: è esattamente il caso in cui va preferito un server che non parte.
* **Il file non esiste e non si riesce a crearlo** → nessun errore. Non c'è
  nulla da perdere, quindi gli innalzamenti valgono per la connessione come
  prima, la cosa viene **dichiarata** nelle risposte (``override_scope``) e
  registrata nel log. Il preflight la segnala con il rimedio.

Una *singola riga* malformata è invece saltata e **contata**: un file corrotto
a metà non deve impedire l'avvio. Ma poiché ogni riga saltata potrebbe essere
un innalzamento perduto, il numero di scarti viene registrato nel log d'audit
e riportato dal preflight. Un silenzio, qui, sarebbe un declassamento
invisibile.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import stat
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from mcp_server.contracts import OwnerAgent, RiskTier

_FILE_MODE = 0o600
_DIR_MODE = 0o700

#: Nome del file dentro la directory di stato.
NOME_FILE = "overrides.jsonl"


class OverrideStoreError(Exception):
    """Lo store esiste ma non è leggibile.

    Distinta da un file assente: assente significa «nessun innalzamento
    registrato», illeggibile significa «non so quali innalzamenti ci sono», e
    le due cose non possono avere la stessa conseguenza.
    """


class OverrideScope(StrEnum):
    """Da dove viene l'override attivo, e quindi quanto dura.

    È la risposta alla domanda che un operatore si pone davvero dopo aver
    alzato un tier: *sopravvive?*
    """

    #: Nessun override: il tool è al tier dichiarato.
    NONE = "none"
    #: Scritto in configurazione versionata: dura, e si vede in review.
    CONFIG = "config"
    #: Registrato nello store: dura oltre questa connessione.
    PERSISTENT = "persistent"
    #: Solo in memoria: lo store non è collegato o non è scrivibile.
    SESSION = "session"

    @property
    def descrizione(self) -> str:
        """Durata in italiano, per il log d'audit.

        Il log lo legge una persona, a volte mesi dopo: ``session`` da solo
        non dice se l'innalzamento che sta leggendo fosse ancora in vigore.
        """
        return _DESCRIZIONI[self]


_DESCRIZIONI = {
    OverrideScope.NONE: "nessun override",
    OverrideScope.CONFIG: "persistente, da configurazione versionata",
    OverrideScope.PERSISTENT: "persistente, registrato nello store",
    OverrideScope.SESSION: "solo questa connessione",
}


@dataclass(frozen=True, slots=True)
class CaricamentoOverride:
    """Esito della rilettura dello store."""

    #: Tier massimo per tool, fra tutte le righe leggibili.
    tiers: dict[str, RiskTier] = field(default_factory=dict)
    #: Righe non vuote presenti nel file.
    righe: int = 0
    #: Righe illeggibili, saltate. Vanno riportate: ciascuna potrebbe essere
    #: un innalzamento perduto.
    scartate: int = 0


class OverrideStore:
    """Registro append-only degli innalzamenti di tier.

    Il costruttore **non tocca il filesystem**: un componente che il server
    costruisce all'avvio non deve poter impedire l'avvio per un percorso non
    ancora creato. Directory e file nascono alla prima scrittura.

    Parameters
    ----------
    path:
        File JSONL dello store.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    @classmethod
    def in_directory(cls, directory: str | os.PathLike[str]) -> OverrideStore:
        """Store dentro una directory di stato, col nome convenzionale."""
        return cls(Path(directory) / NOME_FILE)

    @property
    def path(self) -> Path:
        return self._path

    # -- lettura ------------------------------------------------------------ #

    def carica(self) -> CaricamentoOverride:
        """Rilegge lo store e calcola il tier massimo per tool.

        Raises
        ------
        OverrideStoreError
            Se il file esiste ma non si riesce ad aprirlo o a leggerlo.
        """
        tiers: dict[str, RiskTier] = {}
        righe = scartate = 0

        if not self._path.exists():
            return CaricamentoOverride()

        try:
            with self._path.open("r", encoding="utf-8", errors="replace") as fh:
                contenuto = fh.readlines()
        except OSError as err:
            raise OverrideStoreError(
                f"store degli override non leggibile: {self._path}: {err}. "
                f"Il file esiste, quindi potrebbe contenere innalzamenti di "
                f"tier: proseguire significherebbe applicarne di più bassi."
            ) from err

        for riga in contenuto:
            if not riga.strip():
                continue
            righe += 1
            voce = _interpreta(riga)
            if voce is None:
                scartate += 1
                continue
            tool_id, tier = voce
            precedente = tiers.get(tool_id)
            if precedente is None or tier.rank > precedente.rank:
                tiers[tool_id] = tier

        return CaricamentoOverride(tiers=tiers, righe=righe, scartate=scartate)

    # -- scrittura ---------------------------------------------------------- #

    def registra(
        self,
        tool_id: str,
        tier: RiskTier,
        *,
        agent: OwnerAgent | None = None,
        correlation_id: uuid.UUID | None = None,
    ) -> None:
        """Appende un innalzamento. Solleva :class:`OSError` se non riesce.

        Va chiamata **solo per un incremento reale** del tier effettivo: è ciò
        che dà allo store il suo tetto strutturale. Il chiamante lo sa, perché
        ha appena confrontato il tier richiesto con quello effettivo.
        """
        voce = {
            "ts": _dt.datetime.now(tz=_dt.UTC).isoformat(),
            "tool_id": tool_id,
            "tier": tier.value,
            "agent": agent.value if agent else None,
            "correlation_id": str(correlation_id) if correlation_id else None,
        }
        riga = (json.dumps(voce, ensure_ascii=False) + "\n").encode("utf-8")

        self._path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
        try:
            os.write(fd, riga)
            # Un innalzamento di tier perso in un buffer a un crash sarebbe un
            # declassamento silenzioso: qui l'fsync non è negoziabile come nel
            # log, perché queste righe sono poche per costruzione.
            os.fsync(fd)
        finally:
            os.close(fd)
        _restringi(self._path, _FILE_MODE)
        _restringi(self._path.parent, _DIR_MODE)


def _interpreta(riga: str) -> tuple[str, RiskTier] | None:
    """Legge una riga, o ``None`` se è illeggibile."""
    try:
        voce = json.loads(riga)
        tool_id = voce["tool_id"]
        tier = RiskTier(voce["tier"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    if not isinstance(tool_id, str) or not tool_id:
        return None
    return tool_id, tier


def _restringi(percorso: Path, modo: int) -> None:
    """Impone i permessi se non sono già quelli, tollerando un rifiuto.

    Stessa ragione di ``audit.py``: un file irrigidito con ``chattr +a``
    rifiuta la ``chmod`` anche al proprietario, e insistere renderebbe lo store
    non scrivibile dal proprio scrittore.
    """
    try:
        if stat.S_IMODE(percorso.stat().st_mode) != modo:
            os.chmod(percorso, modo)
    except OSError:
        pass


__all__ = [
    "CaricamentoOverride",
    "NOME_FILE",
    "OverrideScope",
    "OverrideStore",
    "OverrideStoreError",
]
