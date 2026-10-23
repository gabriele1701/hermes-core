"""Caricamento della configurazione del server.

La configurazione è in TOML, letta con ``tomllib`` della libreria standard:
nessuna dipendenza aggiunta, e un parser che non sa deserializzare oggetti
arbitrari. Per un componente che decide cosa può essere eseguito, la
superficie del parser di configurazione è parte della superficie d'attacco.

Fallimento in avvio, non degradazione
-------------------------------------

Una configurazione con un tool non conforme fa **fallire l'avvio**. Partire
con un registro caricato a metà sarebbe peggio che non partire: l'operatore
crederebbe di avere a disposizione dei tool che non ci sono, e scoprirebbe
quali solo al primo uso. Un errore all'avvio è rumoroso e si corregge subito.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from mcp_server.contracts import OwnerAgent

#: Chiavi ammesse al primo livello. Una chiave ignota è un errore e non un
#: campo da ignorare: di solito è un refuso, e un refuso silenzioso in una
#: configurazione di sicurezza è una impostazione che credi di aver messo.
_SEZIONI_AMMESSE = frozenset({"server", "vault", "tool"})
_CHIAVI_SERVER = frozenset(
    {
        "agent",
        "repo_root",
        "container_available",
        "log_path",
        "tool_python",
        "tool_python_flags",
    }
)
_CHIAVI_VAULT = frozenset({"backend", "stub_secrets"})

#: Interprete con cui vengono eseguiti i tool. Percorso **assoluto**: è il
#: punto dell'intera architettura in cui si decide quale codice gira, e
#: lasciarlo al ``PATH`` significa non saperlo.
TOOL_PYTHON_DEFAULT = Path("/usr/bin/python3")

#: Flag di isolamento dell'interprete dei tool.
#:
#: ``-I`` (modalità isolata) esclude da ``sys.path`` sia la directory dello
#: script sia lo user site dell'utente che esegue, e ignora le variabili
#: d'ambiente ``PYTHON*``. Chiude due vie con cui codice non verificato
#: entrerebbe in esecuzione pur lasciando intatto lo SHA dello script.
#:
#: ``-S`` salta anche ``site``, quindi nessun ``site-packages`` e nessun file
#: ``.pth`` di sistema. Costo: un tool che avesse bisogno di un pacchetto di
#: terze parti non partirebbe — e la risposta giusta in quel caso è un venv
#: dedicato in sola lettura per quel tool, non allentare i flag per tutti.
TOOL_PYTHON_FLAGS_DEFAULT = ("-I", "-S")


class ConfigError(Exception):
    """Configurazione assente, malformata o incoerente."""


@dataclass(frozen=True, slots=True)
class VaultConfig:
    """Quale backend di credenziali collegare."""

    backend: str = "stub"
    #: Nomi da seminare nel backend stub. Solo nomi: nessun valore in config.
    stub_secrets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """Configurazione completa di un'istanza del server.

    L'``agent`` è una proprietà dell'istanza, non un parametro delle chiamate:
    vedere ``server.py`` per il motivo.
    """

    agent: OwnerAgent
    repo_root: Path
    log_path: Path
    container_available: bool = False
    #: Interprete dei tool: percorso assoluto, verificato all'avvio.
    tool_python: Path = TOOL_PYTHON_DEFAULT
    tool_python_flags: tuple[str, ...] = TOOL_PYTHON_FLAGS_DEFAULT
    vault: VaultConfig = VaultConfig()
    #: Payload grezzi dei tool: la validazione spetta al registro, che la
    #: registra nel log d'audit.
    tools: tuple[Mapping[str, Any], ...] = ()


def load_config(path: str | Path) -> ServerConfig:
    """Carica e valida la configurazione del server.

    Solleva :class:`ConfigError` su qualunque anomalia: formato, chiavi
    ignote, agente inesistente, percorsi mancanti.
    """
    percorso = Path(path)
    if not percorso.is_file():
        raise ConfigError(f"configurazione assente: {percorso}")

    try:
        with percorso.open("rb") as fh:
            dati = tomllib.load(fh)
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"configurazione malformata: {err}") from err

    ignote = set(dati) - _SEZIONI_AMMESSE
    if ignote:
        raise ConfigError(
            f"sezioni non riconosciute: {', '.join(sorted(ignote))}. "
            f"Ammesse: {', '.join(sorted(_SEZIONI_AMMESSE))}"
        )

    server = dati.get("server")
    if not isinstance(server, dict):
        raise ConfigError("sezione [server] assente")
    _rifiuta_chiavi_ignote("server", server, _CHIAVI_SERVER)

    agent = _agente(server.get("agent"))
    repo_root = _percorso_obbligatorio(server, "repo_root", percorso)
    if not repo_root.is_dir():
        raise ConfigError(f"repo_root non è una directory: {repo_root}")

    log_path = _percorso(server.get("log_path"), percorso) or (
        repo_root / "logs" / "hermes-audit.jsonl"
    )

    container = server.get("container_available", False)
    if not isinstance(container, bool):
        raise ConfigError("server.container_available deve essere booleano")

    return ServerConfig(
        agent=agent,
        repo_root=repo_root,
        log_path=log_path,
        container_available=container,
        tool_python=_interprete(server.get("tool_python")),
        tool_python_flags=_flag_interprete(server.get("tool_python_flags")),
        vault=_vault(dati.get("vault")),
        tools=_tools(dati.get("tool")),
    )


# --------------------------------------------------------------------------- #
# Parti
# --------------------------------------------------------------------------- #


def _rifiuta_chiavi_ignote(
    sezione: str, valori: Mapping[str, Any], ammesse: frozenset[str]
) -> None:
    ignote = set(valori) - ammesse
    if ignote:
        raise ConfigError(
            f"[{sezione}]: chiavi non riconosciute: {', '.join(sorted(ignote))}"
        )


def _agente(valore: Any) -> OwnerAgent:
    """Converte il nome dell'agente, o solleva.

    Un agente non riconosciuto non può diventare un default: l'identità
    dell'istanza è ciò su cui si fonda il confine fra agenti.
    """
    if not isinstance(valore, str) or not valore:
        raise ConfigError("server.agent è obbligatorio")
    try:
        return OwnerAgent(valore)
    except ValueError as err:
        ammessi = ", ".join(a.value for a in OwnerAgent)
        raise ConfigError(
            f"server.agent non riconosciuto: {valore!r}. Ammessi: {ammessi}"
        ) from err


def _interprete(valore: Any) -> Path:
    """Valida l'interprete dei tool, o solleva.

    Deve essere un percorso **assoluto**, esistente ed eseguibile. Non si
    accetta un nome da risolvere nel ``PATH``: quale interprete esegue i tool
    è una decisione di sicurezza, e il ``PATH`` del server la delegherebbe
    all'ambiente in cui il server è stato avviato — che su una macchina
    cambia, e con esso cambia la superficie d'attacco.
    """
    if valore is None:
        candidato = TOOL_PYTHON_DEFAULT
    elif isinstance(valore, str) and valore:
        candidato = Path(valore).expanduser()
    else:
        raise ConfigError("server.tool_python deve essere una stringa non vuota")

    if not candidato.is_absolute():
        raise ConfigError(
            f"server.tool_python deve essere un percorso assoluto, non "
            f"{str(candidato)!r}: un nome risolto dal PATH non è deterministico"
        )
    if not candidato.is_file():
        raise ConfigError(f"server.tool_python non esiste: {candidato}")
    if not os.access(candidato, os.X_OK):
        raise ConfigError(f"server.tool_python non è eseguibile: {candidato}")
    return candidato


def _flag_interprete(valore: Any) -> tuple[str, ...]:
    """Valida i flag dell'interprete dei tool.

    Restano configurabili perché un tool futuro potrebbe richiedere un
    ambiente diverso, ma il default è il più stretto: chi li allenta lo fa
    scrivendolo in configurazione, dove si vede in review.
    """
    if valore is None:
        return TOOL_PYTHON_FLAGS_DEFAULT
    if not isinstance(valore, list) or not all(isinstance(f, str) for f in valore):
        raise ConfigError(
            "server.tool_python_flags deve essere una lista di stringhe"
        )
    if any(not f.startswith("-") or not f.strip() for f in valore):
        raise ConfigError(
            "server.tool_python_flags accetta solo opzioni dell'interprete "
            "(es. [\"-I\", \"-S\"]), non percorsi o argomenti"
        )
    return tuple(valore)


def _percorso(valore: Any, rispetto_a: Path) -> Path | None:
    """Risolve un percorso relativo rispetto alla directory della config."""
    if valore is None:
        return None
    if not isinstance(valore, str) or not valore:
        raise ConfigError("i percorsi devono essere stringhe non vuote")
    candidato = Path(valore).expanduser()
    if not candidato.is_absolute():
        candidato = rispetto_a.parent / candidato
    return candidato.resolve()


def _percorso_obbligatorio(
    valori: Mapping[str, Any], chiave: str, rispetto_a: Path
) -> Path:
    risolto = _percorso(valori.get(chiave), rispetto_a)
    if risolto is None:
        raise ConfigError(f"server.{chiave} è obbligatorio")
    return risolto


def _vault(sezione: Any) -> VaultConfig:
    if sezione is None:
        return VaultConfig()
    if not isinstance(sezione, dict):
        raise ConfigError("[vault] deve essere una sezione")
    _rifiuta_chiavi_ignote("vault", sezione, _CHIAVI_VAULT)

    backend = sezione.get("backend", "stub")
    if not isinstance(backend, str) or not backend:
        raise ConfigError("vault.backend deve essere una stringa non vuota")

    nomi = sezione.get("stub_secrets", [])
    if not isinstance(nomi, list) or not all(isinstance(n, str) for n in nomi):
        raise ConfigError("vault.stub_secrets deve essere una lista di stringhe")

    return VaultConfig(backend=backend, stub_secrets=tuple(nomi))


def _tools(sezione: Any) -> tuple[Mapping[str, Any], ...]:
    """Estrae i payload dei tool senza validarli.

    La validazione spetta al registro, che la registra nel log: un tool
    rifiutato deve lasciare traccia, e il caricatore non ha accesso all'audit.
    """
    if sezione is None:
        return ()
    if not isinstance(sezione, list) or not all(isinstance(t, dict) for t in sezione):
        raise ConfigError("[[tool]] deve essere una lista di tabelle")
    return tuple(sezione)


__all__ = ["ConfigError", "ServerConfig", "VaultConfig", "load_config"]
