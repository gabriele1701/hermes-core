"""Preflight: verifica che il server sia pronto *prima* di coinvolgere Hermes.

    python -m mcp_server.doctor config/hermes.toml

Serve a separare due domande che altrimenti si confondono: «il server
funziona?» e «Hermes lo sta lanciando correttamente?». Se il preflight è
verde e Hermes non vede i tool, il problema è nella registrazione lato
Hermes; se il preflight è rosso, è inutile cercare altrove.

Ogni controllo dice cosa non va **e cosa fare**: un diagnostico che riporta
un errore senza il rimedio sposta il lavoro invece di farlo.

Esiti: ``OK`` tutto a posto · ``AVVISO`` funziona ma c'è qualcosa da sapere ·
``ERRORE`` non funzionerà. Il codice d'uscita è 0 solo se non ci sono errori.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from mcp_server.config import ConfigError, ServerConfig, load_config
from mcp_server.contracts import RiskTier, ToolSpec
from mcp_server.executor import risolvi_script, sha256_file
from mcp_server.tiers import derive_policy_for

_TIMEOUT_HANDSHAKE = 30


class Esito(StrEnum):
    OK = "OK"
    AVVISO = "AVVISO"
    ERRORE = "ERRORE"


@dataclass(slots=True)
class Controllo:
    """Risultato di un singolo controllo."""

    nome: str
    esito: Esito
    messaggio: str
    rimedio: str = ""


@dataclass(slots=True)
class Referto:
    controlli: list[Controllo] = field(default_factory=list)

    def aggiungi(
        self, nome: str, esito: Esito, messaggio: str, rimedio: str = ""
    ) -> Controllo:
        c = Controllo(nome, esito, messaggio, rimedio)
        self.controlli.append(c)
        return c

    @property
    def errori(self) -> list[Controllo]:
        return [c for c in self.controlli if c.esito is Esito.ERRORE]

    @property
    def avvisi(self) -> list[Controllo]:
        return [c for c in self.controlli if c.esito is Esito.AVVISO]

    @property
    def pronto(self) -> bool:
        return not self.errori


# --------------------------------------------------------------------------- #
# Controlli
# --------------------------------------------------------------------------- #


def _configurazione(referto: Referto, percorso: Path) -> ServerConfig | None:
    try:
        cfg = load_config(percorso)
    except ConfigError as err:
        referto.aggiungi(
            "configurazione",
            Esito.ERRORE,
            str(err),
            "Correggere il file; partire da config/hermes.example.toml.",
        )
        return None
    except NotImplementedError as err:
        referto.aggiungi("configurazione", Esito.ERRORE, str(err))
        return None

    referto.aggiungi(
        "configurazione",
        Esito.OK,
        f"valida · agente '{cfg.agent}' · {len(cfg.tools)} tool dichiarati",
    )
    return cfg


def _radice(referto: Referto, cfg: ServerConfig) -> None:
    if not cfg.repo_root.is_dir():
        referto.aggiungi(
            "repo_root",
            Esito.ERRORE,
            f"non è una directory: {cfg.repo_root}",
            "Correggere server.repo_root (relativo alla cartella della config).",
        )
        return
    referto.aggiungi("repo_root", Esito.OK, str(cfg.repo_root))


def _log(referto: Referto, cfg: ServerConfig) -> None:
    percorso = cfg.log_path
    try:
        percorso.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(percorso, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.close(fd)
    except OSError as err:
        referto.aggiungi(
            "log d'audit",
            Esito.ERRORE,
            f"non scrivibile: {err}",
            "Verificare permessi e percorso di server.log_path. "
            "Attenzione: un percorso **relativo** viene risolto rispetto alla "
            "cartella della configurazione, quindi\n"
            "             'var/log/...' finisce dentro il repo mentre "
            "'/var/log/...' è assoluto.\n"
            f"             Percorso risolto: {percorso}",
        )
        return

    modo = stat.S_IMODE(percorso.stat().st_mode)
    if modo & 0o077:
        referto.aggiungi(
            "log d'audit",
            Esito.AVVISO,
            f"permessi {modo:04o}: leggibile da altri utenti",
            f"chmod 600 {percorso}",
        )
    else:
        referto.aggiungi("log d'audit", Esito.OK, f"{percorso} (permessi {modo:04o})")

    if not _append_only(percorso):
        referto.aggiungi(
            "log append-only",
            Esito.AVVISO,
            "l'attributo append-only non è impostato: il log è riscrivibile",
            f"sudo chattr +a {percorso}",
        )
    else:
        referto.aggiungi("log append-only", Esito.OK, "attributo +a impostato")


def _append_only(percorso: Path) -> bool:
    """Legge l'attributo append-only con ``lsattr``, se disponibile."""
    try:
        esito = subprocess.run(
            ["lsattr", "-d", str(percorso)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if esito.returncode != 0:
        return False
    return "a" in esito.stdout.split()[0] if esito.stdout.split() else False


def _scrivibilita_script(referto: Referto, cfg: ServerConfig) -> None:
    """Verifica la mitigazione del TOCTOU: gli script non devono essere nostri.

    Se l'utente che esegue il server può riscrivere gli script, la verifica
    dello SHA protegge dall'errore ma non da chi controlla quel conto.
    """
    radice = cfg.repo_root
    if os.access(radice, os.W_OK):
        referto.aggiungi(
            "scrivibilità script",
            Esito.AVVISO,
            f"l'utente corrente può scrivere in {radice}: la verifica dello SHA "
            "resta utile contro l'errore, non contro chi controlla questo conto",
            "In uso continuativo, eseguire il server con un utente che abbia "
            "solo lettura sul repo.",
        )
    else:
        referto.aggiungi(
            "scrivibilità script", Esito.OK, "il repo non è scrivibile da questo utente"
        )


def _tool(referto: Referto, cfg: ServerConfig) -> None:
    if not cfg.tools:
        referto.aggiungi(
            "tool",
            Esito.AVVISO,
            "nessun tool dichiarato: il server parte ma non espone nulla",
        )
        return

    for payload in cfg.tools:
        tool_id = str(payload.get("tool_id", "<senza tool_id>"))
        try:
            spec = ToolSpec(**payload)
        except Exception as err:  # pydantic ValidationError e simili
            referto.aggiungi(
                f"tool {tool_id}",
                Esito.ERRORE,
                f"spec non conforme: {_prima_riga(err)}",
                "Il server non partirebbe: l'avvio fallisce al primo tool non conforme.",
            )
            continue
        _integrita(referto, cfg, spec)
        _eseguibilita(referto, spec)


def _integrita(referto: Referto, cfg: ServerConfig, spec: ToolSpec) -> None:
    try:
        script = risolvi_script(cfg.repo_root, spec.exec_path)
    except Exception as err:
        referto.aggiungi(
            f"tool {spec.tool_id}",
            Esito.ERRORE,
            f"script non utilizzabile: {_prima_riga(err)}",
            "Verificare exec_path (relativo a repo_root) e che il file esista.",
        )
        return

    effettivo = sha256_file(script)
    if effettivo != spec.exec_sha256:
        referto.aggiungi(
            f"tool {spec.tool_id}",
            Esito.ERRORE,
            f"SHA non corrisponde · dichiarato {spec.exec_sha256[:16]}… · "
            f"effettivo {effettivo[:16]}…",
            f"Se la modifica allo script è voluta, aggiornare exec_sha256 a:\n"
            f"             {effettivo}",
        )
        return

    referto.aggiungi(
        f"tool {spec.tool_id}",
        Esito.OK,
        f"tier {spec.default_tier} · integrità verificata · {script.name}",
    )


def _eseguibilita(referto: Referto, spec: ToolSpec) -> None:
    """Segnala i tool che non sono invocabili in questa milestone."""
    policy = derive_policy_for(spec)
    if policy.requires_confirmation:
        motivi = []
        if spec.default_tier is not RiskTier.VERDE:
            motivi.append(f"tier {spec.default_tier} (conferma {policy.technical})")
        if spec.personal_data:
            motivi.append("flag dati personali")
        referto.aggiungi(
            f"tool {spec.tool_id} · eseguibilità",
            Esito.AVVISO,
            f"richiede conferma ({', '.join(motivi)}): ritornerà "
            "needs_confirmation senza essere eseguito",
            "Atteso: il flusso di conferma non è ancora collegato "
            "(vedere docs/debito-sicurezza.md).",
        )


def _vault(referto: Referto, cfg: ServerConfig) -> None:
    if cfg.vault.backend == "stub":
        referto.aggiungi(
            "vault",
            Esito.AVVISO,
            f"backend 'stub': {len(cfg.vault.stub_secrets)} segreti finti, "
            "nessuna credenziale reale",
            "Atteso in questa milestone.",
        )
    else:
        referto.aggiungi(
            "vault",
            Esito.ERRORE,
            f"backend '{cfg.vault.backend}' non collegato: l'avvio fallirebbe",
            "In questa milestone è disponibile solo 'stub'.",
        )


def _container(referto: Referto, cfg: ServerConfig) -> None:
    richiedenti = [
        str(t.get("tool_id"))
        for t in cfg.tools
        if t.get("requires_container") is True
    ]
    if richiedenti and not cfg.container_available:
        referto.aggiungi(
            "container",
            Esito.AVVISO,
            f"non disponibile, ma richiesto da: {', '.join(richiedenti)} "
            "— quei tool verranno negati, non eseguiti sull'host",
            "Comportamento voluto. Per abilitarli serve il runtime isolato.",
        )
    else:
        referto.aggiungi(
            "container",
            Esito.OK,
            "disponibile" if cfg.container_available else "non richiesto da alcun tool",
        )


def _handshake(referto: Referto, percorso_config: Path) -> None:
    """Avvia il server come farebbe Hermes e verifica il dialogo MCP.

    Verifica anche che su stdout non finisca nulla che non sia JSON-RPC: è la
    causa più comune di fallimento con un host MCP, perché un singolo ``print``
    fuori posto corrompe il protocollo senza alcun messaggio d'errore utile.
    """
    richiesta = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "hermes-core-doctor", "version": "1"},
        },
    }
    try:
        esito = subprocess.run(
            [sys.executable, "-m", "mcp_server.server", str(percorso_config)],
            input=json.dumps(richiesta) + "\n",
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_HANDSHAKE,
            check=False,
        )
    except subprocess.TimeoutExpired:
        referto.aggiungi(
            "avvio su stdio",
            Esito.ERRORE,
            f"nessuna risposta entro {_TIMEOUT_HANDSHAKE}s",
            "Provare a mano: python -m mcp_server.server <config>",
        )
        return

    righe = [r for r in esito.stdout.splitlines() if r.strip()]
    if not righe:
        referto.aggiungi(
            "avvio su stdio",
            Esito.ERRORE,
            f"nessuna risposta su stdout (exit={esito.returncode})"
            + (
                f"\n             causa: {_errore_da_stderr(esito.stderr)}"
                if esito.stderr
                else ""
            ),
            "Il server non è partito per la causa riportata sopra. "
            "Per vedere il traceback completo:\n"
            f"             {sys.executable} -m mcp_server.server {percorso_config}",
        )
        return

    sporche = [r for r in righe if not _e_json(r)]
    if sporche:
        referto.aggiungi(
            "stdout pulito",
            Esito.ERRORE,
            f"{len(sporche)} righe non JSON su stdout, es.: {sporche[0][:60]!r}",
            "Qualcosa scrive su stdout e corrompe il protocollo MCP. "
            "Ogni output diagnostico deve andare su stderr.",
        )
        return
    referto.aggiungi("stdout pulito", Esito.OK, "solo JSON-RPC, nessun rumore")

    try:
        risposta = json.loads(righe[0])
        nome = risposta["result"]["serverInfo"]["name"]
        protocollo = risposta["result"]["protocolVersion"]
    except (json.JSONDecodeError, KeyError, TypeError) as err:
        referto.aggiungi(
            "avvio su stdio",
            Esito.ERRORE,
            f"risposta di initialize inattesa: {_prima_riga(err)}",
        )
        return

    referto.aggiungi(
        "avvio su stdio",
        Esito.OK,
        f"handshake completato · server '{nome}' · protocollo {protocollo}",
    )


# --------------------------------------------------------------------------- #
# Utilità
# --------------------------------------------------------------------------- #


def _e_json(riga: str) -> bool:
    try:
        json.loads(riga)
    except json.JSONDecodeError:
        return False
    return True


def _prima_riga(valore: object) -> str:
    testo = str(valore).strip().splitlines()
    return testo[0][:300] if testo else ""


def _errore_da_stderr(stderr: str) -> str:
    """Estrae da stderr la riga che dice davvero cosa è andato storto.

    La **prima** riga di un traceback è ``Traceback (most recent call last):``,
    che non informa di nulla: l'eccezione sta in fondo. Qui si prende l'ultima
    riga non vuota, e per un traceback si risale anche alla riga di contesto
    precedente, perché un ``PermissionError`` è utile solo se accompagnato dal
    percorso che l'ha provocato.
    """
    righe = [
        r.rstrip()
        for r in str(stderr).splitlines()
        if r.strip() and not _solo_marcatori(r)
    ]
    if not righe:
        return ""
    ultima = righe[-1]
    if len(righe) >= 2 and righe[0].startswith("Traceback"):
        contesto = righe[-2].strip()
        if contesto and not contesto.startswith("File "):
            return f"{ultima[:240]} | {contesto[:120]}"
    return ultima[:360]


def _solo_marcatori(riga: str) -> bool:
    """Se la riga è solo l'indicatore di posizione di Python 3.11+ (``~~~^^^``)."""
    return bool(riga.strip()) and not (set(riga.strip()) - set("~^ "))


# --------------------------------------------------------------------------- #
# Esecuzione
# --------------------------------------------------------------------------- #


def esegui(percorso_config: str | Path) -> Referto:
    """Esegue tutti i controlli e restituisce il referto."""
    percorso = Path(percorso_config)
    referto = Referto()

    cfg = _configurazione(referto, percorso)
    if cfg is None:
        return referto

    _radice(referto, cfg)
    _log(referto, cfg)
    _scrivibilita_script(referto, cfg)
    _vault(referto, cfg)
    _container(referto, cfg)
    _tool(referto, cfg)
    _handshake(referto, percorso)
    return referto


def stampa(referto: Referto, destinazione=sys.stdout) -> None:
    """Stampa il referto in forma leggibile."""
    simboli = {Esito.OK: "  ok  ", Esito.AVVISO: "avviso", Esito.ERRORE: "ERRORE"}
    print("Preflight hermes-core", file=destinazione)
    print("=" * 72, file=destinazione)
    for c in referto.controlli:
        print(f"[{simboli[c.esito]}] {c.nome}: {c.messaggio}", file=destinazione)
        if c.rimedio:
            for riga in c.rimedio.splitlines():
                print(f"           -> {riga}", file=destinazione)
    print("=" * 72, file=destinazione)

    if referto.pronto:
        coda = (
            f" ({len(referto.avvisi)} avvisi, nessuno bloccante)"
            if referto.avvisi
            else ""
        )
        print(f"PRONTO: il server è utilizzabile da Hermes{coda}.", file=destinazione)
        print(
            "Se Hermes non vede i tool, il problema è nella registrazione "
            "lato Hermes, non nel server.",
            file=destinazione,
        )
    else:
        print(
            f"NON PRONTO: {len(referto.errori)} errori da risolvere "
            "(vedere i rimedi sopra).",
            file=destinazione,
        )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="hermes-core-doctor",
        description=(
            "Verifica che il server MCP sia pronto prima di registrarlo in Hermes."
        ),
    )
    parser.add_argument("config", help="percorso del file di configurazione TOML")
    args = parser.parse_args(argv)

    referto = esegui(args.config)
    stampa(referto)
    return 0 if referto.pronto else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
