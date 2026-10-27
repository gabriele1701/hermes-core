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
import pwd
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from mcp_server.config import ConfigError, ServerConfig, load_config
from mcp_server.contracts import RiskTier, ToolSpec
from mcp_server.executor import risolvi_script, sha256_file
from mcp_server.overrides import NOME_FILE as NOME_FILE_OVERRIDE
from mcp_server.overrides import OverrideStore, OverrideStoreError
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


def _log(
    referto: Referto, cfg: ServerConfig, percorso_config: Path | None = None
) -> None:
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
            _perche_non_scrivibile(percorso, cfg, percorso_config),
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


def _stato(
    referto: Referto, cfg: ServerConfig, percorso_config: Path | None = None
) -> None:
    """Verifica lo store che fa sopravvivere gli innalzamenti di tier.

    Due esiti negativi diversi, per due cose diverse:

    * ``state_dir`` **non configurata** è un AVVISO. Il server funziona, e il
      comportamento — innalzamenti validi per la connessione — è quello di
      sempre e viene dichiarato nelle risposte. Manca una proprietà, non un
      pezzo.
    * ``state_dir`` configurata e **non utilizzabile** è un ERRORE. Qui
      l'operatore ha chiesto la persistenza e non la sta ottenendo: è un
      controllo che si crede di avere e non c'è, che è il caso peggiore dei
      due e la ragione per cui questo preflight esiste.
    """
    if cfg.state_dir is None:
        servizio = _utente_di_servizio(cfg) or "<utente-di-servizio>"
        referto.aggiungi(
            "store degli override",
            Esito.AVVISO,
            "server.state_dir non configurata: gli innalzamenti di tier "
            "valgono solo per la connessione",
            f"Per renderli persistenti (l'utente dev'essere quello che esegue "
            f"il SERVER, non chi lancia il preflight):\n"
            f"             sudo install -d -o {servizio} -g {servizio} -m 700 "
            f"/var/lib/hermes/state\n"
            f"             poi in [server]: "
            f"state_dir = \"/var/lib/hermes/state\"\n"
            f"             Attenzione: un percorso relativo viene risolto "
            f"rispetto alla cartella della configurazione, quindi finirebbe "
            f"dentro il repo.",
        )
        return

    percorso = cfg.state_dir / NOME_FILE_OVERRIDE

    # Illeggibile non è vuoto: se il file c'è e non si apre, il server non
    # parte di proposito, perché potrebbe contenere innalzamenti da applicare.
    # Si prova a caricarlo sempre, senza chiedere prima se esista: la domanda
    # «esiste?» è a sua volta rispondibile solo se la directory è
    # attraversabile, e su una state_dir con i permessi sbagliati morirebbe
    # qui — proprio nel controllo che dovrebbe diagnosticarla.
    try:
        OverrideStore(percorso).carica()
    except OverrideStoreError as err:
        referto.aggiungi(
            "store degli override",
            Esito.ERRORE,
            str(err),
            f"Il server non parte finché lo store esiste e non è leggibile.\n"
            "             " + _perche_non_scrivibile(percorso, cfg, percorso_config),
        )
        return
    except OSError as err:  # pragma: no cover - rete di sicurezza
        referto.aggiungi(
            "store degli override",
            Esito.ERRORE,
            f"non ispezionabile: {err}",
            "             " + _perche_non_scrivibile(percorso, cfg, percorso_config),
        )
        return

    try:
        cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(percorso, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.close(fd)
    except OSError as err:
        referto.aggiungi(
            "store degli override",
            Esito.ERRORE,
            f"configurata ma non scrivibile: {err}",
            f"sudo install -d -o {_utente_di_servizio(cfg) or '<utente-di-servizio>'} "
            f"-g {_utente_di_servizio(cfg) or '<utente-di-servizio>'} -m 700 "
            f"{cfg.state_dir}\n"
            "             " + _perche_non_scrivibile(percorso, cfg, percorso_config),
        )
        return

    try:
        dentro = cfg.state_dir.resolve().is_relative_to(cfg.repo_root.resolve())
    except (OSError, ValueError):  # pragma: no cover
        dentro = False
    if dentro:
        referto.aggiungi(
            "store fuori dal repo",
            Esito.AVVISO,
            f"state_dir sta dentro repo_root: {cfg.state_dir}",
            "Uno stato di sicurezza dentro l'albero di lavoro sparisce a un "
            "checkout o a una pulizia, e un innalzamento di tier perso non "
            "lo segnala nessuno. Spostarlo fuori (es. /var/lib/hermes).",
        )

    try:
        esito = OverrideStore(percorso).carica()
        st = percorso.stat()
    except (OverrideStoreError, OSError) as err:  # pragma: no cover
        referto.aggiungi(
            "store degli override",
            Esito.ERRORE,
            f"creato ma non rileggibile: {err}",
            "             " + _perche_non_scrivibile(percorso, cfg, percorso_config),
        )
        return

    modo = stat.S_IMODE(st.st_mode)
    proprietario = _utente(st.st_uid)
    servizio = _utente_di_servizio(cfg)
    if servizio is not None and proprietario != servizio:
        # Il file viene creato da chi lancia il preflight. Lanciato dall'utente
        # sbagliato — da root, tipicamente — lo crea intestato a lui, e il
        # servizio poi non ci scrive: il preflight direbbe «ok» su una
        # persistenza che non funziona. Un falso verde è il guasto peggiore
        # che un preflight possa produrre.
        referto.aggiungi(
            "proprietario dello store",
            Esito.ERRORE,
            f"appartiene a {proprietario}, ma il server gira come {servizio}: "
            f"gli innalzamenti non verranno persistiti",
            f"sudo chattr -a {percorso} 2>/dev/null; "
            f"sudo chown {servizio}: {percorso}\n"
            f"             Poi rilanciare il preflight come {servizio}, non "
            f"come root: è l'esecuzione dall'utente sbagliato ad aver creato "
            f"il file così.",
        )

    if modo & 0o077:
        referto.aggiungi(
            "permessi dello store",
            Esito.AVVISO,
            f"permessi {modo:04o}: leggibile da altri utenti",
            f"chmod 600 {percorso}",
        )

    if esito.scartate:
        referto.aggiungi(
            "store degli override",
            Esito.AVVISO,
            f"{esito.scartate} righe illeggibili su {esito.righe}: ciascuna "
            f"potrebbe essere un innalzamento perduto",
            f"Ispezionare {percorso} e ripristinare a mano i tier che "
            f"risultassero mancanti con raise_tool_tier.",
        )
    else:
        referto.aggiungi(
            "store degli override",
            Esito.OK,
            f"{percorso}: {esito.righe} righe, "
            f"{len(esito.tiers)} tool con innalzamento persistente "
            f"(permessi {modo:04o})",
        )


def _attributi(percorso: Path) -> str | None:
    """Flag di ``lsattr -d``, o ``None`` se non si riescono a leggere.

    ``None`` significa «non lo so» — ``lsattr`` assente, filesystem che non li
    supporta, permessi — e non «nessun attributo». Chi legge deve poter
    distinguere le due cose.
    """
    try:
        esito = subprocess.run(
            ["lsattr", "-d", str(percorso)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if esito.returncode != 0 or not esito.stdout.split():
        return None
    return esito.stdout.split()[0]


def _append_only(percorso: Path) -> bool:
    """Se il percorso ha l'attributo append-only."""
    flag = _attributi(percorso)
    return flag is not None and "a" in flag


def _descrivi(percorso: Path) -> str:
    """Proprietario, permessi e attributi di un percorso, in una riga.

    Non solleva mai: è un aiuto alla diagnosi, e un aiuto alla diagnosi che
    muore trasforma un errore riportato in un traceback. Dire «non
    ispezionabile» è già un'informazione utile, perché di solito significa che
    il livello che blocca è più in alto.
    """
    st = _stat(percorso)
    if st is None:
        return f"{percorso}: non ispezionabile"
    flag = _attributi(percorso)
    attributi = f" · attributi '{flag}'" if flag and flag.strip("-") else ""
    tipo = "dir " if stat.S_ISDIR(st.st_mode) else ""
    return (
        f"{tipo}{percorso}: {_utente(st.st_uid)} (uid {st.st_uid}), "
        f"gid {st.st_gid}, modo {stat.S_IMODE(st.st_mode):04o}{attributi}"
    )


def _utente(uid: int) -> str:
    """Nome dell'utente, o il numero se non risolvibile."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:  # pragma: no cover
        return str(uid)


def _utente_di_servizio(cfg: ServerConfig) -> str | None:
    """Chi eseguirà davvero il server, dedotto dai fatti del dispiegamento.

    Non è chi sta lanciando il preflight. Su una VM fatta come documentata il
    server gira come utente di servizio via comando forzato SSH, mentre il
    preflight lo lancia a mano l'amministratore: due utenti diversi, e i
    rimedi che dicono ``$(id -un)`` producono comandi giusti per la persona
    sbagliata.

    Il proprietario della directory del log è il testimone più affidabile che
    abbiamo: è l'unico posto, insieme a ``state_dir``, in cui il servizio deve
    poter scrivere, e viene creato apposta per lui. ``None`` significa che non
    si riesce a dedurlo, e allora il rimedio resta generico invece di
    inventare un nome.
    """
    st = _stat(cfg.log_path.parent)
    if st is None:
        return None
    nome = _utente(st.st_uid)
    return nome if nome != str(st.st_uid) else None


def _proprietario(percorso: Path) -> str | None:
    """Nome del proprietario di un percorso, o ``None`` se non si vede."""
    st = _stat(percorso)
    return _utente(st.st_uid) if st is not None else None


def _stat(percorso: Path) -> os.stat_result | None:
    """``stat`` che non solleva: ``None`` significa «non si riesce a guardare».

    Serve perché ``Path.exists()`` **solleva** ``PermissionError`` quando una
    directory del percorso non è attraversabile — ed è esattamente la
    situazione che questo codice deve descrivere. Trovato riproducendo il
    guasto invece di immaginarlo.
    """
    try:
        return percorso.stat()
    except OSError:
        return None


def _perche_non_scrivibile(
    percorso: Path, cfg: ServerConfig, percorso_config: Path | None = None
) -> str:
    """Spiega perché un percorso non si lascia scrivere, con i fatti sotto.

    Il rimedio precedente nominava **sempre** la trappola del percorso
    relativo. Su un percorso assoluto e corretto, bloccato da un banale
    problema di proprietario, quel testo manda a cercare dalla parte sbagliata:
    un diagnostico che indica una causa plausibile ma falsa è peggio di uno che
    dice solo «non riesco», perché viene creduto.

    Qui si riportano i fatti — chi sta eseguendo, chi possiede cosa, con quali
    permessi e attributi — e la trappola si nomina solo quando il sintomo c'è
    davvero, cioè quando il percorso risolto è finito dentro il repo.
    """
    righe: list[str] = []

    try:
        gruppi = ",".join(str(g) for g in os.getgroups()) or "nessuno"
    except OSError:  # pragma: no cover
        gruppi = "non leggibili"
    io_sono = _utente(os.geteuid())
    righe.append(
        f"In esecuzione come {io_sono} (uid {os.geteuid()}), gruppi {gruppi}."
    )
    righe.append(f"Percorso risolto: {percorso}")

    # Il livello che blocca davvero è il primo antenato ispezionabile: se una
    # directory non è attraversabile, i permessi di ciò che sta sotto non si
    # vedono nemmeno, e descriverli sarebbe impossibile oltre che inutile.
    righe.append(_descrivi(percorso))
    esistente = percorso
    while _stat(esistente) is None and esistente != esistente.parent:
        esistente = esistente.parent
        righe.append(_descrivi(esistente))
    if esistente == percorso and esistente.parent != esistente:
        righe.append(_descrivi(esistente.parent))

    flag = _attributi(esistente) or ""
    if "i" in flag:
        righe.append(
            f"Causa probabile: attributo IMMUTABILE. Per il log serve 'a' "
            f"(append-only), non 'i': sudo chattr -i {esistente} && "
            f"sudo chattr +a {esistente}"
        )
    elif not os.access(esistente, os.W_OK):
        proprietario = _proprietario(esistente)
        servizio = _utente_di_servizio(cfg) or proprietario or "<utente-di-servizio>"
        if proprietario and proprietario != io_sono:
            righe.append(
                f"Causa probabile: appartiene a {proprietario}, tu sei "
                f"{io_sono}. Se {proprietario} è l'utente che esegue il "
                f"server, NON cambiare i permessi: è il preflight a essere "
                f"lanciato dall'utente sbagliato. Rilanciarlo così:"
            )
        else:
            righe.append(
                "Causa probabile: proprietario o permessi. Il preflight va "
                "eseguito come l'utente che eseguirà il server:"
            )
        righe.append(
            f"    sudo -u {servizio} {sys.executable} -m mcp_server.doctor "
            f"{percorso_config or '<config>'}"
        )

    try:
        if percorso.resolve().is_relative_to(cfg.repo_root.resolve()):
            righe.append(
                "Attenzione: il percorso risolto sta DENTRO repo_root. Un "
                "valore relativo in server.log_path viene risolto rispetto "
                "alla cartella della configurazione: 'var/log/...' finisce nel "
                "repo, '/var/log/...' no. Uno slash di differenza."
            )
    except (OSError, ValueError):  # pragma: no cover
        pass

    return "\n             ".join(righe)


def _interprete(referto: Referto, cfg: ServerConfig) -> None:
    """Verifica l'interprete con cui girano i tool.

    Lo SHA pinna lo script, non chi lo esegue: se l'interprete fosse
    scrivibile da chi non deve, il pinning proteggerebbe il file sbagliato.
    """
    percorso = cfg.tool_python
    flag = " ".join(cfg.tool_python_flags) or "(nessuno)"

    try:
        prova = subprocess.run(
            [str(percorso), *cfg.tool_python_flags, "-c", "import sys; print(sys.version.split()[0])"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as err:
        referto.aggiungi(
            "interprete dei tool",
            Esito.ERRORE,
            f"non eseguibile: {_prima_riga(err)}",
            "Correggere server.tool_python (percorso assoluto di un interprete).",
        )
        return

    if prova.returncode != 0:
        referto.aggiungi(
            "interprete dei tool",
            Esito.ERRORE,
            f"i flag '{flag}' impediscono l'avvio: "
            f"{_errore_da_stderr(prova.stderr) or f'exit={prova.returncode}'}",
            "Verificare server.tool_python_flags.",
        )
        return

    referto.aggiungi(
        "interprete dei tool",
        Esito.OK,
        f"{percorso} (Python {prova.stdout.strip()}) con flag '{flag}'",
    )

    # Isolamento effettivo, non dichiarato.
    mancanti = [f for f in ("-I", "-S") if f not in cfg.tool_python_flags]
    if mancanti:
        referto.aggiungi(
            "isolamento dei tool",
            Esito.AVVISO,
            f"flag di isolamento assenti: {', '.join(mancanti)}",
            "-I esclude user site e directory dello script da sys.path; "
            "-S salta site e i .pth. Senza, codice non verificato può girare "
            "prima dello script lasciando lo SHA intatto.",
        )
    else:
        referto.aggiungi("isolamento dei tool", Esito.OK, "-I e -S attivi")

    # L'interprete non deve stare dentro il repo, né essere scrivibile da altri.
    try:
        dentro = percorso.resolve().is_relative_to(cfg.repo_root.resolve())
    except (OSError, ValueError):  # pragma: no cover
        dentro = False
    if dentro:
        referto.aggiungi(
            "interprete fuori dal repo",
            Esito.ERRORE,
            f"l'interprete sta dentro repo_root: {percorso}",
            "L'interprete non è coperto dallo SHA degli script: va preso da "
            "una posizione di sistema, non dal repo.",
        )
    else:
        referto.aggiungi("interprete fuori dal repo", Esito.OK, "posizione di sistema")

    try:
        modo = stat.S_IMODE(percorso.stat().st_mode)
        proprietario = percorso.stat().st_uid
    except OSError:  # pragma: no cover
        return
    if modo & 0o022:
        referto.aggiungi(
            "permessi dell'interprete",
            Esito.ERRORE,
            f"scrivibile da gruppo o altri (modo {modo:04o})",
            f"sudo chmod go-w {percorso}",
        )
    else:
        referto.aggiungi(
            "permessi dell'interprete",
            Esito.OK,
            f"modo {modo:04o}, uid proprietario {proprietario}",
        )


def _limiti(referto: Referto, cfg: ServerConfig) -> None:
    """Riporta i limiti di contenimento dei processi.

    Non sono guasti da rilevare ma impostazioni da rendere visibili: un
    operatore che non sa qual è il tetto sull'output non sa interpretare un
    risultato troncato.
    """
    referto.aggiungi(
        "limiti di esecuzione",
        Esito.OK,
        f"output max {cfg.max_output_bytes // 1024} KiB per stream · "
        f"{cfg.max_concurrent_tools} esecuzioni contemporanee · "
        f"stdin dei tool su /dev/null · discendenza terminata al timeout",
    )


#: Quanti file esaminare al massimo nel controllo di scrivibilità. Serve a non
#: trasformare il preflight in una scansione del filesystem su un repo grande.
_LIMITE_SCANSIONE = 20_000

#: Quanti percorsi scrivibili elencare nel referto prima di fermarsi: l'elenco
#: serve a far capire il problema, non a essere esaustivo.
_MAX_SEGNALATI = 5


def _scrivibilita(referto: Referto, cfg: ServerConfig) -> None:
    """Verifica che chi esegue il server non possa riscrivere ciò che esegue.

    È la mitigazione reale della finestra TOCTOU fra verifica dello SHA ed
    esecuzione: l'hash protegge dalla modifica accidentale, non da chi
    controlla il conto che può riscrivere gli script.

    Il controllo scende ai **file** e non si ferma alla directory, perché il
    caso reale lo ha mostrato: la directory può essere in sola lettura mentre
    un singolo file, riscritto da un ``git pull`` con una umask permissiva, è
    rimasto scrivibile. Il virtualenv è compreso di proposito — un ``.venv``
    scrivibile dall'utente di servizio è peggio di uno script modificabile,
    perché contiene le librerie del *server* e non ha uno SHA che possa
    smascherarlo.

    Quando il controllo non può dire nulla
    --------------------------------------

    Il risultato è significativo **solo se il preflight gira con l'utente di
    servizio**. Per root e per il proprietario del repo la risposta è nota in
    anticipo — possono scrivere comunque, e il proprietario potrebbe in ogni
    caso cambiarsi i permessi da sé — quindi segnalarlo come errore sarebbe
    rumore che blocca il referto senza informare.

    In quei due casi si dichiara che il controllo non è applicabile e si dice
    come eseguirlo in modo utile. Un controllo che non sa rispondere deve
    dirlo, non rispondere male.
    """
    radice = cfg.repo_root
    utente = os.geteuid()

    if utente == 0:
        referto.aggiungi(
            "scrivibilità del codice",
            Esito.AVVISO,
            "eseguito come root: il controllo non è applicabile, root scrive comunque",
            "Eseguirlo con l'utente di servizio:\n"
            "             sudo -u <utente> <venv>/bin/python "
            "-m mcp_server.doctor <config>",
        )
        return

    try:
        proprietario = radice.stat().st_uid
    except OSError as err:  # pragma: no cover
        referto.aggiungi("scrivibilità del codice", Esito.ERRORE, str(err))
        return

    if utente == proprietario:
        referto.aggiungi(
            "scrivibilità del codice",
            Esito.AVVISO,
            f"eseguito dal proprietario del repo (uid {utente}): il controllo "
            "non è applicabile, il proprietario può comunque modificare i permessi",
            "Eseguirlo con l'utente di servizio:\n"
            "             sudo -u <utente> <venv>/bin/python "
            "-m mcp_server.doctor <config>",
        )
        return

    scrivibili: list[Path] = []
    esaminati = 0
    troncato = False

    for percorso in radice.rglob("*"):
        if ".git" in percorso.parts:
            continue
        if percorso.is_dir() or percorso.is_symlink():
            continue
        esaminati += 1
        if esaminati > _LIMITE_SCANSIONE:
            troncato = True
            break
        if os.access(percorso, os.W_OK):
            scrivibili.append(percorso)
            if len(scrivibili) >= _MAX_SEGNALATI:
                break

    if scrivibili:
        elenco = ", ".join(str(p.relative_to(radice)) for p in scrivibili)
        referto.aggiungi(
            "scrivibilità del codice",
            Esito.ERRORE,
            f"{len(scrivibili)} o più file sono scrivibili dall'utente di "
            f"servizio: {elenco}",
            "Chi esegue non deve poter riscrivere ciò che esegue. Con le ACL, "
            "così che valga anche per i file futuri:\n"
            f"             sudo setfacl -R -m g:<gruppo>:rX {radice}\n"
            f"             sudo setfacl -R -d -m g:<gruppo>:rX {radice}",
        )
        return

    dettaglio = f"{esaminati} file esaminati, nessuno scrivibile dal servizio"
    if troncato:
        dettaglio += f" (scansione fermata a {_LIMITE_SCANSIONE})"
    referto.aggiungi("scrivibilità del codice", Esito.OK, dettaglio)


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
    _log(referto, cfg, percorso)
    _stato(referto, cfg, percorso)
    _interprete(referto, cfg)
    _limiti(referto, cfg)
    _scrivibilita(referto, cfg)
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
    try:
        stampa(referto)
    except BrokenPipeError:
        # Succede passando l'output a `head` o `grep -m`: non è un guasto del
        # preflight, e morire con un traceback farebbe sospettare il contrario.
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 0 if referto.pronto else 1
    return 0 if referto.pronto else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
