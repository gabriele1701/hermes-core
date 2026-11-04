"""Gate di esecuzione dei tool.

Unico punto da cui un tool può essere eseguito, e quindi unico punto in cui
tutti i controlli vengono applicati. Nessun componente esegue script per conto
proprio: un secondo percorso di esecuzione sarebbe un secondo insieme di
controlli da mantenere allineato, e prima o poi non lo sarebbe più.

Ordine dei controlli
--------------------

L'ordine non è arbitrario, ciascun passo presuppone il precedente:

1. **Il tool è registrato.** Un tool sconosciuto non ha metadati, quindi non
   ha nemmeno un tier: non c'è modo di decidere alcunché su di lui.
2. **L'agente è il proprietario.** Confine fra agenti, applicato dal registro.
3. **Il requisito di container è soddisfatto.** Un tool che dichiara
   ``requires_container`` e si ritrova senza runtime viene **negato**, non
   eseguito sull'host: la degradazione silenziosa verso l'ambiente meno
   isolato è esattamente il guasto che l'isolamento esiste per impedire.
4. **L'integrità dello script.** Lo SHA-256 del file deve corrispondere a
   quello dichiarato nella spec.
5. **L'autorizzazione.** Se la policy richiede una conferma e non ne è stata
   fornita, l'esecuzione resta ``PENDING``.

L'integrità precede l'autorizzazione di proposito: non ha senso chiedere a
qualcuno di autorizzare l'esecuzione di uno script la cui identità non è
ancora stata verificata. Si conferma qualcosa che si sa cos'è.

Verifica dell'integrità: a ogni esecuzione
------------------------------------------

Lo SHA dichiarato viene ricalcolato **prima di ogni esecuzione**, non una
volta all'avvio. Un controllo all'avvio lascerebbe aperta tutta la finestra
fra avvio ed esecuzione, che su un server a lunga vita è l'intera giornata.

Resta una finestra TOCTOU irriducibile fra il calcolo dell'hash e lo spawn del
processo: il file potrebbe cambiare in quei millisecondi. Chiuderla
richiederebbe di eseguire dal descrittore già aperto e verificato, cosa che
Python non offre in modo portabile. La protezione reale è che la directory
degli script non sia scrivibile dall'utente che esegue il server. È
registrato in ``docs/debito-sicurezza.md``.

L'interprete è deciso, non ereditato
------------------------------------

Lo SHA pinna lo *script*, ma lo script non è l'unico codice che gira: lo
esegue un interprete, che prima di arrivare al file carica altro. Finché
l'interprete era ``python3`` risolto dal ``PATH``, **non era noto quale
codice venisse eseguito**: dipendeva dall'ambiente in cui il server era
stato avviato, cambiava da macchina a macchina, e con esso cambiava la
superficie d'attacco. Su una macchina il venv, su un'altra il Python di
sistema — con comportamenti diversi rispetto allo user site.

Ora l'interprete è un **percorso assoluto dalla configurazione**, verificato
all'avvio, eseguito con i flag di isolamento (``-I -S`` per default). Questo
chiude tre vie per cui codice non verificato entrava in esecuzione pur
lasciando intatto lo SHA:

* i file ``.pth`` e ``usercustomize.py`` nello **user site** dell'utente di
  servizio, che quell'utente può scrivere: una persistenza invisibile al
  gate, la stessa tecnica vista in compromissioni reali di pacchetti;
* un **modulo omonimo** accanto allo script, perché la sua directory era in
  testa a ``sys.path``: un ``json.py`` vicino a ``run.py`` sostituiva la
  libreria standard;
* i ``site-packages`` di sistema e i loro ``.pth``.

Resta una dipendenza esplicita e documentata: l'interprete configurato non
deve essere scrivibile dall'utente che esegue il server, altrimenti il
pinning dello script protegge il file sbagliato. Il preflight lo verifica.

Confinamento del percorso
-------------------------

``exec_path`` è già validato dal contratto — niente percorsi assoluti, niente
``..``. Resta però il caso del **collegamento simbolico**: un symlink dentro
il repo che punta fuori passerebbe la validazione sintattica. Per questo il
percorso viene risolto e poi ri-verificato contro la radice del repo: la
validazione del contratto guarda la stringa, questa guarda dove il filesystem
va davvero a finire.
"""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence, runtime_checkable

from mcp_server.audit import AuditLog, LogAction
from mcp_server.config import (
    MAX_CONCURRENT_DEFAULT,
    MAX_OUTPUT_BYTES_DEFAULT,
    TOOL_PYTHON_DEFAULT,
    TOOL_PYTHON_FLAGS_DEFAULT,
)
from mcp_server.contracts import (
    AuthorizedBy,
    CallOutcome,
    OwnerAgent,
    RiskTier,
    ToolCall,
    ToolSpec,
)
from mcp_server.registry import ToolRegistry
from mcp_server.scope import ScopeAllowlist, TargetRefused, valida_bersaglio
from mcp_server.slots import Posto, SlotPool, SlotUnavailable
from mcp_server.tiers import ConfirmationPolicy

#: Timeout di default di un'esecuzione. Un tool che non termina è un tool che
#: blocca la catena: meglio un errore che un'attesa indefinita.
TIMEOUT_DEFAULT = 300

#: Secondi concessi a un tool fra SIGTERM e SIGKILL, perché possa chiudere
#: file e connessioni invece di essere troncato a metà.
GRAZIA_SIGTERM = 2.0

#: Quanto si attende un posto libero prima di rifiutare. Attendere a lungo
#: accumulerebbe richieste; rifiutare subito dà un riscontro al chiamante.
ATTESA_POSTO_LIBERO = 1.0

#: Variabili d'ambiente passate ai tool. Tutto il resto viene scartato, perché
#: l'ambiente del server può contenere credenziali che il tool non deve vedere.
_ENV_CONSENTITE = ("PATH", "LANG", "LC_ALL", "TZ")

_CHUNK = 1024 * 1024

#: Percorso assoluto di ``sudo``. Assoluto per lo stesso motivo
#: dell'interprete dei tool: lasciarlo al ``PATH`` significa non sapere quale
#: binario sta concedendo il privilegio.
SUDO = Path("/usr/bin/sudo")

#: Prefisso del nome delle unità transienti. Il nome contiene il
#: ``correlation_id`` dell'invocazione, quindi un processo rimasto in giro si
#: ricollega a chi l'ha generato: oggi un orfano è anonimo.
PREFISSO_UNITA = "hermes-tool"

#: Di quanto il tempo limite di systemd sta SOTTO quello del gate.
#: L'ordine conta: systemd deve vincere per primo, perché è l'unico che può
#: terminare l'albero dentro il cgroup. Il timeout del gate resta la rete di
#: riserva che scatta solo se systemd ha fallito.
MARGINE_TEMPO_LIMITE = 5


# --------------------------------------------------------------------------- #
# Errori
# --------------------------------------------------------------------------- #


class ExecutionError(Exception):
    """Base degli errori del gate."""


class ContainerUnavailable(ExecutionError):
    """Il tool richiede il container isolato, che non è disponibile."""


class IntegrityMismatch(ExecutionError):
    """Lo script non corrisponde allo SHA dichiarato, o non è raggiungibile."""


class ConcurrencyLimitReached(ExecutionError):
    """Troppe esecuzioni contemporanee in questo processo."""


class ToolRunnerUnusable(ExecutionError):
    """Il wrapper di isolamento è configurato ma non si riesce a usarlo.

    Non si ricade sull'identità del servizio: sarebbe l'isolamento promesso e
    non applicato, e nessuno saprebbe di averlo perso. Stessa regola del
    container assente e dei posti condivisi rotti.
    """


class TargetOutOfScope(ExecutionError):
    """Il bersaglio non è ammesso dal perimetro, o non ha la forma attesa.

    Rifiuto della richiesta, non guasto della macchina: il modello ha chiesto
    di toccare qualcosa che non è nel perimetro, e questa è l'informazione che
    più vale la pena vedere nel log.
    """


class SharedSlotsUnusable(ExecutionError):
    """I posti condivisi sono configurati, ma la loro directory non è usabile.

    Distinta da :class:`ConcurrencyLimitReached` di proposito: là la macchina
    è occupata e riprovare fra poco ha senso, qui è rotta e riprovare no. Due
    cause con rimedi opposti dietro la stessa eccezione costringerebbero chi
    legge — persona o modello — a indovinare quale delle due ha incontrato.
    """


class ConfirmationRequired(ExecutionError):
    """La policy richiede una conferma che non è stata fornita."""


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RunResult:
    """Esito grezzo di un processo."""

    returncode: int
    stdout: str
    stderr: str
    #: Se l'output ha superato il tetto e è stato tagliato. Va dichiarato, non
    #: nascosto: un output troncato in silenzio fa trarre conclusioni
    #: sbagliate a chi lo legge, modello compreso.
    truncated: bool = False


@runtime_checkable
class Runner(Protocol):
    """Esegue il processo. Astratto per poter essere sostituito nei test."""

    def run(self, argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> RunResult:
        ...


class SubprocessRunner:
    """Runner reale, con i privilegi ridotti al minimo.

    ``shell=False`` e argv esplicito: nessuna stringa viene mai interpretata
    da una shell, quindi non esiste una via di iniezione via metacaratteri.
    L'ambiente è una lista bianca, non l'ambiente ereditato.

    Lo stdin del tool è ``/dev/null``
    ---------------------------------

    Non è un dettaglio di pulizia. Su trasporto stdio **lo stdin del server è
    il canale del protocollo MCP**: un figlio che lo eredita può leggere — e
    quindi *consumare* — i byte che l'host sta inviando. Verificato: un tool
    lanciato come prima riceveva ``{"jsonrpc":"2.0","id":1,"method":"initia…``.

    Le conseguenze sono due, entrambe serie: il server perde input e la
    sessione si corrompe, e il tool vede ciò che il client manda — che con
    l'elicitation comprenderà le risposte dell'utente alle richieste di
    conferma. Un tool non deve avere alcun canale di lettura verso il
    protocollo.

    Decodifica tollerante
    ---------------------

    L'output viene catturato come **byte** e decodificato con
    ``errors="replace"``. Con ``text=True``, Python decodifica in modo strict e
    solleva ``UnicodeDecodeError`` **dopo** che il processo è terminato: lo
    script ha già avuto i suoi effetti, ma la chiamata fallisce con
    un'eccezione che non è un errore di esecuzione, e l'esito non viene
    registrato da nessuno.

    Non serve un attaccante per arrivarci: basta un banner binario restituito
    da un host scansionato. Un byte fuori posto non deve poter cancellare
    un'esecuzione dalla traccia d'audit.
    """

    def __init__(
        self,
        *,
        max_output_bytes: int = MAX_OUTPUT_BYTES_DEFAULT,
        grazia_sigterm: float = GRAZIA_SIGTERM,
    ) -> None:
        self._max_output = max_output_bytes
        self._grazia = grazia_sigterm

    def run(self, argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> RunResult:
        # File temporanei invece di pipe: con due pipe e un solo thread di
        # lettura un tool che riempie un buffer manderebbe tutto in stallo, e
        # l'alternativa (leggere i due stream in parallelo) aggiunge
        # concorrenza dove non serve. Il consumo di disco resta limitato dal
        # timeout.
        with tempfile.TemporaryFile() as f_out, tempfile.TemporaryFile() as f_err:
            processo = subprocess.Popen(  # noqa: S603 - argv esplicito, shell=False
                argv,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=f_out,
                stderr=f_err,
                shell=False,
                # Il figlio diventa capogruppo: al timeout si può terminare
                # tutta la discendenza, non solo lui.
                start_new_session=True,
            )
            try:
                processo.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._termina_gruppo(processo)
                raise
            finally:
                if processo.poll() is None:  # pragma: no cover - rete di sicurezza
                    self._termina_gruppo(processo)

            stdout, tagliato_out = self._leggi(f_out)
            stderr, tagliato_err = self._leggi(f_err)

        return RunResult(
            returncode=processo.returncode,
            stdout=stdout,
            stderr=stderr,
            truncated=tagliato_out or tagliato_err,
        )

    # -- interno ------------------------------------------------------------ #

    def _termina_gruppo(self, processo: subprocess.Popen) -> None:
        """Termina il processo e tutta la sua discendenza.

        ``subprocess`` ucciderebbe solo il figlio diretto: un tool che ha
        lanciato a sua volta qualcosa — ``nmap`` dentro uno script, per dire —
        lascerebbe quel qualcosa vivo e adottato da init, mentre il log
        dichiara l'esecuzione terminata. Una scansione «conclusa» che continua
        a girare è peggio di un errore, perché nessuno la sta più guardando.

        Prima ``SIGTERM``, per dare al tool la possibilità di chiudere i
        propri file e connessioni, poi ``SIGKILL`` se non basta.
        """
        try:
            gruppo = os.getpgid(processo.pid)
        except (ProcessLookupError, PermissionError):  # pragma: no cover
            return

        for segnale in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(gruppo, segnale)
            except (ProcessLookupError, PermissionError):
                return
            try:
                processo.wait(timeout=self._grazia)
                return
            except subprocess.TimeoutExpired:
                continue

    def _leggi(self, handle) -> tuple[str, bool]:
        """Legge al massimo ``max_output_bytes``, segnalando il taglio."""
        handle.seek(0)
        dati = handle.read(self._max_output + 1)
        tagliato = len(dati) > self._max_output
        return _decodifica(dati[: self._max_output]), tagliato


def _decodifica(grezzo: bytes | str | None) -> str:
    """Decodifica l'output di un processo senza poter fallire.

    I byte non decodificabili diventano il carattere di sostituzione: perdere
    un carattere è accettabile, perdere la riga di audit non lo è.
    """
    if grezzo is None:
        return ""
    if isinstance(grezzo, str):
        return grezzo
    return grezzo.decode("utf-8", errors="replace")


def _wrapper_inutilizzabile(percorso: Path) -> str | None:
    """Perché il wrapper non è usabile, o ``None`` se lo è.

    Si guarda ciò che si può misurare senza eseguire nulla: esiste, è un file,
    è eseguibile, ed è di root e non scrivibile da altri. Le ultime due non
    sono igiene: se l'utente di servizio potesse riscrivere il wrapper, la
    riga di sudoers che lo autorizza diventerebbe sudo pieno — la restrizione
    sarebbe custodita da chi la subisce, per la quarta volta in questa patch.

    Non si verifica qui che ``sudo -n`` funzioni: richiederebbe di eseguire
    qualcosa a ogni invocazione. Quello lo fa il preflight, una volta.

    Riporta **tutti** i problemi, non il primo. Fermarsi al primo manderebbe
    chi ripara a scoprirne un altro dopo ogni correzione, e renderebbe il
    messaggio dipendente dall'ordine dei controlli invece che dallo stato del
    file — che è anche il modo in cui questa funzione ha prodotto un test che
    passava nel container e falliva sulla VM.
    """
    try:
        st = percorso.stat()
    except OSError as err:
        # Qui non c'è altro da guardare: senza stat ogni altro controllo
        # risponderebbe su un file che non si è potuto leggere.
        return f"{percorso} non ispezionabile: {err}"

    problemi = []
    if not stat.S_ISREG(st.st_mode):
        problemi.append("non è un file regolare")
    modo = stat.S_IMODE(st.st_mode)
    if not modo & 0o111:
        problemi.append(f"non è eseguibile (permessi {modo:04o})")
    if st.st_uid != 0:
        problemi.append(f"non è di root (uid {st.st_uid})")
    if modo & 0o022:
        problemi.append(
            f"è scrivibile da altri (permessi {modo:04o}): chi esegue i tool "
            f"potrebbe riscrivere il proprio confine"
        )
    if not problemi:
        return None
    return f"{percorso} " + "; ".join(problemi)


def ambiente_minimo() -> dict[str, str]:
    """Ambiente ridotto alla lista bianca.

    L'ambiente del server può contenere token e credenziali: ereditarlo
    passerebbe al tool tutto ciò che il server conosce, che è il contrario del
    minimo privilegio.
    """
    return {k: os.environ[k] for k in _ENV_CONSENTITE if k in os.environ}


# --------------------------------------------------------------------------- #
# Esito preparato
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PreparedExecution:
    """Esecuzione che ha superato tutti i controlli ed è pronta a partire."""

    spec: ToolSpec
    agent: OwnerAgent
    effective_tier: RiskTier
    policy: ConfirmationPolicy
    script: Path
    authorized_by: AuthorizedBy
    correlation_id: uuid.UUID
    target: str | None = None
    #: Bersaglio validato e in forma canonica, che è ciò che viene passato al
    #: tool. Diverso da ``target`` quando il modello ha usato un alias: il log
    #: conserva entrambi, così dice cosa è stato chiesto *e* cosa è stato
    #: toccato.
    target_risolto: str | None = None


# --------------------------------------------------------------------------- #
# Integrità
# --------------------------------------------------------------------------- #


def sha256_file(path: Path) -> str:
    """SHA-256 esadecimale del file, letto a blocchi."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while blocco := fh.read(_CHUNK):
            digest.update(blocco)
    return digest.hexdigest()


def risolvi_script(repo_root: Path, exec_path: str) -> Path:
    """Risolve ``exec_path`` e verifica che resti dentro il repo.

    Il contratto valida la stringa; qui si verifica dove il filesystem va
    davvero a finire, perché un symlink dentro il repo può puntare fuori.
    """
    radice = repo_root.resolve()
    candidato = (radice / exec_path).resolve()
    if not candidato.is_relative_to(radice):
        raise IntegrityMismatch(
            f"lo script esce dalla radice del repo: {exec_path!r} -> {candidato}"
        )
    if not candidato.is_file():
        raise IntegrityMismatch(f"script assente o non regolare: {candidato}")
    return candidato


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #


class ToolExecutor:
    """Applica i controlli e, solo se tutti passano, esegue.

    Parameters
    ----------
    registry:
        Registro da cui provengono spec, tier effettivo e policy.
    audit:
        Log su cui registrare ogni decisione, rifiuti compresi.
    repo_root:
        Radice entro cui gli script devono restare.
    container_available:
        Se il runtime isolato è disponibile. In Milestone 0 è ``False``: i
        tool che lo richiedono vengono negati, non eseguiti sull'host.
    runner:
        Esecutore del processo. Sostituibile nei test.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        audit: AuditLog,
        *,
        repo_root: Path,
        container_available: bool = False,
        runner: Runner | None = None,
        tool_python: Path | str = TOOL_PYTHON_DEFAULT,
        tool_python_flags: Sequence[str] = TOOL_PYTHON_FLAGS_DEFAULT,
        max_output_bytes: int = MAX_OUTPUT_BYTES_DEFAULT,
        max_concurrent: int = MAX_CONCURRENT_DEFAULT,
        slots: SlotPool | None = None,
        scope: ScopeAllowlist | None = None,
        tool_runner: Path | None = None,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._repo_root = Path(repo_root)
        self._container_available = container_available
        self._runner = runner or SubprocessRunner(max_output_bytes=max_output_bytes)
        self._tool_python = Path(tool_python)
        self._tool_python_flags = tuple(tool_python_flags)
        self._max_output_bytes = max_output_bytes
        self._max_concurrent = max_concurrent
        # I tool sincroni girano nel thread pool del framework MCP, quindi le
        # invocazioni concorrenti sono thread reali dello stesso processo.
        self._posti = threading.BoundedSemaphore(max_concurrent)
        # Il semaforo resta anche quando c'è il pool condiviso: è il percorso
        # veloce, non costa I/O, e due limiti dello stesso numero non si
        # contraddicono — il più stretto vince e sono uguali.
        self._slots = slots
        # ``None`` significa perimetro non configurato, non «tutto ammesso»:
        # è `valida_bersaglio` a rifiutare i tool con bersaglio, e lo fa
        # con un motivo leggibile invece di lasciar passare.
        self._scope = scope
        # ``None`` → i tool girano con l'identità del servizio, come prima, e
        # il preflight e il catalogo lo dichiarano. Non è un default
        # inventato: è il comportamento che c'era, con la sua conseguenza
        # detta.
        self._tool_runner = tool_runner

    @property
    def container_available(self) -> bool:
        return self._container_available

    @property
    def tool_python(self) -> Path:
        """Interprete con cui vengono eseguiti i tool."""
        return self._tool_python

    @property
    def tool_python_flags(self) -> tuple[str, ...]:
        return self._tool_python_flags

    @property
    def max_output_bytes(self) -> int:
        return self._max_output_bytes

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def uid_separato(self) -> bool:
        """Se i tool girano sotto un'identità diversa da quella del server."""
        return self._tool_runner is not None

    @property
    def perimetro_configurato(self) -> bool:
        """Se esiste un perimetro dei bersagli da applicare."""
        return self._scope is not None

    @property
    def concorrenza_condivisa(self) -> bool:
        """Se il limite vale fra le connessioni dell'agente o solo qui dentro."""
        return self._slots is not None

    def _prendi_posto_condiviso(self) -> Posto | None:
        """Occupa un posto nel pool fra processi, se configurato.

        Qui non si decide nulla: o il pool non è configurato — e allora il
        limite per processo è tutto ciò che è stato promesso — o è
        configurato, e un suo guasto risale al gate.

        Degradare sarebbe stato il riflesso comodo: il semaforo di processo ha
        già fatto il suo lavoro, e un lock che non si crea somiglia a un
        problema di filesystem più che a un problema di sicurezza. Ma se i
        posti sono configurati, il tetto che la configurazione dichiara è
        quello condiviso: eseguire senza avrebbe significato girare oltre il
        limite dichiarato proprio nel momento in cui la macchina ha già un
        guasto — e senza che nessuno, leggendo la risposta, avesse motivo di
        sospettarlo. È la stessa forma del container, che assente nega invece
        di ricadere sull'ambiente meno isolato.
        """
        if self._slots is None:
            return None
        return self._slots.acquire()

    def _ferma_unita(self, unita: str, correlation_id: uuid.UUID) -> None:
        """Ferma l'unità transiente, e registra se non ci riesce.

        Chiamata solo quando il tempo limite di systemd non è scattato: a quel
        punto il tool vive in un cgroup che il gate non può toccare
        direttamente, e lasciarlo lì sarebbe un orfano che consuma la macchina
        senza che niente lo dica. Se anche questo fallisce, la cosa va nel log
        — un residuo invisibile è peggio di un residuo noto.
        """
        if self._tool_runner is None:  # pragma: no cover - chiamata solo con runner
            return
        try:
            esito = subprocess.run(  # noqa: S603 - argv esplicito, shell=False
                [str(SUDO), "-n", str(self._tool_runner), "--stop", unita],
                env=ambiente_minimo(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=GRAZIA_SIGTERM + 5,
                check=False,
            )
            if esito.returncode == 0:
                return
            dettaglio = f"esito {esito.returncode}"
        except (OSError, subprocess.SubprocessError) as err:
            dettaglio = f"{type(err).__name__}: {err}"
        self._audit.log(
            correlation_id=correlation_id,
            action=LogAction.TOOL_CALL,
            outcome=CallOutcome.ERROR,
            detail=(
                f"unità {unita} non fermata ({dettaglio}): possibile "
                f"discendenza ancora attiva. Verificare con "
                f"'systemctl status {unita}.service'."
            ),
        )

    # -- preparazione -------------------------------------------------------- #

    def prepare(
        self,
        tool_id: str,
        agent: OwnerAgent,
        *,
        correlation_id: uuid.UUID,
        confirmed: bool = False,
        target: str | None = None,
    ) -> PreparedExecution:
        """Applica i controlli senza eseguire.

        Solleva al primo che fallisce, registrando il rifiuto.
        """
        # 1-2. Registrazione e proprietà del tool.
        spec = self._registry.assert_can_invoke(
            tool_id, agent, correlation_id=correlation_id
        )
        tier = self._registry.effective_tier(tool_id)
        policy = self._registry.policy_for(tool_id)

        # 3. Perimetro del bersaglio.
        #
        # Prima del container, e non è una questione di costo: un bersaglio
        # fuori perimetro deve essere rifiutato e registrato allo stesso modo
        # sia che il container ci sia sia che non ci sia. Col controllo del
        # container davanti, un tool che lo richiede su una macchina che non
        # l'ha registrerebbe «container non disponibile», e il tentativo fuori
        # perimetro diventerebbe invisibile — perdendo esattamente il segnale
        # che più conta: che il modello ha provato a toccare qualcosa fuori
        # dal confine.
        try:
            target_risolto = valida_bersaglio(spec.target_kind, target, self._scope)
        except TargetRefused as err:
            self._nega(
                spec,
                agent,
                tier,
                correlation_id,
                target,
                f"bersaglio rifiutato: {err}",
            )
            raise TargetOutOfScope(f"bersaglio rifiutato: {err}") from None

        # 4. Isolamento sotto un'altra identità, se promesso.
        #
        # Si controlla qui e non allo spawn perché un wrapper inutilizzabile è
        # una decisione del gate, non un guasto dell'esecuzione: va rifiutata
        # e registrata prima che qualcosa parta.
        if self._tool_runner is not None:
            guasto = _wrapper_inutilizzabile(self._tool_runner)
            if guasto is not None:
                motivo = (
                    f"isolamento dei tool promesso e non applicabile: "
                    f"{guasto}. Invocazione rifiutata, non eseguita: ricadere "
                    f"sull'identità del servizio significherebbe eseguire "
                    f"senza il confine che la configurazione dichiara. "
                    f"Riprovare non cambia l'esito finché il wrapper non è "
                    f"riparato."
                )
                self._nega(spec, agent, tier, correlation_id, target, motivo)
                raise ToolRunnerUnusable(motivo)

        # 5. Isolamento nel container: mai degradare silenziosamente verso l'host.
        if spec.requires_container and not self._container_available:
            self._nega(
                spec,
                agent,
                tier,
                correlation_id,
                target,
                "il tool richiede il container isolato, non disponibile: "
                "esecuzione negata invece di ricadere sull'host",
            )
            raise ContainerUnavailable(
                f"{tool_id!r} richiede il container isolato, non disponibile"
            )

        # 6. Integrità, dopo il perimetro: rifiutare fuori confine è più
        #    economico e più indipendente dal tool che hashare uno script.
        try:
            script = risolvi_script(self._repo_root, spec.exec_path)
            effettivo = sha256_file(script)
        except IntegrityMismatch as err:
            self._nega(spec, agent, tier, correlation_id, target, str(err))
            raise
        except OSError as err:
            self._nega(
                spec, agent, tier, correlation_id, target, f"script illeggibile: {err}"
            )
            raise IntegrityMismatch(f"script illeggibile: {err}") from err

        if effettivo != spec.exec_sha256:
            self._nega(
                spec,
                agent,
                tier,
                correlation_id,
                target,
                f"integrità fallita: atteso {spec.exec_sha256[:12]}…, "
                f"calcolato {effettivo[:12]}…",
            )
            raise IntegrityMismatch(
                f"{tool_id!r}: lo script non corrisponde allo SHA dichiarato"
            )

        # 7. Autorizzazione.
        if policy.requires_confirmation and not confirmed:
            self._audit.log(
                correlation_id=correlation_id,
                action=LogAction.TOOL_CALL,
                outcome=CallOutcome.PENDING,
                agent=agent,
                tool_id=spec.tool_id,
                target=target,
                tier_effective=tier,
                authorized_by=AuthorizedBy.NONE,
                detail=(
                    f"conferma richiesta e non fornita: tecnica="
                    f"{policy.technical}, dedicata={policy.personal}"
                ),
            )
            raise ConfirmationRequired(
                f"{tool_id!r} richiede conferma (tecnica={policy.technical}, "
                f"dati personali={policy.personal})"
            )

        return PreparedExecution(
            spec=spec,
            agent=agent,
            effective_tier=tier,
            policy=policy,
            script=script,
            authorized_by=(
                AuthorizedBy.USER if policy.requires_confirmation else AuthorizedBy.POLICY
            ),
            correlation_id=correlation_id,
            target=target,
            target_risolto=target_risolto,
        )

    # -- esecuzione ---------------------------------------------------------- #

    def execute(
        self,
        tool_id: str,
        agent: OwnerAgent,
        *,
        correlation_id: uuid.UUID,
        confirmed: bool = False,
        target: str | None = None,
        timeout: int = TIMEOUT_DEFAULT,
    ) -> tuple[ToolCall, RunResult]:
        """Prepara ed esegue, restituendo la traccia e l'esito grezzo.

        La :class:`~mcp_server.contracts.ToolCall` restituita è già conforme
        al contratto e pronta per entrare in un ``AgentResult``.

        Dopo lo spawn, nessuna eccezione sfugge
        ---------------------------------------

        Superata la preparazione, il processo **può essere già partito**: da
        quel punto in avanti qualunque errore — timeout, interprete non
        trovato, output indecodificabile, un guasto del runner — viene
        convertito in un esito **registrato** invece di risalire come
        eccezione.

        Il motivo è che l'alternativa non è "l'esecuzione non avviene": è
        "l'esecuzione avviene e il log non la contiene". Un'eccezione che
        risale lascia lo script con i suoi effetti già prodotti e l'audit con
        un ``agent_invoked`` orfano, e chi legge il log conclude che non è
        stato eseguito nulla. Meglio una riga che dice «eseguito, esito
        incerto» di nessuna riga.
        """
        pronta = self.prepare(
            tool_id,
            agent,
            correlation_id=correlation_id,
            confirmed=confirmed,
            target=target,
        )

        # Posto libero, o rifiuto tracciato. Il gate è l'unico punto in cui
        # passano le esecuzioni, quindi è il punto in cui si contano.
        if not self._posti.acquire(timeout=ATTESA_POSTO_LIBERO):
            # Un solo testo per la riga di log e per l'eccezione. Tenerli
            # separati aveva prodotto esattamente il difetto del `pending`:
            # la formulazione che dice se riprovare ha senso finiva nel log,
            # che legge una persona, mentre al modello arrivava il messaggio
            # corto — e chi decide se riprovare è il modello.
            motivo = (
                f"limite di esecuzioni contemporanee raggiunto in questo "
                f"processo ({self._max_concurrent}): invocazione rifiutata, "
                f"non eseguita. Riprovare ha senso quando una delle "
                f"esecuzioni in corso sarà terminata."
            )
            self._nega(
                pronta.spec,
                agent,
                pronta.effective_tier,
                correlation_id,
                target,
                motivo,
            )
            raise ConcurrencyLimitReached(motivo)

        # Secondo posto, quello condiviso fra i processi dell'agente. Si
        # prende dopo il semaforo e si rilascia per primo, come ogni coppia di
        # lock annidati: l'ordine inverso fra due esecuzioni produrrebbe uno
        # stallo.
        try:
            posto = self._prendi_posto_condiviso()
        except SlotUnavailable:
            self._posti.release()
            motivo = (
                f"limite di esecuzioni contemporanee raggiunto fra le "
                f"connessioni dell'agente ({self._max_concurrent}): "
                f"invocazione rifiutata, non eseguita. Riprovare ha senso "
                f"quando una delle esecuzioni in corso sarà terminata."
            )
            self._nega(
                pronta.spec,
                agent,
                pronta.effective_tier,
                correlation_id,
                target,
                motivo,
            )
            raise ConcurrencyLimitReached(motivo) from None
        except OSError as err:
            # Posti configurati e non utilizzabili: il limite dichiarato non
            # è applicabile, quindi non si esegue. Qui riprovare NON ha senso,
            # ed è l'opposto del rifiuto qui sopra: due cause che il testo
            # deve distinguere, perché portano a due comportamenti diversi.
            self._posti.release()
            motivo = (
                f"posti condivisi non utilizzabili in "
                f"{self._slots.directory if self._slots else '?'}: {err}. "
                f"Il limite fra le connessioni dell'agente è configurato ma "
                f"non applicabile: invocazione rifiutata, non eseguita. "
                f"Riprovare non cambia l'esito finché la directory di stato "
                f"non è riparata."
            )
            self._nega(
                pronta.spec,
                agent,
                pronta.effective_tier,
                correlation_id,
                target,
                motivo,
            )
            raise SharedSlotsUnusable(motivo) from err
        except BaseException:
            # Qualunque altra cosa vada storta qui deve comunque restituire il
            # posto in memoria prima di risalire. Un semaforo perso riduce la
            # capacità del processo per sempre: è esattamente il controllo che
            # si auto-esaurisce che questo modulo esiste per evitare.
            self._posti.release()
            raise

        # Argomenti fissi dichiarati nel contratto, poi il separatore, poi il
        # bersaglio già validato. Il `--` non è cosmetico: senza, un bersaglio
        # che inizia per '-' verrebbe letto come opzione dal tool. `scope.py`
        # lo rifiuta già, e questo è il secondo dei due meccanismi — un
        # controllo che dipende da un solo punto non è un controllo.
        argv = [
            str(self._tool_python),
            *self._tool_python_flags,
            str(pronta.script),
            *pronta.spec.exec_args,
        ]
        if pronta.target_risolto is not None:
            argv += ["--", pronta.target_risolto]

        # Isolamento sotto un'altra identità, se configurato. Il nome
        # dell'unità porta il correlation_id: serve al percorso di
        # terminazione, e fa sì che un processo rimasto in giro si ricolleghi
        # all'invocazione che l'ha generato.
        unita = f"{PREFISSO_UNITA}-{correlation_id}"
        if self._tool_runner is not None:
            argv = [
                str(SUDO),
                # -n: senza autorizzazione FALLISCE, invece di chiedere una
                # password a un canale non interattivo e restare appeso.
                "-n",
                str(self._tool_runner),
                unita,
                str(max(1, timeout - MARGINE_TEMPO_LIMITE)),
                "--",
                *argv,
            ]
        try:
            esito = self._runner.run(
                argv,
                cwd=self._repo_root,
                env=ambiente_minimo(),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # Rete di riserva: il tempo limite di systemd sta sotto il nostro,
            # quindi se siamo qui systemd non ha fatto il suo lavoro. Uccidere
            # il gruppo di processi — che il runner ha già fatto — non
            # raggiunge il tool, che vive nel cgroup dell'unità: va fermata
            # l'unità.
            self._ferma_unita(unita, correlation_id)
            return self._esito_non_riuscito(
                pronta, f"timeout dopo {timeout}s", "timeout"
            )
        except BaseException as err:
            # BaseException e non Exception: anche un KeyboardInterrupt o un
            # SystemExit a metà esecuzione deve lasciare la riga, prima di
            # essere ri-sollevato.
            call, risultato = self._esito_non_riuscito(
                pronta,
                f"errore del runner dopo lo spawn: {type(err).__name__}",
                type(err).__name__,
            )
            if not isinstance(err, Exception):
                raise
            return call, risultato
        finally:
            if posto is not None:
                posto.release()
            self._posti.release()

        outcome = CallOutcome.OK if esito.returncode == 0 else CallOutcome.ERROR
        detail = f"exit={esito.returncode}"
        if esito.truncated:
            detail += f"; output troncato a {self._max_output_bytes} byte per stream"
        call = self._traccia(pronta, outcome, detail)
        self._log_call(call, pronta)
        return call, esito

    # -- interno ------------------------------------------------------------- #

    def _esito_non_riuscito(
        self, pronta: PreparedExecution, detail: str, stderr: str
    ) -> tuple[ToolCall, RunResult]:
        """Registra un'esecuzione andata male e ne restituisce la traccia.

        ``returncode = -1`` segnala che il processo non ha riportato un codice
        d'uscita proprio: distingue «ha fallito» da «è uscito con errore».
        """
        call = self._traccia(pronta, CallOutcome.ERROR, detail)
        self._log_call(call, pronta)
        return call, RunResult(returncode=-1, stdout="", stderr=stderr)

    def _traccia(
        self, pronta: PreparedExecution, outcome: CallOutcome, detail: str
    ) -> ToolCall:
        return ToolCall(
            tool_id=pronta.spec.tool_id,
            target=pronta.target,
            tier_effective=pronta.effective_tier,
            authorized_by=pronta.authorized_by,
            outcome=outcome,
            detail=detail,
        )

    def _log_call(self, call: ToolCall, pronta: PreparedExecution) -> None:
        self._audit.log(
            correlation_id=pronta.correlation_id,
            action=LogAction.TOOL_CALL,
            outcome=call.outcome,
            agent=pronta.agent,
            tool_id=call.tool_id,
            target=call.target,
            tier_effective=call.tier_effective,
            authorized_by=call.authorized_by,
            detail=call.detail,
        )

    def _nega(
        self,
        spec: ToolSpec,
        agent: OwnerAgent,
        tier: RiskTier,
        correlation_id: uuid.UUID,
        target: str | None,
        motivo: str,
    ) -> None:
        self._audit.log(
            correlation_id=correlation_id,
            action=LogAction.TOOL_CALL,
            outcome=CallOutcome.DENIED,
            agent=agent,
            tool_id=spec.tool_id,
            target=target,
            tier_effective=tier,
            authorized_by=AuthorizedBy.NONE,
            detail=motivo,
        )


__all__ = [
    "ConcurrencyLimitReached",
    "ConfirmationRequired",
    "ContainerUnavailable",
    "ExecutionError",
    "IntegrityMismatch",
    "PreparedExecution",
    "RunResult",
    "Runner",
    "SharedSlotsUnusable",
    "SubprocessRunner",
    "TIMEOUT_DEFAULT",
    "TargetOutOfScope",
    "ToolExecutor",
    "ToolRunnerUnusable",
    "ambiente_minimo",
    "risolvi_script",
    "sha256_file",
]
