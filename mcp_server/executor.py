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
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import (
    AuthorizedBy,
    CallOutcome,
    OwnerAgent,
    RiskTier,
    ToolCall,
    ToolSpec,
)
from mcp_server.registry import ToolRegistry
from mcp_server.tiers import ConfirmationPolicy

#: Timeout di default di un'esecuzione. Un tool che non termina è un tool che
#: blocca la catena: meglio un errore che un'attesa indefinita.
TIMEOUT_DEFAULT = 300

#: Variabili d'ambiente passate ai tool. Tutto il resto viene scartato, perché
#: l'ambiente del server può contenere credenziali che il tool non deve vedere.
_ENV_CONSENTITE = ("PATH", "LANG", "LC_ALL", "TZ")

_CHUNK = 1024 * 1024


# --------------------------------------------------------------------------- #
# Errori
# --------------------------------------------------------------------------- #


class ExecutionError(Exception):
    """Base degli errori del gate."""


class ContainerUnavailable(ExecutionError):
    """Il tool richiede il container isolato, che non è disponibile."""


class IntegrityMismatch(ExecutionError):
    """Lo script non corrisponde allo SHA dichiarato, o non è raggiungibile."""


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

    def run(self, argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> RunResult:
        completato = subprocess.run(  # noqa: S603 - argv esplicito, shell=False
            argv,
            cwd=str(cwd),
            env=env,
            timeout=timeout,
            capture_output=True,
            shell=False,
            check=False,
        )
        return RunResult(
            returncode=completato.returncode,
            stdout=_decodifica(completato.stdout),
            stderr=_decodifica(completato.stderr),
        )


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
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._repo_root = Path(repo_root)
        self._container_available = container_available
        self._runner = runner or SubprocessRunner()

    @property
    def container_available(self) -> bool:
        return self._container_available

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

        # 3. Isolamento: mai degradare silenziosamente verso l'host.
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

        # 4. Integrità, prima di chiedere qualunque conferma.
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

        # 5. Autorizzazione.
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

        argv = ["python3", str(pronta.script)]
        try:
            esito = self._runner.run(
                argv,
                cwd=self._repo_root,
                env=ambiente_minimo(),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
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

        outcome = CallOutcome.OK if esito.returncode == 0 else CallOutcome.ERROR
        call = self._traccia(pronta, outcome, f"exit={esito.returncode}")
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
    "ConfirmationRequired",
    "ContainerUnavailable",
    "ExecutionError",
    "IntegrityMismatch",
    "PreparedExecution",
    "RunResult",
    "Runner",
    "SubprocessRunner",
    "TIMEOUT_DEFAULT",
    "ToolExecutor",
    "ambiente_minimo",
    "risolvi_script",
    "sha256_file",
]
