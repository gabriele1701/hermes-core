"""Server MCP di hermes-core, su trasporto stdio.

Espone al client MCP (Hermes) i tool registrati e la loro invocazione,
applicando il gate di esecuzione. Trasporto **stdio**: il server viene
lanciato come sottoprocesso dal client, non ascolta su alcuna porta, e quindi
non ha superficie di rete da proteggere.

L'identità dell'agente non è un parametro
-----------------------------------------

Un'istanza del server **appartiene a un agente**, dichiarato nella propria
configurazione e fissato all'avvio. Le funzioni esposte non accettano un
parametro ``agent``.

Il motivo è che un parametro renderebbe decorativo il confine fra agenti: un
client potrebbe dichiararsi l'agente che gli conviene e invocare i tool di
chiunque, e il controllo di proprietà del registro non proteggerebbe più
nulla. Con l'identità legata al processo, la separazione è imposta da **come
il server viene lanciato** — un processo per agente, con la propria config —
e non da un valore che il chiamante fornisce.

Per la stessa ragione l'elenco dei tool è filtrato sull'agente: un agente non
ha bisogno di sapere quali tool appartengono agli altri.

Il vault non è esposto
----------------------

Non esiste una funzione MCP che restituisca un segreto. Esporla significherebbe
dare a qualunque client connesso la possibilità di estrarre credenziali, che è
l'opposto dello scopo del vault: i segreti vanno **usati**, non consegnati. Il
vault resta raggiungibile solo dall'interno, lungo il percorso di esecuzione di
un tool che ne ha bisogno, e ogni accesso resta tracciato.

La conferma non è un parametro
------------------------------

``invoke_tool`` non ha un flag ``confirmed``. Un booleano fornito dal
chiamante sarebbe un'autorizzazione che il chiamante concede a se stesso: il
client passerebbe sempre ``true`` e la cadenza di conferma diventerebbe
ornamentale.

Di conseguenza, in questa milestone un tool che richiede conferma **non è
eseguibile** attraverso il server: l'invocazione ritorna
``needs_confirmation`` con la chiamata in ``pending``, e lì si ferma. È un
comportamento fail-closed deliberato. Il collegamento della conferma reale
passa dal meccanismo di elicitation di MCP, con cui il server chiede all'host
di interpellare l'utente; è registrato in ``docs/debito-sicurezza.md``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_server.audit import AuditLog, LogAction
from mcp_server.config import ServerConfig, load_config
from mcp_server.contracts import (
    AgentResult,
    AgentStatus,
    AuthorizedBy,
    CallOutcome,
    OwnerAgent,
    RiskTier,
    ToolCall,
)
from mcp_server.executor import (
    ConfirmationRequired,
    ContainerUnavailable,
    ExecutionError,
    IntegrityMismatch,
    ToolExecutor,
)
from mcp_server.overrides import OverrideScope, OverrideStore
from mcp_server.registry import (
    InvocationRefused,
    OverrideRefused,
    ToolNotRegistered,
    ToolRegistry,
    ToolSpecRejected,
)
from mcp_server.slots import SlotPool
from mcp_server.vault import StubBackend, Vault, VaultBackend

NOME_SERVER = "hermes-core"

VERSIONE = "0.0.1"

#: Cosa dire, per ciascuna durata, a chi ha appena innalzato un tier. La
#: durata va **dichiarata**, non lasciata presumere: l'host avvia un processo
#: server nuovo a ogni connessione, e un innalzamento non persistito sparisce
#: senza che nulla lo segnali. Chi alza un tier dopo un incidente si aspetta
#: il contrario.
NOTE_DURATA = {
    OverrideScope.CONFIG: (
        "l'innalzamento è scritto nella configurazione versionata: resta fino "
        "a quando non viene rimosso da lì, cosa che richiede una modifica al "
        "repository"
    ),
    OverrideScope.PERSISTENT: (
        "l'innalzamento è registrato nello store ed è stato scritto su disco: "
        "resta valido anche alle prossime connessioni, e non è annullabile da "
        "questa interfaccia — per riportarlo giù serve un intervento manuale "
        "di un amministratore sulla macchina"
    ),
    OverrideScope.SESSION: (
        "l'innalzamento vale solo per questa connessione: lo store degli "
        "override non è configurato o non è scrivibile, quindi alla prossima "
        "connessione il tool torna al tier dichiarato"
    ),
    OverrideScope.NONE: "nessun override attivo: vale il tier dichiarato",
}

#: Cosa si registra e si restituisce quando la policy richiede una conferma.
#: Non "in attesa": non c'è nulla in attesa, perché nessun canale di conferma
#: è collegato. Vedere :meth:`HermesServer._risultato_in_attesa`.
MOTIVO_CONFERMA_NON_COLLEGATA = (
    "conferma richiesta e non fornibile: nessun canale di conferma è "
    "collegato (l'elicitation MCP non è implementata in questa milestone). "
    "Il tool NON è stato eseguito e non verrà eseguito riprovando: serve "
    "un'autorizzazione fuori banda."
)

_ISTRUZIONI = """\
Toolbox difensiva Hermes. I tool elencati appartengono all'agente di questa
istanza e operano solo su host di proprietà o espressamente autorizzati.

Ogni tool porta un risk tier (verde/giallo/rosso) e un flag sui dati
personali, da cui derivano le conferme richieste.

Un tool che richiede conferma NON viene eseguito: l'invocazione ritorna
needs_confirmation. In questa milestone non esiste alcun canale su cui una
conferma possa arrivare, quindi riprovare non cambia l'esito: va chiesta
un'autorizzazione a una persona, fuori da questa interfaccia.

Il tier di un tool può essere innalzato con raise_tool_tier, mai abbassato.
La risposta dichiara in override_scope quanto dura l'innalzamento.
"""


class HermesServer:
    """Istanza del server MCP per un singolo agente.

    Mette insieme log d'audit, registro, vault e gate di esecuzione, e li
    espone come funzioni MCP. Costruirlo non fa partire nulla: :meth:`run`
    avvia il trasporto.
    """

    def __init__(self, config: ServerConfig, *, backend: VaultBackend | None = None) -> None:
        self._config = config
        self._audit = AuditLog(config.log_path)
        self._store = (
            OverrideStore.in_directory(config.state_dir)
            if config.state_dir is not None
            else None
        )
        self._registry = ToolRegistry(self._audit, store=self._store)
        self._vault = Vault(
            backend or _costruisci_backend(config),
            self._audit,
            correlation_id=self._registry.correlation_id,
        )
        self._executor = ToolExecutor(
            self._registry,
            self._audit,
            repo_root=config.repo_root,
            container_available=config.container_available,
            tool_python=config.tool_python,
            tool_python_flags=config.tool_python_flags,
            max_output_bytes=config.max_output_bytes,
            max_concurrent=config.max_concurrent_tools,
            # Senza state_dir il limite resta per processo, come prima. Non
            # si inventa una directory: l'assenza ha una conseguenza precisa
            # che il preflight dichiara.
            slots=(
                SlotPool.per_agente(
                    config.state_dir, config.agent, config.max_concurrent_tools
                )
                if config.state_dir is not None
                else None
            ),
        )
        self._carica_tool()
        self._mcp = self._costruisci_mcp()

    # -- accesso ai componenti (per test e integrazione) -------------------- #

    @property
    def agent(self) -> OwnerAgent:
        return self._config.agent

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def vault(self) -> Vault:
        """Vault interno. Non è esposto come funzione MCP: vedere il modulo."""
        return self._vault

    @property
    def mcp(self) -> MCPServer:
        return self._mcp

    def run(self, transport: str = "stdio") -> None:
        """Avvia il server. Di default su stdio."""
        self._mcp.run(transport=transport)  # type: ignore[arg-type]

    # -- avvio -------------------------------------------------------------- #

    def _carica_tool(self) -> None:
        """Registra i tool della configurazione, fallendo al primo non conforme.

        Un registro caricato a metà farebbe credere all'operatore di avere
        tool che non ci sono. L'eccezione risale e l'avvio non completa; il
        rifiuto è comunque già nel log, registrato dal registro.
        """
        for payload in self._config.tools:
            self._registry.register_payload(payload)

    def _costruisci_mcp(self) -> MCPServer:
        mcp = MCPServer(
            name=NOME_SERVER,
            version=VERSIONE,
            instructions=_ISTRUZIONI,
        )
        mcp.add_tool(
            self._list_available_tools,
            name="list_available_tools",
            description=(
                "Elenca i tool di questo agente con risk tier effettivo, flag "
                "dati personali e conferme richieste."
            ),
        )
        mcp.add_tool(
            self._describe_tool,
            name="describe_tool",
            description=(
                "Dettaglio di un tool: tier dichiarato ed effettivo, conferme "
                "richieste, requisito di container, eseguibilità non presidiata."
            ),
        )
        mcp.add_tool(
            self._invoke_tool,
            name="invoke_tool",
            description=(
                "Esegue un tool di questo agente applicando i controlli. "
                "Restituisce un risultato strutturato; un tool che richiede "
                "conferma ritorna needs_confirmation senza essere eseguito."
            ),
        )
        mcp.add_tool(
            self._raise_tool_tier,
            name="raise_tool_tier",
            description=(
                "Innalza il risk tier di un tool. Il tier può solo salire: "
                "ogni declassamento viene rifiutato, e l'innalzamento NON è "
                "annullabile da questa interfaccia. Se l'innalzamento è "
                "persistente, portare un tool a 'rosso' lo rende non "
                "invocabile finché un amministratore non interviene sulla "
                "macchina. Da usare quando serve più severità, non per "
                "provare."
            ),
        )
        return mcp

    # -- funzioni esposte --------------------------------------------------- #

    def _tool_dell_agente(self, tool_id: str):
        """Recupera un tool verificando che appartenga a questo agente.

        Un tool di un altro agente è trattato come inesistente: rivelare che
        esiste darebbe a questa istanza informazioni su un perimetro che non è
        il suo.
        """
        spec = self._registry.spec(tool_id)
        if spec.owner_agent is not self._config.agent:
            raise ToolNotRegistered(f"tool non disponibile: {tool_id!r}")
        return spec

    def _list_available_tools(self) -> dict[str, Any]:
        """Tool di questo agente, con tier effettivo e conferme richieste."""
        elenco = [
            self._riassunto(tool_id)
            for tool_id, spec in sorted(self._registry.tools.items())
            if spec.owner_agent is self._config.agent
        ]
        return {
            "agent": self._config.agent.value,
            "vault_backend": self._vault.nome_backend,
            "vault_is_stub": self._vault.e_stub,
            "container_available": self._config.container_available,
            # Come gli altri due: un presidio che non c'è va dichiarato dove
            # lo si legge, non solo nel preflight. False significa che il
            # tetto sulle esecuzioni vale per questo processo, e l'host ne
            # avvia uno per connessione.
            "concurrency_shared_across_connections": (
                self._executor.concorrenza_condivisa
            ),
            "tools": elenco,
        }

    def _describe_tool(self, tool_id: str) -> dict[str, Any]:
        """Dettaglio di un singolo tool."""
        self._tool_dell_agente(tool_id)
        return self._riassunto(tool_id, dettagliato=True)

    def _invoke_tool(
        self,
        tool_id: str,
        target: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Esegue un tool applicando il gate, e restituisce un AgentResult.

        Nessun parametro di conferma e nessun parametro di identità: vedere la
        docstring del modulo.

        ``correlation_id`` resta un parametro, ma **non è più l'identità della
        catena**: quella la genera il server. Il valore del client viene
        registrato a parte, in ``peer_correlation_id``.

        La differenza conta. Prima, un client poteva dichiarare il
        ``correlation_id`` di un'altra invocazione e scrivere le proprie righe
        sotto quella catena, rendendo ambigua la ricostruzione — e un log in
        cui non si distingue quale riga appartiene a quale invocazione è un
        log che non si può usare per rispondere a «cosa è stato eseguito».

        Il collegamento non si perde: resta registrato come *affermazione del
        chiamante*, che è ciò che è. E il ``correlation_id`` del server viene
        restituito nel risultato, così chi ha invocato può annotare a sua
        volta la corrispondenza dalla propria parte — due registrazioni
        indipendenti dello stesso collegamento, nessuna delle due falsificabile
        dall'altra parte.
        """
        dichiarato = _peer_correlation_id(correlation_id)
        correlation_id = uuid.uuid4()
        self._audit.log(
            correlation_id=correlation_id,
            peer_correlation_id=dichiarato,
            action=LogAction.AGENT_INVOKED,
            outcome=CallOutcome.OK,
            agent=self._config.agent,
            tool_id=tool_id,
            target=target,
            detail="invocazione ricevuta dal client MCP",
        )

        try:
            self._tool_dell_agente(tool_id)
        except ToolNotRegistered as err:
            return self._risultato_errore(correlation_id, str(err))

        try:
            call, esito = self._executor.execute(
                tool_id,
                self._config.agent,
                correlation_id=correlation_id,
                target=target,
            )
        except ConfirmationRequired as err:
            return self._risultato_in_attesa(correlation_id, tool_id, target, str(err))
        except (ContainerUnavailable, IntegrityMismatch) as err:
            return self._risultato_negato(correlation_id, tool_id, target, str(err))
        except (InvocationRefused, ToolNotRegistered) as err:
            return self._risultato_errore(correlation_id, str(err))
        except ExecutionError as err:
            return self._risultato_errore(correlation_id, f"esecuzione fallita: {err}")
        except Exception as err:
            # Rete di sicurezza finale. Un'eccezione che risalisse al framework
            # MCP lascerebbe nel log un 'agent_invoked' orfano, e chi lo legge
            # concluderebbe che non è stato eseguito nulla — mentre il tool
            # potrebbe aver già agito. Una riga che dice «esito incerto» è
            # un'informazione; l'assenza di righe è una conclusione sbagliata.
            return self._risultato_errore(
                correlation_id,
                f"errore inatteso durante l'invocazione: {type(err).__name__}: {err}",
            )

        risultato = AgentResult(
            correlation_id=correlation_id,
            agent=self._config.agent,
            status=(
                AgentStatus.OK if call.outcome is CallOutcome.OK else AgentStatus.ERROR
            ),
            summary=f"{tool_id}: {call.detail}",
            tool_calls=[call],
        )
        self._log_risultato(risultato)
        return {
            "result": risultato.model_dump(mode="json"),
            "output": {
                "stdout": esito.stdout,
                "stderr": esito.stderr,
                "returncode": esito.returncode,
                # Dichiarato, non nascosto: chi legge un output tagliato senza
                # saperlo — il modello compreso — ne trae conclusioni sbagliate.
                "truncated": esito.truncated,
            },
        }

    def _raise_tool_tier(self, tool_id: str, tier: str) -> dict[str, Any]:
        """Innalza il tier di un tool. Solo in salita."""
        correlation_id = uuid.uuid4()
        try:
            self._tool_dell_agente(tool_id)
        except ToolNotRegistered as err:
            return {"ok": False, "error": str(err)}

        try:
            richiesto = RiskTier(tier)
        except ValueError:
            ammessi = ", ".join(t.value for t in RiskTier)
            return {"ok": False, "error": f"tier non valido: {tier!r}. Ammessi: {ammessi}"}

        try:
            risultante = self._registry.set_override(
                tool_id,
                richiesto,
                correlation_id=correlation_id,
                agent=self._config.agent,
            )
        except OverrideRefused as err:
            return {"ok": False, "error": str(err)}

        durata = self._registry.override_scope(tool_id)
        return {
            "ok": True,
            "tool_id": tool_id,
            "effective_tier": risultante.value,
            "declared_tier": self._registry.spec(tool_id).default_tier.value,
            # La durata è quella reale, non una costante: dipende da dove
            # l'innalzamento è finito, e una scrittura su disco può non essere
            # riuscita. Dichiararla «persistente» in quel caso sarebbe la
            # bugia peggiore delle due, perché induce a non ricontrollare.
            "override_scope": durata.value,
            "override_note": NOTE_DURATA[durata],
        }

    # -- riassunti e risultati ---------------------------------------------- #

    def _riassunto(self, tool_id: str, *, dettagliato: bool = False) -> dict[str, Any]:
        spec = self._registry.spec(tool_id)
        policy = self._registry.policy_for(tool_id)
        base: dict[str, Any] = {
            "tool_id": spec.tool_id,
            "description": spec.description,
            "declared_tier": spec.default_tier.value,
            "effective_tier": self._registry.effective_tier(tool_id).value,
            "personal_data": spec.personal_data,
            "requires_container": spec.requires_container,
            "confirmation": {
                "technical": policy.technical.value,
                "personal_data": policy.personal.value,
                "required": policy.requires_confirmation,
            },
            "executable_now": not policy.requires_confirmation,
        }
        if dettagliato:
            base["unattended_safe"] = policy.unattended_safe
            base["shares_script_with"] = list(
                self._registry.tools_sharing_exec(tool_id)
            )
            durata = self._registry.override_scope(tool_id)
            attivo = durata is not OverrideScope.NONE
            base["override_active"] = attivo
            base["override_scope"] = durata.value if attivo else None
            base["override_note"] = NOTE_DURATA[durata] if attivo else None
        return base

    def _log_risultato(self, risultato: AgentResult) -> None:
        """Registra la riga ``agent_result`` della catena.

        Solo quella: le righe ``tool_call`` sono già state scritte da chi ha
        preso quelle decisioni — il gate e il registro — e riscriverle qui le
        duplicherebbe sotto lo stesso ``correlation_id``, rendendo il log
        ambiguo su quante volte una cosa è avvenuta davvero.
        """
        esito = {
            AgentStatus.OK: CallOutcome.OK,
            AgentStatus.ERROR: CallOutcome.ERROR,
            AgentStatus.NEEDS_CONFIRMATION: CallOutcome.PENDING,
        }[risultato.status]
        self._audit.log(
            correlation_id=risultato.correlation_id,
            action=LogAction.AGENT_RESULT,
            outcome=esito,
            agent=risultato.agent,
            detail=risultato.summary,
        )

    def _risultato_in_attesa(
        self, correlation_id: uuid.UUID, tool_id: str, target: str | None, motivo: str
    ) -> dict[str, Any]:
        """Risultato di un tool che richiede conferma: **non** eseguito.

        Il ``detail`` diceva "in attesa di conferma dell'utente", e non è
        vero: non c'è nessuna attesa, perché non esiste un canale su cui la
        conferma possa arrivare. Il canale reale è l'elicitation di MCP, che
        non è ancora collegata.

        La differenza non è di stile. Un modello che legge "in attesa"
        conclude che qualcuno gli risponderà, e il comportamento ragionevole
        diventa riprovare — o peggio, cercare un'altra via per ottenere lo
        stesso effetto, che è esattamente ciò che la conferma doveva
        impedire. Un modello che legge "nessun canale collegato" sa che deve
        chiedere a una persona fuori banda.
        """
        risultato = AgentResult(
            correlation_id=correlation_id,
            agent=self._config.agent,
            status=AgentStatus.NEEDS_CONFIRMATION,
            summary=motivo,
            tool_calls=[
                ToolCall(
                    tool_id=tool_id,
                    target=target,
                    tier_effective=self._registry.effective_tier(tool_id),
                    authorized_by=AuthorizedBy.NONE,
                    outcome=CallOutcome.PENDING,
                    detail=MOTIVO_CONFERMA_NON_COLLEGATA,
                )
            ],
        )
        self._log_risultato(risultato)
        return {"result": risultato.model_dump(mode="json"), "output": None}

    def _risultato_negato(
        self, correlation_id: uuid.UUID, tool_id: str, target: str | None, motivo: str
    ) -> dict[str, Any]:
        risultato = AgentResult(
            correlation_id=correlation_id,
            agent=self._config.agent,
            status=AgentStatus.ERROR,
            summary=motivo,
            tool_calls=[
                ToolCall(
                    tool_id=tool_id,
                    target=target,
                    tier_effective=self._registry.effective_tier(tool_id),
                    authorized_by=AuthorizedBy.NONE,
                    outcome=CallOutcome.DENIED,
                    detail=motivo,
                )
            ],
        )
        self._log_risultato(risultato)
        return {"result": risultato.model_dump(mode="json"), "output": None}

    def _risultato_errore(self, correlation_id: uuid.UUID, motivo: str) -> dict[str, Any]:
        risultato = AgentResult(
            correlation_id=correlation_id,
            agent=self._config.agent,
            status=AgentStatus.ERROR,
            summary=motivo,
        )
        self._log_risultato(risultato)
        return {"result": risultato.model_dump(mode="json"), "output": None}


def _peer_correlation_id(valore: object) -> str | None:
    """Normalizza l'identificativo dichiarato dal client, per registrarlo.

    Non viene usato come identità della catena, quindi non deve essere un
    UUID valido: viene conservato come stringa, perché registrare «il client
    ha dichiarato questo valore malformato» è più informativo che scartarlo.

    Trattato come input non fidato: solo stringhe, troncate alla lunghezza del
    campo di log.
    """
    if isinstance(valore, str) and valore.strip():
        return valore.strip()[:128]
    return None


def _costruisci_backend(config: ServerConfig) -> VaultBackend:
    """Costruisce il backend del vault dalla configurazione.

    In Milestone 0 esiste solo lo stub. Un backend sconosciuto fa fallire
    l'avvio invece di ricadere sullo stub: credere di avere le credenziali
    reali e averne di finte è un modo silenzioso di non funzionare.
    """
    if config.vault.backend != "stub":
        raise NotImplementedError(
            f"backend vault non collegato: {config.vault.backend!r}. "
            "In questa milestone è disponibile solo 'stub'."
        )
    stub = StubBackend()
    for nome in config.vault.stub_secrets:
        stub.semina(nome)
    return stub


def crea_server(config_path: str | Path) -> HermesServer:
    """Costruisce un server dalla configurazione indicata."""
    return HermesServer(load_config(config_path))


def main(argv: list[str] | None = None) -> int:
    """Entrypoint: ``python -m mcp_server.server <config.toml>``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="hermes-core",
        description="Server MCP della toolbox difensiva Hermes (trasporto stdio).",
    )
    parser.add_argument("config", help="percorso del file di configurazione TOML")
    args = parser.parse_args(argv)

    crea_server(args.config).run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
