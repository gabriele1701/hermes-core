"""Registro dei tool del server MCP.

Unico punto in cui un tool diventa invocabile. Tiene tre cose separate:

1. le :class:`~mcp_server.contracts.ToolSpec` registrate, immutabili;
2. gli **override di tier** dell'utente, in store distinti dalle spec;
3. il calcolo del **tier effettivo** e della policy che ne deriva.

Perché gli store degli override sono separati
---------------------------------------------

Il tier dichiarato all'integrazione non è modificabile: la spec è ``frozen``.
Un innalzamento finisce in uno store a parte, e il tier effettivo è il massimo
fra la spec e gli store. Da questo derivano due proprietà che una singola
struttura mutabile non darebbe:

* il tier dichiarato resta sempre ispezionabile come l'ha dichiarato
  l'integratore, utile in audit per distinguere "era rischioso" da "l'ho
  alzato io";
* un override più basso del default è **inerte anche se finisse in uno store**,
  perché il massimo lo scarta. La difesa non riposa solo sul controllo
  all'ingresso.

Semantica dell'override: solo in salita
---------------------------------------

``set_override`` accetta un tier maggiore o uguale a quello effettivo e
**rifiuta** qualunque declassamento. Permettere di abbassare un tier sarebbe
un modo di disattivare i controlli, cosa che il documento di scope vieta:
l'override è consenso a eseguire qualcosa di rischioso, non licenza di
dichiararlo meno rischioso di quanto sia.

L'invariante che ne risulta è che il tier effettivo è monotòno non decrescente.

Tre fonti di innalzamento, un solo massimo
------------------------------------------

Il tier effettivo è ``max`` di tre fonti, e **nessuna può abbassare le altre**:

1. il tier **dichiarato** nella spec, che fa da pavimento;
2. ``override_tier`` in ``[[tool]]``, versionato, per gli innalzamenti che
   devono restare e che si vedono in review;
3. lo **store** append-only (:mod:`mcp_server.overrides`), scritto quando
   l'innalzamento arriva a runtime via MCP.

Prima di questa patch esisteva solo un dizionario in memoria, e l'host MCP
avvia un processo server **nuovo a ogni connessione**, a ogni ``/reload-mcp``
e a ogni sessione: un tool innalzato a Rosso tornava al proprio tier
dichiarato poco dopo, mentre il log continuava a mostrare l'``override_set``
come se fosse ancora in vigore.

Dove la persistenza non c'è il comportamento resta quello di prima, ma
**dichiarato**: se lo store non è configurato — o se la scrittura non riesce —
l'innalzamento vale per la connessione, ``override_scope`` lo dice, e il log
registra un ``override_not_persisted``. Un controllo che decade in silenzio è
peggio di un controllo assente; uno che decade dichiarandolo è un limite noto.

Un ``override_tier`` più basso del tier dichiarato non fa fallire l'avvio: è
inerte per costruzione, e l'esito è il tier dichiarato, cioè il **più
stretto** dei due. Viene registrato come rifiuto e il server parte, perché far
cadere l'intera toolbox per un override che non allenta nulla sarebbe una
reazione sproporzionata. Un ``override_tier`` con un **valore inventato** fa
invece fallire l'avvio: lì l'operatore crede di aver alzato un tier e non l'ha
alzato, e quello è un controllo che manca.

Registrazione: append-only, costruita all'avvio
-----------------------------------------------

Il registro si popola all'avvio dalla configurazione versionata e non espone
deregistrazione. Registrare due volte lo stesso ``tool_id`` è **rifiutato**:
sarebbe la via più comoda per aggirare la regola sull'override, ri-registrando
un tool con un tier più basso. Aggiornare un tool (nuovo script, nuovo SHA)
significa modificare la configurazione versionata e riavviare il server, non
sovrascrivere una voce a caldo.

Isolamento fra agenti
---------------------

Ogni tool dichiara il proprio ``owner_agent``, e il registro è l'unico
componente che lo sa. :meth:`ToolRegistry.assert_can_invoke` fa valere quel
confine: senza, il campo sarebbe decorativo e l'agente di pentest potrebbe
invocare i tool dell'agente di vulnerability assessment e viceversa.

Aliasing: perché si rileva ma non si blocca
-------------------------------------------

Rifiutare il ``tool_id`` duplicato chiude la via più comoda al declassamento,
non tutte. Resta quella di registrare un **secondo tool_id sullo stesso
script** dichiarandolo a tier più basso: stessa capacità, conferme più lasche,
regola sull'override aggirata.

Un rifiuto secco su ``exec_path`` ripetuto sarebbe però sbagliato, perché lo
stesso pattern descrive un caso legittimo: uno script con più sottocomandi,
dove ``nmap.ping_sweep`` è davvero Verde e ``nmap.aggressive`` è davvero
Rosso. I due casi oggi sono **indistinguibili**, perché :class:`ToolSpec` non
ha un campo argomenti: ``exec_path`` è l'intera identità di ciò che viene
eseguito, e il contratto non ha l'informazione per dire se due tool facciano
la stessa cosa o cose diverse.

Finché quell'informazione manca, il registro **rileva e registra** invece di
bloccare: una registrazione che condivide ``exec_path`` con un tool a tier
superiore emette un evento ``tool_alias_detected``, che in review salta
all'occhio senza rompere il pattern legittimo. Viene segnalata anche la
dichiarazione di integrità incoerente — stesso ``exec_path``, ``exec_sha256``
diversi — che non ha alcun caso d'uso valido: lo stesso file non può avere
due hash, quindi una delle due spec è sbagliata.

La chiusura definitiva richiede ``exec_args`` nel contratto, così che
l'identità di un tool diventi ``(path, sha, args)`` e l'aliasing genuino
diventi rifiutabile senza falsi positivi. È registrata come voce ad **alta
rilevanza** in ``docs/debito-sicurezza.md``.

Limite di fiducia
-----------------

Nessun controllo in questo modulo protegge da una configurazione malevola: il
registro **si fida del proprio input per costruzione**. Il confine di fiducia
vero è chi può scrivere la configurazione, cioè chi può scrivere nel repo. Ciò
che il registro può fare, e fa, è rendere ogni registrazione, rifiuto e
anomalia un evento tracciato, così che configurazione e log raccontino la
stessa storia e una discrepanza si veda.
"""

from __future__ import annotations

import uuid
from types import MappingProxyType
from typing import Mapping

from pydantic import ValidationError

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier, ToolSpec
from mcp_server.overrides import OverrideScope, OverrideStore
from mcp_server.tiers import ConfirmationPolicy, derive_policy_for

#: Chiave che, in un payload ``[[tool]]``, innalza il tier in modo versionato.
#: Non è un campo di :class:`ToolSpec`: la spec deve restare esattamente come
#: l'ha dichiarata l'integratore, altrimenti in audit non si distingue più
#: «era rischioso» da «l'ho alzato io».
CHIAVE_OVERRIDE = "override_tier"

# --------------------------------------------------------------------------- #
# Errori
# --------------------------------------------------------------------------- #


class RegistryError(Exception):
    """Base degli errori del registro."""


class ToolAlreadyRegistered(RegistryError):
    """Un tool con lo stesso ``tool_id`` è già registrato."""


class ToolNotRegistered(RegistryError):
    """Il ``tool_id`` richiesto non è nel registro."""


class ToolSpecRejected(RegistryError):
    """La spec proposta non soddisfa il contratto di registrazione."""


class OverrideRefused(RegistryError):
    """L'override richiesto abbasserebbe il tier effettivo."""


class InvocationRefused(RegistryError):
    """L'agente richiedente non è il proprietario del tool."""


# --------------------------------------------------------------------------- #
# Registro
# --------------------------------------------------------------------------- #


class ToolRegistry:
    """Registro in memoria dei tool invocabili.

    Parameters
    ----------
    audit:
        Log su cui registrare registrazioni, rifiuti e override. Ogni
        decisione di sicurezza del registro lascia una riga.
    correlation_id:
        Correlazione usata per gli eventi che non nascono da una invocazione
        di agente — tipicamente il popolamento all'avvio. Se omesso ne viene
        generato uno per istanza, così gli eventi di startup restano
        raggruppabili.
    store:
        Store append-only degli innalzamenti. ``None`` significa nessuna
        persistenza: gli override valgono per la connessione, come prima di
        questa patch, e la cosa viene dichiarata invece di essere presunta.

    Raises
    ------
    mcp_server.overrides.OverrideStoreError
        Se lo store esiste ma non è leggibile. Non si prosegue: applicare tier
        più bassi di quelli registrati perché un file non si apriva sarebbe
        allentare dei controlli per un guasto di I/O.
    """

    def __init__(
        self,
        audit: AuditLog,
        *,
        correlation_id: uuid.UUID | None = None,
        store: OverrideStore | None = None,
    ) -> None:
        self._audit = audit
        self._correlation_id = correlation_id or uuid.uuid4()
        self._specs: dict[str, ToolSpec] = {}
        self._store = store
        # Tre dizionari e non uno: il tier effettivo è il massimo, ma la
        # *provenienza* serve per dire quanto dura l'innalzamento, e un
        # dizionario unico la perderebbe.
        self._config_tiers: dict[str, RiskTier] = {}
        self._store_tiers: dict[str, RiskTier] = {}
        self._session_tiers: dict[str, RiskTier] = {}
        self._carica_store()

    # -- introspezione ------------------------------------------------------ #

    @property
    def correlation_id(self) -> uuid.UUID:
        return self._correlation_id

    @property
    def tools(self) -> Mapping[str, ToolSpec]:
        """Vista in sola lettura delle spec registrate."""
        return MappingProxyType(self._specs)

    @property
    def overrides(self) -> Mapping[str, RiskTier]:
        """Override attivi per tool: il massimo fra le fonti, spec esclusa.

        Un tool assente da questa vista è al proprio tier dichiarato. La vista
        non dice da *dove* venga l'innalzamento: per quello c'è
        :meth:`override_scope`.
        """
        combinati: dict[str, RiskTier] = {}
        for fonte in (self._config_tiers, self._store_tiers, self._session_tiers):
            for tool_id, tier in fonte.items():
                precedente = combinati.get(tool_id)
                if precedente is None or tier.rank > precedente.rank:
                    combinati[tool_id] = tier
        return MappingProxyType(combinati)

    def override_scope(self, tool_id: str) -> OverrideScope:
        """Da dove viene l'override attivo, e quindi se sopravvive.

        È la domanda che si pone chi ha appena alzato un tier dopo un
        incidente: *resta alzato?* Una risposta sbagliata qui è peggio di
        nessuna risposta, perché induce a non ricontrollare.
        """
        massimo = self.overrides.get(tool_id)
        if massimo is None:
            return OverrideScope.NONE
        if self._config_tiers.get(tool_id) is massimo:
            return OverrideScope.CONFIG
        if self._store_tiers.get(tool_id) is massimo:
            return OverrideScope.PERSISTENT
        return OverrideScope.SESSION

    def __contains__(self, tool_id: object) -> bool:
        return tool_id in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def spec(self, tool_id: str) -> ToolSpec:
        """Restituisce la spec, o solleva.

        Solleva invece di restituire ``None`` di proposito: un ``None``
        silenzioso invita allo schema ``if not spec: ...`` che finisce per
        saltare i controlli su un tool sconosciuto.
        """
        try:
            return self._specs[tool_id]
        except KeyError as err:
            raise ToolNotRegistered(f"tool non registrato: {tool_id!r}") from err

    # -- registrazione ------------------------------------------------------ #

    def register(self, spec: ToolSpec) -> ToolSpec:
        """Registra un tool già validato.

        Rifiuta un ``tool_id`` duplicato: il registro è append-only.
        """
        if spec.tool_id in self._specs:
            self._log(
                LogAction.TOOL_REGISTRATION_REJECTED,
                CallOutcome.DENIED,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail="tool_id già registrato: il registro non ammette sovrascritture",
            )
            raise ToolAlreadyRegistered(f"tool già registrato: {spec.tool_id!r}")

        self._specs[spec.tool_id] = spec
        policy = derive_policy_for(spec)
        self._log(
            LogAction.TOOL_REGISTERED,
            CallOutcome.OK,
            agent=spec.owner_agent,
            tool_id=spec.tool_id,
            tier_effective=spec.default_tier,
            detail=(
                f"registrato; personal_data={spec.personal_data}, "
                f"requires_container={spec.requires_container}, "
                f"conferma tecnica={policy.technical}, dedicata={policy.personal}"
            ),
        )
        self._segnala_anomalie_di_alias(spec)
        return spec

    def register_payload(self, payload: Mapping[str, object]) -> ToolSpec:
        """Valida un payload grezzo e lo registra.

        Un tentativo di registrazione malformato — tier assente, tier
        inventato, ``exec_path`` con traversal, campi non dichiarati — viene
        **registrato nel log** prima di essere respinto: un tool che prova a
        entrare senza i metadati richiesti è un evento che l'audit deve
        conservare, non un errore da far evaporare.

        La chiave ``override_tier`` viene estratta dal payload prima di
        costruire la spec, e applicata dopo la registrazione: la spec deve
        restare quella dichiarata dall'integratore.
        """
        grezzo = dict(payload)
        richiesto = grezzo.pop(CHIAVE_OVERRIDE, None)
        # Prima il valore dell'override, poi la spec: un valore inventato va
        # scoperto senza aver già registrato il tool.
        override = self._override_da_config(payload, richiesto)

        try:
            spec = ToolSpec(**grezzo)
        except ValidationError as err:
            self._log(
                LogAction.TOOL_REGISTRATION_REJECTED,
                CallOutcome.DENIED,
                tool_id=_tool_id_dal_payload(payload),
                detail=f"spec non conforme al contratto: {_compatta(err)}",
            )
            raise ToolSpecRejected(f"spec non conforme: {err}") from err

        self.register(spec)
        if override is not None:
            self._applica_override_di_config(spec, override)
        return spec

    def _override_da_config(
        self, payload: Mapping[str, object], valore: object
    ) -> RiskTier | None:
        """Converte ``override_tier``, o fa fallire la registrazione.

        Un valore inventato **non** può essere ignorato: l'operatore crede di
        aver innalzato un tier e non l'ha innalzato, quindi il controllo che
        pensa di avere non esiste. È il caso in cui è giusto che il server non
        parta.
        """
        if valore is None:
            return None
        try:
            return RiskTier(valore)  # type: ignore[arg-type]
        except ValueError as err:
            ammessi = ", ".join(t.value for t in RiskTier)
            dettaglio = (
                f"{CHIAVE_OVERRIDE} non valido: {valore!r}. Ammessi: {ammessi}"
            )
            self._log(
                LogAction.TOOL_REGISTRATION_REJECTED,
                CallOutcome.DENIED,
                tool_id=_tool_id_dal_payload(payload),
                detail=dettaglio,
            )
            raise ToolSpecRejected(dettaglio) from err

    def _applica_override_di_config(self, spec: ToolSpec, tier: RiskTier) -> None:
        """Registra un innalzamento versionato, se innalza qualcosa.

        Un override pari o inferiore al tier dichiarato è inerte per
        costruzione, perché il tier effettivo è un massimo. Non viene
        memorizzato — comparirebbe come «override attivo» senza cambiare
        nulla — ma viene registrato: di solito è un refuso, e un refuso in una
        configurazione di sicurezza va visto.

        Non fa fallire l'avvio, a differenza di un valore inventato: l'esito è
        il tier dichiarato, cioè il più stretto dei due, e far cadere l'intera
        toolbox per un override che non allenta nulla sarebbe sproporzionato.
        """
        if tier.rank < spec.default_tier.rank:
            self._log(
                LogAction.OVERRIDE_REJECTED,
                CallOutcome.DENIED,
                agent=spec.owner_agent,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail=(
                    f"{CHIAVE_OVERRIDE}='{tier}' in configurazione è inferiore "
                    f"al tier dichiarato '{spec.default_tier}': inerte, vale il "
                    f"dichiarato. L'override può solo innalzare."
                ),
            )
            return

        if tier.rank == spec.default_tier.rank:
            self._log(
                LogAction.OVERRIDE_REJECTED,
                CallOutcome.OK,
                agent=spec.owner_agent,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail=(
                    f"{CHIAVE_OVERRIDE}='{tier}' coincide col tier dichiarato: "
                    f"ridondante, nessun override registrato"
                ),
            )
            return

        self._config_tiers[spec.tool_id] = tier
        self._log(
            LogAction.OVERRIDE_SET,
            CallOutcome.OK,
            agent=spec.owner_agent,
            tool_id=spec.tool_id,
            tier_effective=tier,
            detail=(
                f"override da configurazione versionata: '{spec.default_tier}' "
                f"-> '{tier}'; durata: {OverrideScope.CONFIG.descrizione}"
            ),
        )

    def _carica_store(self) -> None:
        """Rilegge lo store degli innalzamenti e registra l'esito.

        Le righe scartate vengono **contate e registrate**: ciascuna potrebbe
        essere un innalzamento perduto, e scoprirlo leggendo il log è l'unico
        modo per accorgersene.
        """
        if self._store is None:
            return
        esito = self._store.carica()  # OverrideStoreError risale: fail-closed
        self._store_tiers.update(esito.tiers)
        self._log(
            LogAction.OVERRIDE_STORE_LOADED,
            CallOutcome.ERROR if esito.scartate else CallOutcome.OK,
            detail=(
                f"store {self._store.path}: {esito.righe} righe, "
                f"{len(esito.tiers)} tool con innalzamento attivo, "
                f"{esito.scartate} righe illeggibili scartate"
            ),
        )

    # -- tier effettivo e override ------------------------------------------ #

    def effective_tier(self, tool_id: str) -> RiskTier:
        """Tier applicato al tool: il massimo fra spec, config e store.

        Il massimo è il secondo presidio: anche se in una delle fonti finisse
        un override più basso del tier dichiarato, resterebbe inerte.
        """
        spec = self.spec(tool_id)
        candidati = [spec.default_tier]
        for fonte in (self._config_tiers, self._store_tiers, self._session_tiers):
            tier = fonte.get(tool_id)
            if tier is not None:
                candidati.append(tier)
        return max(candidati, key=lambda t: t.rank)

    def set_override(
        self,
        tool_id: str,
        tier: RiskTier,
        *,
        correlation_id: uuid.UUID | None = None,
        agent: OwnerAgent | None = None,
    ) -> RiskTier:
        """Innalza il tier di un tool. Rifiuta ogni declassamento.

        ``agent`` è l'istanza che ha chiesto la modifica, e va passato: un
        innalzamento di tier è una modifica ai controlli di sicurezza, quindi
        è precisamente l'evento di cui l'audit deve sapere la provenienza.
        Senza, la riga di log dice che il tier è cambiato ma non per mano di
        chi.

        Attenzione a cosa significa quella provenienza: ``raise_tool_tier`` è
        un tool MCP, quindi lo chiama il **modello**, eventualmente spinto da
        un'iniezione nel suo contesto. L'istanza registrata dice da quale
        server è arrivata la richiesta, non che un essere umano l'abbia
        voluta. Il log lo scrive come «richiesto dal client MCP» invece di
        «override utente», perché la seconda formulazione farebbe credere a
        chi legge che dietro ci fosse una persona.

        L'attribuzione a una persona sarà possibile solo quando la conferma
        passerà dall'host, con l'elicitation.

        Un tier uguale a quello effettivo è accettato ed è idempotente, e
        **non scrive nulla**: è ciò che dà allo store il suo tetto
        strutturale. Solo un incremento reale produce una riga, quindi
        diecimila richieste di 'rosso' su un tool già Rosso lasciano una sola
        riga nello store — e diecimilauno nel log d'audit, dove è giusto che
        si vedano, perché in audit conta sapere che qualcuno ha insistito.

        Uno inferiore viene rifiutato e registrato come evento di sicurezza:
        abbassare un tier equivarrebbe a disattivare un controllo.

        Returns
        -------
        Il tier effettivo risultante.
        """
        corrente = self.effective_tier(tool_id)  # solleva se non registrato
        if tier.rank < corrente.rank:
            self._log(
                LogAction.OVERRIDE_REJECTED,
                CallOutcome.DENIED,
                agent=agent,
                tool_id=tool_id,
                tier_effective=corrente,
                detail=(
                    f"declassamento rifiutato, richiesto dal client MCP: "
                    f"'{tier}' su effettivo '{corrente}'; l'override può solo "
                    f"innalzare"
                ),
                correlation_id=correlation_id,
            )
            raise OverrideRefused(
                f"l'override non può abbassare il tier: richiesto {tier!r}, "
                f"effettivo {corrente!r}"
            )

        if tier.rank == corrente.rank:
            # Idempotente: niente da innalzare, quindi niente da persistere.
            self._log(
                LogAction.OVERRIDE_SET,
                CallOutcome.OK,
                agent=agent,
                tool_id=tool_id,
                tier_effective=corrente,
                detail=(
                    f"override richiesto dal client MCP: già a '{corrente}', "
                    f"nessun cambiamento (durata: "
                    f"{self.override_scope(tool_id).descrizione})"
                ),
                correlation_id=correlation_id,
            )
            return corrente

        durata = self._persisti(
            tool_id, tier, agent=agent, correlation_id=correlation_id
        )
        risultante = self.effective_tier(tool_id)
        self._log(
            LogAction.OVERRIDE_SET,
            CallOutcome.OK,
            agent=agent,
            tool_id=tool_id,
            tier_effective=risultante,
            detail=(
                f"override richiesto dal client MCP: '{corrente}' -> "
                f"'{risultante}' (dichiarato "
                f"'{self.spec(tool_id).default_tier}'); durata: {durata.descrizione}"
            ),
            correlation_id=correlation_id,
        )
        return risultante

    def _persisti(
        self,
        tool_id: str,
        tier: RiskTier,
        *,
        agent: OwnerAgent | None,
        correlation_id: uuid.UUID | None,
    ) -> OverrideScope:
        """Registra l'innalzamento dove può, e dice dove è finito.

        L'innalzamento **vale in ogni caso**: se la scrittura non riesce, il
        tier sale comunque in memoria. Il contrario — rifiutare di alzare un
        tier perché non si è riusciti a scriverlo su disco — lascerebbe il
        tool al tier più basso proprio nel momento in cui qualcuno sta
        chiedendo di trattarlo come più rischioso.

        Ciò che non si può fare è **tacere** che non durerà.
        """
        if self._store is None:
            self._session_tiers[tool_id] = tier
            return OverrideScope.SESSION

        try:
            self._store.registra(
                tool_id, tier, agent=agent, correlation_id=correlation_id
            )
        except OSError as err:
            self._session_tiers[tool_id] = tier
            self._log(
                LogAction.OVERRIDE_NOT_PERSISTED,
                CallOutcome.ERROR,
                agent=agent,
                tool_id=tool_id,
                tier_effective=tier,
                detail=(
                    f"innalzamento applicato ma non scritto su "
                    f"{self._store.path}: {err}. Vale per questa connessione; "
                    f"alla prossima il tool torna al tier dichiarato."
                ),
                correlation_id=correlation_id,
            )
            return OverrideScope.SESSION

        self._store_tiers[tool_id] = tier
        return OverrideScope.PERSISTENT

    def policy_for(self, tool_id: str) -> ConfirmationPolicy:
        """Policy di conferma calcolata sul tier **effettivo**."""
        spec = self.spec(tool_id)
        return derive_policy_for(spec, effective_tier=self.effective_tier(tool_id))

    # -- aliasing ------------------------------------------------------------ #

    def tools_sharing_exec(self, tool_id: str) -> tuple[str, ...]:
        """Altri ``tool_id`` registrati sullo stesso ``exec_path``.

        Serve in review: è la domanda da fare quando si vuole sapere quante
        porte d'accesso esistono verso lo stesso script.
        """
        spec = self.spec(tool_id)
        return tuple(
            sorted(
                altro.tool_id
                for altro in self._specs.values()
                if altro.tool_id != tool_id and altro.exec_path == spec.exec_path
            )
        )

    def _segnala_anomalie_di_alias(self, spec: ToolSpec) -> None:
        """Registra gli alias sospetti sullo stesso script.

        Non blocca: il pattern legittimo (uno script, più sottocomandi a
        rischio diverso) e quello abusivo (stesso script a tier più basso)
        sono indistinguibili finché il contratto non ha ``exec_args``.
        """
        fratelli = [
            altro
            for altro in self._specs.values()
            if altro.tool_id != spec.tool_id and altro.exec_path == spec.exec_path
        ]
        if not fratelli:
            return

        # (a) Alias a tier inferiore: possibile declassamento mascherato.
        superiori = [
            altro
            for altro in fratelli
            if self.effective_tier(altro.tool_id).rank > spec.default_tier.rank
        ]
        if superiori:
            elenco = ", ".join(
                f"{a.tool_id}={self.effective_tier(a.tool_id)}" for a in sorted(
                    superiori, key=lambda s: s.tool_id
                )
            )
            self._log(
                LogAction.TOOL_ALIAS_DETECTED,
                CallOutcome.OK,
                agent=spec.owner_agent,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail=(
                    f"registrato a tier '{spec.default_tier}' su exec_path "
                    f"'{spec.exec_path}' già usato a tier superiore da: {elenco}. "
                    f"Verificare che non sia un declassamento mascherato."
                ),
            )

        # (b) Integrità incoerente: lo stesso file non può avere due hash.
        discordi = sorted(
            {a.tool_id for a in fratelli if a.exec_sha256 != spec.exec_sha256}
        )
        if discordi:
            self._log(
                LogAction.TOOL_ALIAS_DETECTED,
                CallOutcome.DENIED,
                agent=spec.owner_agent,
                tool_id=spec.tool_id,
                tier_effective=spec.default_tier,
                detail=(
                    f"dichiarazione di integrità incoerente su exec_path "
                    f"'{spec.exec_path}': exec_sha256 diverso da {', '.join(discordi)}. "
                    f"Almeno una delle spec è errata."
                ),
            )

    # -- isolamento fra agenti ---------------------------------------------- #

    def can_invoke(self, tool_id: str, agent: OwnerAgent) -> bool:
        """Se l'agente è il proprietario del tool."""
        return self.spec(tool_id).owner_agent is agent

    def assert_can_invoke(
        self,
        tool_id: str,
        agent: OwnerAgent,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> ToolSpec:
        """Verifica il confine fra agenti, o solleva registrando il rifiuto."""
        spec = self.spec(tool_id)
        if spec.owner_agent is not agent:
            self._log(
                LogAction.TOOL_CALL,
                CallOutcome.DENIED,
                agent=agent,
                tool_id=tool_id,
                tier_effective=self.effective_tier(tool_id),
                detail=(
                    f"invocazione rifiutata: il tool appartiene a "
                    f"'{spec.owner_agent}', richiedente '{agent}'"
                ),
                correlation_id=correlation_id,
            )
            raise InvocationRefused(
                f"{agent!r} non può invocare {tool_id!r}: appartiene a "
                f"{spec.owner_agent!r}"
            )
        return spec

    # -- interno ------------------------------------------------------------ #

    def _log(
        self,
        action: LogAction,
        outcome: CallOutcome,
        *,
        correlation_id: uuid.UUID | None = None,
        **campi,
    ) -> None:
        self._audit.log(
            correlation_id=correlation_id or self._correlation_id,
            action=action,
            outcome=outcome,
            **campi,
        )


def _tool_id_dal_payload(payload: Mapping[str, object]) -> str | None:
    """Estrae un ``tool_id`` utilizzabile nel log da un payload non valido.

    Il payload è per definizione non conforme, quindi il valore va trattato
    come non fidato: solo stringhe, troncate alla lunghezza del campo di log.
    """
    valore = payload.get("tool_id")
    if isinstance(valore, str) and valore:
        return valore[:64]
    return None


def _compatta(err: ValidationError) -> str:
    """Riassume un errore di validazione in una riga di log."""
    pezzi = [
        f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}"
        for e in err.errors()
    ]
    riga = "; ".join(pezzi)
    return riga[:2000]


__all__ = [
    "CHIAVE_OVERRIDE",
    "InvocationRefused",
    "OverrideRefused",
    "RegistryError",
    "ToolAlreadyRegistered",
    "ToolNotRegistered",
    "ToolRegistry",
    "ToolSpecRejected",
]
