"""Derivazione della confirmation policy dai metadati di un tool.

Il contratto di metadati ha **due assi indipendenti**:

* l'asse tecnico, il :class:`~mcp_server.contracts.RiskTier` (verde/giallo/rosso);
* l'asse dei dati personali, il flag booleano ``personal_data``.

Questo modulo traduce quei due assi nelle conferme che l'utente deve dare prima
che un tool venga eseguito. È una funzione **pura**: nessuna I/O, nessuno stato,
nessun accesso al registry. Il che la rende esaustivamente testabile — sei
combinazioni in tutto — e questa è una proprietà voluta, perché è il punto in
cui si decide se chiedere o non chiedere il permesso all'utente.

Perché la derivazione sta qui e non nel contratto
-------------------------------------------------

:class:`~mcp_server.contracts.ToolSpec` non ha, e non deve avere, un campo
``confirmation_policy``: se il tool potesse dichiarare la propria cadenza di
conferma, potrebbe assegnarsene una più lassa del proprio rischio. La cadenza è
calcolata dal server a partire dal tier dichiarato. Per la stessa ragione
:class:`ConfirmationCadence` vive in questo modulo e non in ``contracts``: è
vocabolario di ciò che il server *deriva*, non di ciò che il tool *dichiara*.

I due assi non si fondono
-------------------------

Un tool Verde che tratta dati personali non richiede conferme tecniche ma
richiede comunque la conferma dedicata sui dati personali. Collassare i due
assi in un unico valore perderebbe questa informazione, e con essa la ragione
per cui all'utente viene chiesto qualcosa. :class:`ConfirmationPolicy` espone
quindi le due cadenze separatamente, e offre la sintesi solo come comodità.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_server.contracts import RiskTier, ToolSpec


class ConfirmationCadence(StrEnum):
    """Con quale frequenza l'utente deve confermare.

    L'ordinamento è significativo: ``NESSUNA < UNA_TANTUM_PER_SCOPE < PUNTUALE``.
    Serve a stabilire quale di due conferme sia la più stringente senza
    codificare confronti altrove.
    """

    NESSUNA = "nessuna"
    UNA_TANTUM_PER_SCOPE = "una_tantum_per_scope"
    PUNTUALE = "puntuale"

    @property
    def rank(self) -> int:
        return _CADENCE_RANK[self]


_CADENCE_RANK: dict[ConfirmationCadence, int] = {
    ConfirmationCadence.NESSUNA: 0,
    ConfirmationCadence.UNA_TANTUM_PER_SCOPE: 1,
    ConfirmationCadence.PUNTUALE: 2,
}


#: Asse tecnico → cadenza. Mappa totale: ogni tier ha una voce, così
#: l'aggiunta di un tier futuro rompe i test invece di cadere in un default
#: permissivo.
_CADENZA_PER_TIER: dict[RiskTier, ConfirmationCadence] = {
    RiskTier.VERDE: ConfirmationCadence.NESSUNA,
    RiskTier.GIALLO: ConfirmationCadence.UNA_TANTUM_PER_SCOPE,
    RiskTier.ROSSO: ConfirmationCadence.PUNTUALE,
}

#: Asse dati personali → cadenza della conferma dedicata, quando il flag è
#: attivo. Una-tantum-per-scope è proporzionata: l'utente va reso consapevole
#: di diventare titolare del trattamento, ma una conferma a ogni esecuzione
#: lo addestrerebbe a cliccare senza leggere, che è il contrario dello scopo.
CADENZA_DATI_PERSONALI: ConfirmationCadence = ConfirmationCadence.UNA_TANTUM_PER_SCOPE


class ConfirmationPolicy(BaseModel):
    """Le conferme richieste per un tool, per asse.

    Immutabile e priva di campi non dichiarati, come i contratti: una policy
    che si possa modificare dopo il calcolo non è un controllo.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tier: RiskTier = Field(description="Tier effettivo su cui è stata calcolata.")
    personal_data: bool = Field(description="Flag dati personali del tool.")
    technical: ConfirmationCadence = Field(
        description="Cadenza della conferma dovuta al rischio tecnico."
    )
    personal: ConfirmationCadence = Field(
        description="Cadenza della conferma dedicata ai dati personali."
    )

    @model_validator(mode="after")
    def _coerenza_con_gli_assi(self) -> ConfirmationPolicy:
        """La policy deve corrispondere ai suoi assi.

        Impedisce di costruire a mano una policy che dichiari un tier Rosso e
        una cadenza tecnica inferiore a quella dovuta: un oggetto del genere
        sarebbe un aggiramento dei controlli travestito da dato.
        """
        attesa = _CADENZA_PER_TIER[self.tier]
        if self.technical is not attesa:
            raise ValueError(
                f"tier '{self.tier}' impone cadenza tecnica '{attesa}', "
                f"ricevuta '{self.technical}'"
            )
        attesa_personale = (
            CADENZA_DATI_PERSONALI if self.personal_data else ConfirmationCadence.NESSUNA
        )
        if self.personal is not attesa_personale:
            raise ValueError(
                f"personal_data={self.personal_data} impone cadenza "
                f"'{attesa_personale}', ricevuta '{self.personal}'"
            )
        return self

    # -- sintesi ------------------------------------------------------------ #

    @property
    def requires_confirmation(self) -> bool:
        """Se almeno una conferma è richiesta su uno qualsiasi dei due assi."""
        return (
            self.technical is not ConfirmationCadence.NESSUNA
            or self.personal is not ConfirmationCadence.NESSUNA
        )

    @property
    def strictest(self) -> ConfirmationCadence:
        """La più stringente fra le due cadenze.

        Comodità per chi deve prendere una sola decisione. Non sostituisce le
        due cadenze: il *motivo* per cui si chiede resta nei due assi, e
        all'utente va mostrato quello, non la sintesi.
        """
        return max(self.technical, self.personal, key=lambda c: c.rank)

    @property
    def unattended_safe(self) -> bool:
        """Se il tool è eseguibile senza nessuno davanti allo schermo.

        Solo una cadenza ``NESSUNA`` su entrambi gli assi lo è. Una cadenza
        ``UNA_TANTUM_PER_SCOPE`` è eseguibile in modo non presidiato soltanto
        se il consenso per quello scope è già stato registrato — condizione che
        questo modulo non può verificare, perché non ha stato: la valuta il
        gestore delle routine. Una cadenza ``PUNTUALE`` non lo è mai:
        pianificarla equivarrebbe a declassarla.
        """
        return not self.requires_confirmation


def derive_policy(tier: RiskTier, personal_data: bool) -> ConfirmationPolicy:
    """Deriva la policy dai due assi.

    Funzione totale: ogni combinazione di ``(tier, personal_data)`` ha un
    esito, e un tier non mappato solleva un errore invece di ricadere su un
    default.
    """
    try:
        technical = _CADENZA_PER_TIER[tier]
    except KeyError as err:  # pragma: no cover - raggiungibile solo con un tier nuovo
        raise ValueError(f"tier senza cadenza definita: {tier!r}") from err

    personal = (
        CADENZA_DATI_PERSONALI if personal_data else ConfirmationCadence.NESSUNA
    )
    return ConfirmationPolicy(
        tier=tier,
        personal_data=personal_data,
        technical=technical,
        personal=personal,
    )


def derive_policy_for(spec: ToolSpec, *, effective_tier: RiskTier | None = None) -> ConfirmationPolicy:
    """Deriva la policy di un tool registrato.

    Parameters
    ----------
    spec:
        Contratto di registrazione del tool.
    effective_tier:
        Tier effettivo calcolato dal registry come ``max(default, override)``.
        Se omesso si usa il ``default_tier`` della spec. Il parametro esiste
        perché la policy va calcolata sul tier *effettivo*: ignorare un
        override significherebbe applicare conferme più lasse di quelle
        richieste dall'utente.
    """
    return derive_policy(effective_tier or spec.default_tier, spec.personal_data)


__all__ = [
    "CADENZA_DATI_PERSONALI",
    "ConfirmationCadence",
    "ConfirmationPolicy",
    "derive_policy",
    "derive_policy_for",
]
