"""Test della derivazione della confirmation policy (M0 passo 3).

La derivazione ha sei combinazioni in tutto: sono tutte coperte
esplicitamente, perché è il punto in cui si decide se chiedere o non chiedere
il permesso all'utente, e una combinazione non testata lì è una conferma che
potrebbe non essere mai chiesta.
"""

from __future__ import annotations

import itertools

import pytest
from pydantic import ValidationError

from mcp_server.contracts import OwnerAgent, RiskTier, ToolSpec
from mcp_server.tiers import (
    CADENZA_DATI_PERSONALI,
    ConfirmationCadence,
    ConfirmationPolicy,
    derive_policy,
    derive_policy_for,
)

TUTTI_I_TIER = tuple(RiskTier)
TUTTE_LE_COMBINAZIONI = tuple(itertools.product(TUTTI_I_TIER, (False, True)))


def _spec(**override) -> ToolSpec:
    base = {
        "tool_id": "echo.ping",
        "owner_agent": OwnerAgent.ECHO_DUMMY,
        "default_tier": RiskTier.VERDE,
        "personal_data": False,
        "requires_container": False,
        "exec_path": "agents/echo_agent/run.py",
        "exec_sha256": "a" * 64,
        "description": "Tool dummy.",
    }
    return ToolSpec(**(base | override))


# --------------------------------------------------------------------------- #
# Cadenza — ordinamento
# --------------------------------------------------------------------------- #


def test_cadenza_ordinamento_monotono():
    assert (
        ConfirmationCadence.NESSUNA.rank
        < ConfirmationCadence.UNA_TANTUM_PER_SCOPE.rank
        < ConfirmationCadence.PUNTUALE.rank
    )


def test_ogni_cadenza_ha_un_rank():
    """Una cadenza senza rank romperebbe il calcolo della più stringente."""
    assert {c.rank for c in ConfirmationCadence} == {0, 1, 2}


# --------------------------------------------------------------------------- #
# Asse tecnico — la tabella concordata
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("tier", "attesa"),
    [
        (RiskTier.VERDE, ConfirmationCadence.NESSUNA),
        (RiskTier.GIALLO, ConfirmationCadence.UNA_TANTUM_PER_SCOPE),
        (RiskTier.ROSSO, ConfirmationCadence.PUNTUALE),
    ],
)
def test_cadenza_tecnica_per_tier(tier: RiskTier, attesa: ConfirmationCadence):
    assert derive_policy(tier, personal_data=False).technical is attesa


def test_ogni_tier_ha_una_cadenza():
    """Mappa totale: un tier futuro deve rompere i test, non cadere su un default."""
    for tier in TUTTI_I_TIER:
        assert derive_policy(tier, personal_data=False).technical in ConfirmationCadence


def test_cadenza_tecnica_monotona_nel_tier():
    """Un tier più alto non può richiedere una conferma più debole."""
    ordinati = sorted(TUTTI_I_TIER, key=lambda t: t.rank)
    ranghi = [derive_policy(t, personal_data=False).technical.rank for t in ordinati]
    assert ranghi == sorted(ranghi)


# --------------------------------------------------------------------------- #
# Asse dati personali — indipendenza
# --------------------------------------------------------------------------- #


def test_dati_personali_non_altera_asse_tecnico():
    """I due assi sono indipendenti: il flag non tocca la cadenza tecnica."""
    for tier in TUTTI_I_TIER:
        senza = derive_policy(tier, personal_data=False)
        con = derive_policy(tier, personal_data=True)
        assert senza.technical is con.technical


def test_verde_con_dati_personali_richiede_comunque_conferma():
    """Il caso che dimostra che i due assi non si fondono.

    Nessuna conferma tecnica dovuta, ma la conferma dedicata sui dati
    personali resta. Collassare gli assi perderebbe esattamente questo.
    """
    pol = derive_policy(RiskTier.VERDE, personal_data=True)
    assert pol.technical is ConfirmationCadence.NESSUNA
    assert pol.personal is CADENZA_DATI_PERSONALI
    assert pol.requires_confirmation is True
    assert pol.unattended_safe is False


def test_senza_dati_personali_nessuna_conferma_dedicata():
    for tier in TUTTI_I_TIER:
        assert (
            derive_policy(tier, personal_data=False).personal
            is ConfirmationCadence.NESSUNA
        )


def test_dati_personali_non_indebolisce_mai():
    """Attivare il flag può solo aggiungere conferme, mai togliere."""
    for tier in TUTTI_I_TIER:
        senza = derive_policy(tier, personal_data=False)
        con = derive_policy(tier, personal_data=True)
        assert con.strictest.rank >= senza.strictest.rank
        assert con.requires_confirmation or not senza.requires_confirmation


# --------------------------------------------------------------------------- #
# Totalità ed esaustività
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("tier", "personal_data"), TUTTE_LE_COMBINAZIONI)
def test_tutte_le_combinazioni_derivano(tier: RiskTier, personal_data: bool):
    pol = derive_policy(tier, personal_data)
    assert pol.tier is tier
    assert pol.personal_data is personal_data


def test_solo_verde_senza_dati_personali_e_non_presidiabile():
    """Unattended-safe solo con nessuna conferma su entrambi gli assi."""
    sicuri = [
        (t, pd) for t, pd in TUTTE_LE_COMBINAZIONI if derive_policy(t, pd).unattended_safe
    ]
    assert sicuri == [(RiskTier.VERDE, False)]


def test_rosso_mai_non_presidiato():
    """Pianificare un tool a conferma puntuale equivarrebbe a declassarlo."""
    for personal_data in (False, True):
        pol = derive_policy(RiskTier.ROSSO, personal_data)
        assert pol.strictest is ConfirmationCadence.PUNTUALE
        assert pol.unattended_safe is False


def test_strictest_prende_la_piu_stringente():
    # Giallo (una-tantum) + dati personali (una-tantum) -> una-tantum
    assert (
        derive_policy(RiskTier.GIALLO, True).strictest
        is ConfirmationCadence.UNA_TANTUM_PER_SCOPE
    )
    # Rosso (puntuale) + dati personali (una-tantum) -> puntuale
    assert derive_policy(RiskTier.ROSSO, True).strictest is ConfirmationCadence.PUNTUALE
    # Verde (nessuna) + dati personali (una-tantum) -> una-tantum
    assert (
        derive_policy(RiskTier.VERDE, True).strictest
        is ConfirmationCadence.UNA_TANTUM_PER_SCOPE
    )


# --------------------------------------------------------------------------- #
# La policy non è falsificabile
# --------------------------------------------------------------------------- #


def test_policy_immutabile():
    pol = derive_policy(RiskTier.ROSSO, personal_data=False)
    with pytest.raises(ValidationError):
        pol.technical = ConfirmationCadence.NESSUNA  # type: ignore[misc]


def test_policy_incoerente_non_costruibile():
    """Non si può dichiarare un tier Rosso con una cadenza più lassa.

    Un oggetto così sarebbe un aggiramento dei controlli travestito da dato.
    """
    with pytest.raises(ValidationError) as err:
        ConfirmationPolicy(
            tier=RiskTier.ROSSO,
            personal_data=False,
            technical=ConfirmationCadence.NESSUNA,
            personal=ConfirmationCadence.NESSUNA,
        )
    assert "rosso" in str(err.value).lower()


def test_policy_dati_personali_incoerente_non_costruibile():
    with pytest.raises(ValidationError):
        ConfirmationPolicy(
            tier=RiskTier.VERDE,
            personal_data=True,
            technical=ConfirmationCadence.NESSUNA,
            personal=ConfirmationCadence.NESSUNA,
        )


def test_policy_rifiuta_campi_non_dichiarati():
    with pytest.raises(ValidationError):
        ConfirmationPolicy(
            tier=RiskTier.VERDE,
            personal_data=False,
            technical=ConfirmationCadence.NESSUNA,
            personal=ConfirmationCadence.NESSUNA,
            override_consentito=True,
        )


# --------------------------------------------------------------------------- #
# Derivazione da una ToolSpec
# --------------------------------------------------------------------------- #


def test_derive_per_spec_usa_il_default_tier():
    pol = derive_policy_for(_spec(default_tier=RiskTier.GIALLO))
    assert pol.technical is ConfirmationCadence.UNA_TANTUM_PER_SCOPE


def test_derive_per_spec_onora_il_tier_effettivo():
    """La policy va calcolata sul tier effettivo, non sul dichiarato.

    Ignorare un override significherebbe applicare conferme più lasse di
    quelle che l'utente ha richiesto innalzando il tier.
    """
    spec = _spec(default_tier=RiskTier.VERDE)
    pol = derive_policy_for(spec, effective_tier=RiskTier.ROSSO)
    assert pol.tier is RiskTier.ROSSO
    assert pol.technical is ConfirmationCadence.PUNTUALE


def test_derive_per_spec_propaga_dati_personali():
    pol = derive_policy_for(_spec(personal_data=True))
    assert pol.personal is CADENZA_DATI_PERSONALI


def test_spec_non_puo_dichiarare_la_policy():
    """La cadenza è derivata dal server, non dichiarabile dal tool."""
    assert "confirmation_policy" not in ToolSpec.model_fields
    assert not hasattr(_spec(), "confirmation_policy")


def test_modulo_senza_io():
    """La derivazione è pura: nessuno stato, nessun accesso a file o registry."""
    import mcp_server.tiers as tiers

    assert not hasattr(tiers, "open")
    vietati = {"os", "pathlib", "json", "sqlite3", "socket", "subprocess"}
    assert vietati.isdisjoint(vars(tiers).keys())
