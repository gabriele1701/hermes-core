"""`docs/vocabolari-condivisi.md` deve dire il vero sul lato del server.

Il documento confronta i vocabolari di `hermes-core` con quelli del pannello,
ed è ciò su cui si baserà l'integrazione. Una tabella scritta a mano invecchia
al primo enum che cambia, e invecchia in silenzio: chi la legge dopo non ha
modo di sapere che non corrisponde più al codice.

Questo test lega la colonna del server al codice. **Non** lega quella del
pannello — questo repo non vede l'altro — e il documento lo dice: quella è
una fotografia con una data.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

import pytest

from mcp_server import audit, contracts, overrides, tiers
from mcp_server.audit import esito_da_status
from mcp_server.contracts import AgentStatus

DOCUMENTO = Path(__file__).resolve().parent.parent / "docs" / "vocabolari-condivisi.md"

#: Ogni vocabolario che il documento deve classificare, con l'enum che lo
#: definisce. Un enum nuovo che attraversa il confine col pannello va aggiunto
#: qui *e* nel documento: è la regola «nessun vocabolario non classificato».
VOCABOLARI: dict[str, type[Enum]] = {
    "RiskTier": contracts.RiskTier,
    "OwnerAgent": contracts.OwnerAgent,
    "CallOutcome": contracts.CallOutcome,
    "AuthorizedBy": contracts.AuthorizedBy,
    "LogAction": audit.LogAction,
    "TargetKind": contracts.TargetKind,
    "OverrideScope": overrides.OverrideScope,
    "AgentStatus": contracts.AgentStatus,
    "Severity": contracts.Severity,
    "ConfirmationCadence": tiers.ConfirmationCadence,
}

STATI = {"allineato", "divergente per scelta", "divergente da chiudere"}


def _righe(testo: str, intestazione: str) -> list[list[str]]:
    """Le righe della tabella che comincia con ``intestazione``, cella per cella."""
    righe = testo.splitlines()
    inizio = next(i for i, r in enumerate(righe) if r.startswith(intestazione))
    corpo = []
    for riga in righe[inizio + 2 :]:
        if not riga.startswith("|"):
            break
        corpo.append([c.strip() for c in riga.strip().strip("|").split("|")])
    return corpo


@pytest.fixture(scope="module")
def testo() -> str:
    return DOCUMENTO.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tabella(testo: str) -> dict[str, list[str]]:
    righe = _righe(testo, "| Vocabolario | `hermes-core` |")
    return {riga[0].strip("`"): riga for riga in righe}


def test_il_documento_classifica_ogni_vocabolario(tabella):
    assert set(tabella) == set(VOCABOLARI)


@pytest.mark.parametrize("nome", sorted(VOCABOLARI))
def test_i_valori_del_server_sono_quelli_del_codice(tabella, nome: str):
    """Stessi valori, **nello stesso ordine**: per `RiskTier` e per
    `ConfirmationCadence` l'ordine è significativo."""
    scritti = re.findall(r"`([^`]+)`", tabella[nome][1])
    assert scritti == [membro.value for membro in VOCABOLARI[nome]]


def test_ogni_voce_ha_uno_dei_tre_stati(testo: str):
    """Tutte le tabelle del documento, non solo la prima."""
    viste = 0
    for intestazione in ("| Vocabolario |", "| Concetto |", "| Regola |"):
        for riga in _righe(testo, intestazione):
            assert riga[-1].strip("*") in STATI, riga
            viste += 1
    assert viste >= 20, "le tabelle non sono state lette: il formato è cambiato"


def test_ogni_enum_del_confine_e_fra_quelli_classificati():
    """Un enum aggiunto a questi moduli senza passare dal documento.

    `contracts` e `audit` sono i due moduli il cui vocabolario finisce nel
    log e nel catalogo, cioè ciò che il pannello leggerà.
    """
    classificati = set(VOCABOLARI.values())
    for modulo in (contracts, audit):
        for nome in dir(modulo):
            oggetto = getattr(modulo, nome)
            if (
                isinstance(oggetto, type)
                and issubclass(oggetto, Enum)
                and oggetto.__module__ == modulo.__name__
            ):
                assert oggetto in classificati, (
                    f"{modulo.__name__}.{nome} non è classificato in "
                    f"docs/vocabolari-condivisi.md"
                )


def test_la_traduzione_di_agentstatus_e_quella_scritta(testo: str):
    """Il documento dice che il pannello non ha bisogno di `AgentStatus`
    perché il log lo traduce. Se la traduzione cambia, quella frase mente."""
    righe = _righe(testo, "| `AgentStatus` | `CallOutcome` nel log |")
    scritta = {riga[0].strip("`"): riga[1].strip("`") for riga in righe}
    assert scritta == {s.value: esito_da_status(s).value for s in AgentStatus}


def test_la_regola_sui_caratteri_del_prefisso_e_quella_del_caricatore(tmp_path):
    """La divergenza «da chiudere» esiste davvero, nei due versi dichiarati.

    Il documento chiede un lavoro nel pannello su questa base: se il server
    smettesse di rifiutare questi prefissi, quel lavoro non servirebbe più e
    la voce andrebbe riclassificata.
    """
    from mcp_server.scope import ScopeAllowlist, ScopeError

    def carica(prefisso: str):
        percorso = tmp_path / "scope.toml"
        percorso.write_text(f'percorsi = ["{prefisso}"]\n', encoding="utf-8")
        return ScopeAllowlist.carica(percorso)

    for rifiutato in ("/srv/campioni lab", "/srv/a:b", "/srv/./lab"):
        with pytest.raises(ScopeError):
            carica(rifiutato)
    # E il verso innocuo: il server accetta ciò che il pannello rifiuta.
    assert carica("/srv/lab..vecchio").percorsi == ("/srv/lab..vecchio",)
