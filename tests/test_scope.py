"""Test del perimetro dei bersagli ammessi.

Il modulo decide se un'invocazione può toccare un indirizzo, quindi i test che
contano sono quelli sui **rifiuti**: un perimetro che ammette ciò che deve
ammettere ma non rifiuta ciò che deve rifiutare non è un perimetro.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from mcp_server.contracts import TargetKind
from mcp_server.scope import (
    MAX_TARGET,
    ScopeAllowlist,
    ScopeError,
    TargetRefused,
    valida_bersaglio,
)


def _scrivi(tmp_path: Path, contenuto: str) -> Path:
    percorso = tmp_path / "scope.toml"
    percorso.write_text(contenuto, encoding="utf-8")
    return percorso


def _perimetro(reti=("10.10.0.0/16",), alias=None) -> ScopeAllowlist:
    return ScopeAllowlist(
        tuple(ipaddress.ip_network(r) for r in reti),
        {
            nome: ipaddress.ip_address(ind)
            for nome, ind in (alias or {}).items()
        },
    )


# --------------------------------------------------------------------------- #
# Caricamento: un perimetro che non si capisce non è un perimetro
# --------------------------------------------------------------------------- #


def test_carica_reti_e_alias(tmp_path: Path):
    p = _scrivi(
        tmp_path,
        'reti = ["10.10.0.0/16", "192.168.205.0/24"]\n\n'
        '[alias]\nlab-web = "192.168.205.20"\ndc01 = "10.10.0.5"\n',
    )
    perimetro = ScopeAllowlist.carica(p)
    assert len(perimetro) == 4
    assert perimetro.alias == ("dc01", "lab-web")
    assert perimetro.percorso == p


def test_file_assente_solleva(tmp_path: Path):
    with pytest.raises(ScopeError, match="non trovato"):
        ScopeAllowlist.carica(tmp_path / "manca.toml")


def test_toml_rotto_solleva(tmp_path: Path):
    with pytest.raises(ScopeError, match="non parsabile"):
        ScopeAllowlist.carica(_scrivi(tmp_path, "reti = [\n"))


def test_non_leggibile_solleva(tmp_path: Path):
    """Una directory al posto del file: esiste e non si apre."""
    (tmp_path / "scope.toml").mkdir()
    with pytest.raises(ScopeError, match="non leggibile"):
        ScopeAllowlist.carica(tmp_path / "scope.toml")


def test_perimetro_vuoto_solleva(tmp_path: Path):
    """Vuoto non può significare «tutto», e «niente» sarebbe indiagnosticabile."""
    with pytest.raises(ScopeError, match="perimetro vuoto"):
        ScopeAllowlist.carica(_scrivi(tmp_path, "reti = []\n"))


def test_chiave_sconosciuta_solleva(tmp_path: Path):
    """Una chiave scritta male è un perimetro diverso da quello che si crede."""
    with pytest.raises(ScopeError, match="non riconosciute"):
        ScopeAllowlist.carica(
            _scrivi(tmp_path, 'rete = ["10.0.0.0/8"]\n')  # singolare
        )


def test_rete_non_canonica_solleva(tmp_path: Path):
    """`192.168.1.5/24` è quasi sempre un errore di chi scrive il file.

    Accettarlo silenziosamente darebbe un perimetro più largo di quello
    inteso, che è esattamente il difetto che questo file esiste per evitare.
    """
    with pytest.raises(ScopeError, match="rete non valida"):
        ScopeAllowlist.carica(_scrivi(tmp_path, 'reti = ["192.168.1.5/24"]\n'))


def test_alias_verso_un_nome_solleva(tmp_path: Path):
    """Un alias è la risoluzione, non un secondo livello da risolvere."""
    with pytest.raises(ScopeError, match="indirizzo IP"):
        ScopeAllowlist.carica(
            _scrivi(
                tmp_path,
                'reti = ["10.10.0.0/16"]\n\n[alias]\nweb = "web.lab.local"\n',
            )
        )


def test_alias_fuori_dalle_reti_solleva(tmp_path: Path):
    """Il file direbbe nello stesso momento che è ammesso e che non lo è."""
    with pytest.raises(ScopeError, match="non sta in nessuna"):
        ScopeAllowlist.carica(
            _scrivi(
                tmp_path,
                'reti = ["10.10.0.0/16"]\n\n[alias]\nfuori = "192.0.2.1"\n',
            )
        )


def test_alias_senza_reti_e_ammesso(tmp_path: Path):
    """Solo alias è un perimetro legittimo: la forma più stretta possibile."""
    perimetro = ScopeAllowlist.carica(
        _scrivi(tmp_path, '[alias]\ndc01 = "10.10.0.5"\n')
    )
    assert perimetro.risolvi("dc01") == "10.10.0.5"
    with pytest.raises(TargetRefused):
        perimetro.risolvi("10.10.0.6")


# --------------------------------------------------------------------------- #
# Risoluzione: cosa passa e cosa no
# --------------------------------------------------------------------------- #


def test_ip_dentro_la_rete_ammesso():
    assert _perimetro().risolvi("10.10.3.7") == "10.10.3.7"


def test_ip_fuori_rifiutato():
    with pytest.raises(TargetRefused, match="fuori dal perimetro"):
        _perimetro().risolvi("192.0.2.1")


def test_alias_sostituito_dal_suo_indirizzo():
    """Il log deve dire cosa è stato toccato, non come il modello l'ha chiamato."""
    perimetro = _perimetro(alias={"dc01": "10.10.0.5"})
    assert perimetro.risolvi("dc01") == "10.10.0.5"


def test_hostname_non_dichiarato_rifiutato():
    """Nessun DNS: un nome non dichiarato non è un bersaglio."""
    with pytest.raises(TargetRefused, match="non interroga il DNS"):
        _perimetro().risolvi("lab.local")


def test_il_messaggio_elenca_gli_alias_disponibili():
    """Un rifiuto deve dire come si fa, non solo che non si può."""
    perimetro = _perimetro(alias={"dc01": "10.10.0.5"})
    with pytest.raises(TargetRefused, match="dc01"):
        perimetro.risolvi("sconosciuto.local")


def test_bersaglio_che_inizia_per_meno_rifiutato():
    """Sarebbe letto come opzione dal tool: injection di argomenti.

    Il separatore `--` in argv la impedisce già; questo è il secondo dei due
    meccanismi, perché un controllo che dipende da un solo punto non è un
    controllo.
    """
    with pytest.raises(TargetRefused, match="inizia per"):
        _perimetro().risolvi("--script=http-vuln-cve2017-5638")


def test_bersaglio_con_spazi_rifiutato():
    """Un bersaglio è un solo indirizzo, non una riga di comando."""
    with pytest.raises(TargetRefused, match="spazi"):
        _perimetro().risolvi("10.10.0.5 10.10.0.6")


def test_spazi_ai_bordi_rifiutati_non_normalizzati():
    """Normalizzare significa eseguire qualcosa di diverso da ciò che è chiesto."""
    with pytest.raises(TargetRefused, match="spazi iniziali o finali"):
        _perimetro().risolvi(" 10.10.0.5")


def test_bersaglio_vuoto_rifiutato():
    with pytest.raises(TargetRefused, match="vuoto"):
        _perimetro().risolvi("")


def test_bersaglio_troppo_lungo_rifiutato():
    """Un'esecuzione che non entra nella riga di audit non si fa."""
    with pytest.raises(TargetRefused, match="riga di audit"):
        _perimetro().risolvi("1" * (MAX_TARGET + 1))


def test_byte_nullo_rifiutato():
    with pytest.raises(TargetRefused):
        _perimetro().risolvi("10.10.0.5\x00")


def test_ipv6_nella_sua_rete():
    perimetro = _perimetro(reti=("fd00::/8",))
    assert perimetro.risolvi("fd00::1") == "fd00::1"


def test_ipv4_non_entra_in_una_rete_ipv6():
    with pytest.raises(TargetRefused, match="fuori dal perimetro"):
        _perimetro(reti=("fd00::/8",)).risolvi("10.10.0.5")


# --------------------------------------------------------------------------- #
# Il validatore per kind: nessun kind senza validatore
# --------------------------------------------------------------------------- #


def test_kind_none_rifiuta_un_bersaglio():
    """Accettato e ignorato è il modo in cui un modello si illude di aver limitato."""
    with pytest.raises(TargetRefused, match="non accetta un bersaglio"):
        valida_bersaglio(TargetKind.NONE, "10.10.0.5", _perimetro())


def test_kind_none_senza_bersaglio_passa():
    assert valida_bersaglio(TargetKind.NONE, None, None) is None


def test_kind_host_senza_bersaglio_rifiutato():
    with pytest.raises(TargetRefused, match="richiede un bersaglio"):
        valida_bersaglio(TargetKind.HOST, None, _perimetro())


def test_kind_host_senza_perimetro_rifiutato():
    """L'assenza di perimetro non vale come «tutto ammesso».

    È il punto in cui questo modulo si discosta dall'invariante del 6b: là
    l'assenza di `state_dir` degradava a un comportamento dichiarato, qui il
    degrado sarebbe la rinuncia al controllo.
    """
    with pytest.raises(TargetRefused, match="nessun perimetro configurato"):
        valida_bersaglio(TargetKind.HOST, "10.10.0.5", None)


def test_ogni_kind_ha_un_validatore():
    """Il test che protegge la regola quando l'enum crescerà.

    Un valore nuovo senza il suo ramo in `valida_bersaglio` diventerebbe un
    passaggio libero verso la riga di comando di un tool. Qui fallisce subito,
    e il messaggio dice cosa manca.
    """
    perimetro = _perimetro(alias={"dc01": "10.10.0.5"})
    for kind in TargetKind:
        try:
            valida_bersaglio(kind, "dc01", perimetro)
        except TargetRefused as err:
            assert "non ha un validatore" not in str(err), (
                f"{kind} non ha un ramo in valida_bersaglio"
            )
