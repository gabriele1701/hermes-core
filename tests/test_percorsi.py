"""Test dei bersagli di tipo percorso.

Un file solo per tutta l'estensione — contratto, caricatore, gate, wrapper,
preflight — perché il vincolo sotto cui è stata scritta è l'additività: i
test che c'erano non sono stati toccati, e quelli nuovi stanno qui, dove si
vede a colpo d'occhio cosa è stato aggiunto.

Come per le reti, i test che contano sono quelli sui **rifiuti**. E una
cosa questi test non possono dirla: che il kernel confini davvero. Qui il
wrapper parla con un `systemd-run` finto, quindi si verifica *cosa chiede*,
non *cosa ottiene*. Quello lo misura `bin/hermes-collauda-percorsi`, sulla
macchina vera, e nessun verde di questo file lo sostituisce.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path

import pytest

from mcp_server.audit import LogAction
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier, TargetKind
from mcp_server.doctor import ESITO_SONDA_NON_LEGGIBILE, Esito, esegui
from mcp_server.executor import (
    OPZIONE_PERCORSI,
    ConfirmationRequired,
    TargetOutOfScope,
    ToolRunnerUnusable,
)
from mcp_server.scope import (
    MAX_TARGET,
    ScopeAllowlist,
    ScopeError,
    TargetRefused,
    valida_bersaglio,
)

# Le fixture e gli aiuti dei moduli vicini, riusati e non ricopiati: una
# seconda copia di `_spec` o di `scrivi_config` sarebbe la terza mappa
# status → esito.
from tests.test_doctor import (  # noqa: F401 - fixture usate per nome
    WRAPPER_FINTO as WRAPPER_FINTO_DOCTOR,
    _controllo,
    dipendenze_conformi,
    radice,
    scrivi_config,
)
from tests.test_executor import (  # noqa: F401 - fixture usate per nome
    WRAPPER_FINTO,
    RunnerFinto,
    _executor,
    _negati,
    _spec,
    audit,
    registry,
    repo,
)

RADICE = Path(__file__).resolve().parent.parent
WRAPPER = RADICE / "bin" / "hermes-tool-run"


def _scrivi(tmp_path: Path, contenuto: str) -> Path:
    percorso = tmp_path / "scope.toml"
    percorso.write_text(contenuto, encoding="utf-8")
    return percorso


@pytest.fixture()
def lab(tmp_path: Path) -> Path:
    """Un perimetro vero sul disco: un prefisso, un file dentro, uno fuori.

    Risolto, perché un prefisso deve essere il percorso reale: su una
    macchina dove la directory temporanea passa da un symlink il test
    fallirebbe per l'ambiente e non per il codice.
    """
    base = tmp_path.resolve()
    (base / "lab" / "campioni").mkdir(parents=True)
    (base / "lab" / "campioni" / "a.bin").write_bytes(b"dentro")
    (base / "fuori").mkdir()
    (base / "fuori" / "segreto.txt").write_text("fuori", encoding="utf-8")
    return base


def _perimetro(lab: Path, *prefissi: str) -> ScopeAllowlist:
    return ScopeAllowlist((), {}, percorsi=prefissi or (str(lab / "lab"),))


# --------------------------------------------------------------------------- #
# Contratto
# --------------------------------------------------------------------------- #


def test_un_tool_con_bersaglio_di_tipo_percorso_e_registrabile(repo, registry):
    spec = _spec(repo, target_kind=TargetKind.PATH)
    registry.register(spec)
    assert registry.tools["echo.ping"].target_kind is TargetKind.PATH


def test_il_valore_sul_filo_e_path():
    """È il valore che il pannello ha già nel proprio enum: deve coincidere."""
    assert TargetKind("path") is TargetKind.PATH


def test_process_non_esiste_ed_e_voluto():
    """Per un processo il confine è l'isolamento, non una lista.

    Se un giorno qualcuno lo aggiungesse all'enum senza validatore, la regola
    «nessun kind senza validatore» cadrebbe in silenzio. Questo test lo rende
    una decisione da prendere, non una riga da aggiungere.
    """
    assert {k.value for k in TargetKind} == {"none", "host", "path"}


# --------------------------------------------------------------------------- #
# Caricatore: percorsi è opzionale, e ogni regola ha il suo motivo
# --------------------------------------------------------------------------- #


def test_un_perimetro_senza_percorsi_carica_come_prima(tmp_path: Path):
    p = _scrivi(tmp_path, 'reti = ["10.10.0.0/16"]\n\n[alias]\ndc = "10.10.0.5"\n')
    perimetro = ScopeAllowlist.carica(p)
    assert perimetro.percorsi == ()
    assert len(perimetro) == 2
    assert perimetro.risolvi("dc") == "10.10.0.5"


def test_carica_i_percorsi_accanto_a_reti_e_alias(tmp_path: Path):
    p = _scrivi(
        tmp_path,
        'reti = ["10.10.0.0/16"]\npercorsi = ["/srv/lab", "/opt/campioni_2"]\n\n'
        '[alias]\ndc = "10.10.0.5"\n',
    )
    perimetro = ScopeAllowlist.carica(p)
    assert perimetro.percorsi == ("/srv/lab", "/opt/campioni_2")
    assert [str(r) for r in perimetro.reti] == ["10.10.0.0/16"]


def test_un_perimetro_di_soli_percorsi_non_e_vuoto(tmp_path: Path):
    perimetro = ScopeAllowlist.carica(_scrivi(tmp_path, 'percorsi = ["/srv/lab"]\n'))
    assert perimetro.percorsi == ("/srv/lab",)


def test_percorsi_vuoto_e_nient_altro_resta_un_perimetro_vuoto(tmp_path: Path):
    with pytest.raises(ScopeError, match="perimetro vuoto"):
        ScopeAllowlist.carica(_scrivi(tmp_path, "percorsi = []\n"))


@pytest.mark.parametrize(
    ("voce", "motivo"),
    [
        ("srv/lab", "assoluto"),
        ("DA_COMPILARE", "assoluto"),
        ("./lab", "assoluto"),
        ("/", "radice"),
        ("/srv/lab/", "barra finale"),
        ("/srv/../etc", r"'\.\.'"),
        ("/srv/lab/..", r"'\.\.'"),
        ("/srv//lab", "forma canonica"),
        ("/srv/./lab", "forma canonica"),
        ("/srv/lab uno", "direttiva di montaggio"),
        ("/srv/lab:/etc", "direttiva di montaggio"),
        ("/srv/lab*", "direttiva di montaggio"),
        ("/srv/" + "a" * MAX_TARGET, "più lungo"),
    ],
)
def test_un_prefisso_malformato_e_rifiutato_col_motivo(
    tmp_path: Path, voce: str, motivo: str
):
    p = _scrivi(tmp_path, f'reti = ["10.0.0.0/8"]\npercorsi = ["{voce}"]\n')
    with pytest.raises(ScopeError, match=motivo):
        ScopeAllowlist.carica(p)


def test_un_prefisso_ripetuto_e_rifiutato(tmp_path: Path):
    p = _scrivi(tmp_path, 'percorsi = ["/srv/lab", "/srv/altro", "/srv/lab"]\n')
    with pytest.raises(ScopeError, match="unici"):
        ScopeAllowlist.carica(p)


@pytest.mark.parametrize("valore", ['"/srv/lab"', "[1, 2]", '{ a = "/srv" }'])
def test_percorsi_deve_essere_una_lista_di_stringhe(tmp_path: Path, valore: str):
    with pytest.raises(ScopeError, match="lista di stringhe"):
        ScopeAllowlist.carica(_scrivi(tmp_path, f"percorsi = {valore}\n"))


def test_percorsi_scritta_dopo_alias_lo_dice(tmp_path: Path):
    """L'errore più facile da fare, con il messaggio che lo nomina.

    In TOML una chiave dopo `[alias]` appartiene a quella tabella. Senza il
    suggerimento il caricatore parlerebbe di alias a chi sta scrivendo
    percorsi — una causa plausibile e falsa.
    """
    p = _scrivi(
        tmp_path, 'reti = ["10.0.0.0/8"]\n\n[alias]\npercorsi = ["/srv/lab"]\n'
    )
    with pytest.raises(ScopeError, match="PRIMA dell'intestazione"):
        ScopeAllowlist.carica(p)


def test_il_modello_versionato_non_contiene_un_percorso_vero():
    """La lezione di D-12, sui percorsi: il segnaposto deve sembrarlo.

    Si toglie il commento al blocco `percorsi` del modello, come farebbe chi
    lo attiva senza compilarlo, e si pretende due cose: che dentro ci sia
    solo il segnaposto, e che il caricatore lo rifiuti.
    """
    testo = (RADICE / "config" / "scope.example.toml").read_text(encoding="utf-8")
    blocco = re.search(r"^# percorsi = \[\n(?:# .*\n)*?# \]\n", testo, re.MULTILINE)
    assert blocco, "il modello non ha più il blocco 'percorsi' commentato"
    attivo = "".join(riga[2:] for riga in blocco.group(0).splitlines(keepends=True))
    assert tomllib.loads(attivo) == {"percorsi": ["DA_COMPILARE"]}

    # Nessun'altra riga del modello assegna 'percorsi'.
    assert len(re.findall(r"^\s*#?\s*percorsi\s*=", testo, re.MULTILINE)) == 1


def test_il_blocco_percorsi_del_modello_sta_prima_di_alias():
    testo = (RADICE / "config" / "scope.example.toml").read_text(encoding="utf-8")
    assert testo.index("# percorsi = [") < testo.index("\n[alias]")


def test_il_modello_attivato_senza_compilarlo_e_rifiutato(tmp_path: Path):
    testo = (RADICE / "config" / "scope.example.toml").read_text(encoding="utf-8")
    attivo = re.sub(
        r"^# (percorsi = \[)\n#( +\"DA_COMPILARE\",)\n# (\])$",
        r"\1\n\2\n\3",
        testo,
        flags=re.MULTILINE,
    ).replace('reti = [\n    "DA_COMPILARE",\n]', 'reti = ["10.0.0.0/8"]')
    assert attivo != testo
    with pytest.raises(ScopeError, match="assoluto"):
        ScopeAllowlist.carica(_scrivi(tmp_path, attivo))


# --------------------------------------------------------------------------- #
# Validatore: risolve, confronta il risolto, restituisce il risolto
# --------------------------------------------------------------------------- #


def test_un_percorso_dentro_il_perimetro_torna_risolto(lab: Path):
    bersaglio = str(lab / "lab" / "campioni" / "a.bin")
    assert _perimetro(lab).risolvi_percorso(bersaglio) == bersaglio


def test_il_prefisso_stesso_e_ammesso(lab: Path):
    assert _perimetro(lab).risolvi_percorso(str(lab / "lab")) == str(lab / "lab")


def test_un_percorso_fuori_perimetro_e_rifiutato(lab: Path):
    with pytest.raises(TargetRefused, match="fuori dal perimetro dei percorsi"):
        _perimetro(lab).risolvi_percorso(str(lab / "fuori" / "segreto.txt"))


def test_un_symlink_dentro_che_punta_fuori_e_rifiutato_e_dice_dove_porta(lab: Path):
    """Il caso per cui il perimetro dei percorsi esiste.

    Il percorso chiesto sta dentro il prefisso, carattere per carattere: un
    confronto sul testo lo ammetterebbe. Il rifiuto nomina entrambi i valori,
    perché «chiesto questo, portava lì» è ciò che l'audit deve conservare.
    """
    esce = lab / "lab" / "campioni" / "esce"
    esce.symlink_to(lab / "fuori" / "segreto.txt")
    with pytest.raises(TargetRefused) as err:
        _perimetro(lab).risolvi_percorso(str(esce))
    assert str(esce) in str(err.value)
    assert str(lab / "fuori" / "segreto.txt") in str(err.value)
    assert "risolve in" in str(err.value)


def test_una_directory_symlink_a_meta_percorso_non_fa_uscire(lab: Path):
    (lab / "lab" / "scorciatoia").symlink_to(lab / "fuori")
    with pytest.raises(TargetRefused, match="fuori dal perimetro"):
        _perimetro(lab).risolvi_percorso(str(lab / "lab" / "scorciatoia" / "segreto.txt"))


def test_un_symlink_che_resta_dentro_e_ammesso_e_torna_il_risolto(lab: Path):
    link = lab / "lab" / "ultimo"
    link.symlink_to(lab / "lab" / "campioni" / "a.bin")
    assert _perimetro(lab).risolvi_percorso(str(link)) == str(
        lab / "lab" / "campioni" / "a.bin"
    )


def test_i_due_punti_non_fanno_uscire(lab: Path):
    with pytest.raises(TargetRefused, match="fuori dal perimetro"):
        _perimetro(lab).risolvi_percorso(str(lab / "lab" / ".." / "fuori" / "segreto.txt"))


def test_un_prefisso_non_e_un_prefisso_di_testo(lab: Path):
    """`/x/lab` non ammette `/x/lab-altro`: il confine è il segmento."""
    (lab / "lab-altro").mkdir()
    (lab / "lab-altro" / "f").write_text("x", encoding="utf-8")
    with pytest.raises(TargetRefused, match="fuori dal perimetro"):
        _perimetro(lab).risolvi_percorso(str(lab / "lab-altro" / "f"))


@pytest.mark.parametrize(
    ("bersaglio", "motivo"),
    [
        ("", "vuoto"),
        ("lab/a.bin", "non è assoluto"),
        ("-rf", "non è assoluto"),
        (" /srv/lab", "spazi iniziali o finali"),
        ("/srv/lab\n/etc/shadow", "caratteri di controllo"),
        ("/srv/lab\x00", "caratteri di controllo"),
        ("/" + "a" * MAX_TARGET, "più lungo"),
    ],
)
def test_la_forma_del_bersaglio_e_rifiutata_prima_di_toccare_il_disco(
    lab: Path, bersaglio: str, motivo: str
):
    with pytest.raises(TargetRefused, match=motivo):
        _perimetro(lab).risolvi_percorso(bersaglio)


def test_un_percorso_che_non_esiste_e_rifiutato(lab: Path):
    """Non si confronta un percorso di cui non si sa dove porta."""
    with pytest.raises(TargetRefused, match="non è risolvibile"):
        _perimetro(lab).risolvi_percorso(str(lab / "lab" / "mai-esistito"))


def test_un_ciclo_di_symlink_e_rifiutato(lab: Path):
    (lab / "lab" / "a").symlink_to(lab / "lab" / "b")
    (lab / "lab" / "b").symlink_to(lab / "lab" / "a")
    with pytest.raises(TargetRefused, match="non è risolvibile"):
        _perimetro(lab).risolvi_percorso(str(lab / "lab" / "a"))


def test_un_bersaglio_con_spazi_nel_nome_e_ammesso(lab: Path):
    """Lo spazio è vietato nei PREFISSI, non nei bersagli: viaggiano in argv."""
    f = lab / "lab" / "campione uno.exe"
    f.write_bytes(b"x")
    assert _perimetro(lab).risolvi_percorso(str(f)) == str(f)


def test_un_prefisso_che_e_un_symlink_non_ammette_niente_e_lo_dice(lab: Path):
    """Un prefisso symlink ammetterebbe la propria destinazione.

    Il bersaglio sta davvero sotto la destinazione del link: se il prefisso
    venisse risolto invece che preteso reale, passerebbe.
    """
    (lab / "finto-lab").symlink_to(lab / "fuori")
    perimetro = _perimetro(lab, str(lab / "finto-lab"))
    with pytest.raises(TargetRefused) as err:
        perimetro.risolvi_percorso(str(lab / "finto-lab" / "segreto.txt"))
    assert "non utilizzabili su questa macchina" in str(err.value)
    assert f"risolve in {lab / 'fuori'}" in str(err.value)


def test_senza_prefissi_dichiarati_nessun_percorso_e_ammesso(lab: Path):
    import ipaddress

    solo_reti = ScopeAllowlist((ipaddress.ip_network("10.0.0.0/8"),), {})
    with pytest.raises(TargetRefused, match="non vale come «tutto ammesso»"):
        solo_reti.risolvi_percorso(str(lab / "lab" / "campioni" / "a.bin"))


def test_valida_bersaglio_ha_un_ramo_per_path(lab: Path):
    bersaglio = str(lab / "lab" / "campioni" / "a.bin")
    assert valida_bersaglio(TargetKind.PATH, bersaglio, _perimetro(lab)) == bersaglio
    with pytest.raises(TargetRefused, match="richiede un bersaglio"):
        valida_bersaglio(TargetKind.PATH, None, _perimetro(lab))
    with pytest.raises(TargetRefused, match="nessun perimetro configurato"):
        valida_bersaglio(TargetKind.PATH, bersaglio, None)


def test_un_percorso_non_passa_per_un_tool_di_tipo_host(lab: Path):
    """I due perimetri non si prestano i bersagli."""
    with pytest.raises(TargetRefused, match="non è un indirizzo IP"):
        valida_bersaglio(
            TargetKind.HOST, str(lab / "lab" / "campioni" / "a.bin"), _perimetro(lab)
        )


# --------------------------------------------------------------------------- #
# Gate
# --------------------------------------------------------------------------- #


def _gate(repo, registry, audit, lab, **kw):
    registry.register(_spec(repo, target_kind=TargetKind.PATH, **kw.pop("spec", {})))
    kw.setdefault("tool_runner", WRAPPER_FINTO)
    kw.setdefault("scope", _perimetro(lab))
    return _executor(registry, audit, repo, **kw)


def test_il_gate_esegue_dentro_il_perimetro_e_chiede_il_montaggio(
    repo, registry, audit, lab
):
    ex = _gate(repo, registry, audit, lab)
    bersaglio = str(lab / "lab" / "campioni" / "a.bin")
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target=bersaglio
    )
    assert call.outcome is CallOutcome.OK

    argv = ex._runner.chiamate[0]["argv"]
    # L'opzione sta fra il tempo limite e il '--' del wrapper: è una parola
    # per il wrapper, non un argomento del tool.
    primo_separatore = argv.index("--")
    assert argv[primo_separatore - 1] == OPZIONE_PERCORSI
    assert argv.count(OPZIONE_PERCORSI) == 1
    # Il tool riceve il percorso RISOLTO, dopo il proprio '--'.
    assert argv[-2:] == ["--", bersaglio]
    # E nessun prefisso viaggia in argv: li legge il wrapper dal file di root.
    assert str(lab / "lab") not in argv[:primo_separatore]


def test_nel_log_ci_sono_il_percorso_chiesto_e_quello_risolto(
    repo, registry, audit, lab
):
    """Il criterio di accettazione, alla lettera: entrambi, nella stessa riga."""
    link = lab / "lab" / "ultimo"
    reale = lab / "lab" / "campioni" / "a.bin"
    link.symlink_to(reale)
    ex = _gate(repo, registry, audit, lab)
    cid = uuid.uuid4()
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid, target=str(link)
    )

    assert call.target == str(link)
    assert ex._runner.chiamate[0]["argv"][-1] == str(reale)

    riga = [
        r
        for r in audit.read_all()
        if r.action is LogAction.TOOL_CALL and r.outcome is CallOutcome.OK
    ][-1]
    assert riga.correlation_id == cid
    assert riga.target == str(link)
    assert f"percorso risolto: {reale}" in riga.detail


def test_il_risolto_e_nel_log_anche_quando_coincide_col_chiesto(
    repo, registry, audit, lab
):
    """Una riga che lo omette non si distingue da una che non l'ha registrato."""
    bersaglio = str(lab / "lab" / "campioni" / "a.bin")
    ex = _gate(repo, registry, audit, lab)
    ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target=bersaglio
    )
    riga = [r for r in audit.read_all() if r.outcome is CallOutcome.OK][-1]
    assert riga.target == bersaglio
    assert f"percorso risolto: {bersaglio}" in riga.detail


def test_il_gate_nega_un_percorso_fuori_perimetro(repo, registry, audit, lab):
    """Il guasto, esercitato: il tool prova a uscire e lo si vede dire di no."""
    ex = _gate(repo, registry, audit, lab)
    fuori = str(lab / "fuori" / "segreto.txt")
    with pytest.raises(TargetOutOfScope, match="fuori dal perimetro dei percorsi"):
        ex.execute(
            "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target=fuori
        )
    assert ex._runner.chiamate == [], "un bersaglio rifiutato non deve partire"
    negata = _negati(audit)[-1]
    assert negata.target == fuori
    assert "fuori dal perimetro" in negata.detail


def test_il_gate_nega_il_symlink_che_esce_e_registra_dove_portava(
    repo, registry, audit, lab
):
    esce = lab / "lab" / "campioni" / "esce"
    esce.symlink_to(lab / "fuori" / "segreto.txt")
    ex = _gate(repo, registry, audit, lab)
    with pytest.raises(TargetOutOfScope):
        ex.execute(
            "echo.ping",
            OwnerAgent.ECHO_DUMMY,
            correlation_id=uuid.uuid4(),
            target=str(esce),
        )
    assert ex._runner.chiamate == []
    negata = _negati(audit)[-1]
    # Chiesto nel campo, risolto nel motivo: entrambi nella stessa riga.
    assert negata.target == str(esce)
    assert str(lab / "fuori" / "segreto.txt") in negata.detail


def test_senza_wrapper_un_tool_di_tipo_percorso_e_negato(repo, registry, audit, lab):
    """Il confinamento dei percorsi lo applica il wrapper: senza, si nega.

    Stessa regola del container. La sola risoluzione nel gate è un controllo
    prima dell'uso, e un symlink sostituito al momento giusto la supera.
    """
    ex = _gate(repo, registry, audit, lab, tool_runner=None)
    with pytest.raises(ToolRunnerUnusable, match="tool_runner non è configurato"):
        ex.execute(
            "echo.ping",
            OwnerAgent.ECHO_DUMMY,
            correlation_id=uuid.uuid4(),
            target=str(lab / "lab" / "campioni" / "a.bin"),
        )
    assert ex._runner.chiamate == []
    assert "montaggio ristretto" in _negati(audit)[-1].detail


def test_senza_wrapper_il_tentativo_fuori_perimetro_resta_visibile(
    repo, registry, audit, lab
):
    """L'ordine dei controlli: il perimetro viene prima dell'isolamento.

    Altrimenti su una macchina senza wrapper ogni tentativo di uscire si
    registrerebbe come «wrapper assente», e si perderebbe il segnale che
    conta: che qualcuno ha provato a toccare qualcosa fuori dal confine.
    """
    ex = _gate(repo, registry, audit, lab, tool_runner=None)
    with pytest.raises(TargetOutOfScope):
        ex.execute(
            "echo.ping",
            OwnerAgent.ECHO_DUMMY,
            correlation_id=uuid.uuid4(),
            target=str(lab / "fuori" / "segreto.txt"),
        )
    assert "fuori dal perimetro" in _negati(audit)[-1].detail


def test_una_conferma_in_sospeso_registra_il_percorso_risolto(
    repo, registry, audit, lab
):
    link = lab / "lab" / "ultimo"
    reale = lab / "lab" / "campioni" / "a.bin"
    link.symlink_to(reale)
    ex = _gate(repo, registry, audit, lab, spec={"default_tier": RiskTier.ROSSO})
    with pytest.raises(ConfirmationRequired):
        ex.execute(
            "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target=str(link)
        )
    sospesa = [r for r in audit.read_all() if r.outcome is CallOutcome.PENDING][-1]
    assert sospesa.target == str(link)
    assert f"percorso risolto: {reale}" in sospesa.detail


def test_un_tool_di_tipo_host_non_chiede_il_montaggio(repo, registry, audit, lab):
    """Il perimetro dei percorsi non tocca i tool di rete.

    Stesso gate, stesso wrapper, perimetro che dichiara ANCHE dei percorsi:
    un tool di tipo host non chiede il montaggio, e riceve l'indirizzo.

    Questo test pretendeva anche `detail == "exit=0"`, quando il vincolo era
    che i bersagli di rete non cambiassero di una riga. Quel vincolo è caduto
    con la voce del debito che ne era la conseguenza: ora la riga porta
    l'indirizzo risolto, e lo verificano i test qui sotto.
    """
    import ipaddress

    registry.register(_spec(repo, target_kind=TargetKind.HOST))
    perimetro = ScopeAllowlist(
        (ipaddress.ip_network("10.10.0.0/16"),),
        {"lab-kali": ipaddress.ip_address("10.10.0.5")},
        percorsi=(str(lab / "lab"),),
    )
    ex = _executor(registry, audit, repo, scope=perimetro, tool_runner=WRAPPER_FINTO)
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target="lab-kali"
    )
    argv = ex._runner.chiamate[0]["argv"]
    assert OPZIONE_PERCORSI not in argv
    assert argv[-2:] == ["--", "10.10.0.5"]
    assert call.detail == "exit=0; indirizzo risolto: 10.10.0.5"


def test_un_tool_senza_bersaglio_non_chiede_il_montaggio(repo, registry, audit, lab):
    registry.register(_spec(repo))
    ex = _executor(registry, audit, repo, scope=_perimetro(lab), tool_runner=WRAPPER_FINTO)
    call, _ = ex.execute("echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4())
    assert OPZIONE_PERCORSI not in ex._runner.chiamate[0]["argv"]
    assert call.detail == "exit=0"


# --------------------------------------------------------------------------- #
# Wrapper: cosa chiede a systemd
#
# Il wrapper è uno script di root con i percorsi scritti dentro, quindi qui
# se ne prova una COPIA in cui cambiano solo le costanti di percorso:
# `systemd-run` diventa uno script che registra come è stato chiamato. Tutto
# il resto — l'analisi degli argomenti, la lettura del perimetro, le regole —
# è il codice vero.
# --------------------------------------------------------------------------- #

UNITA = "hermes-tool-00000000-0000-4000-8000-000000000001"

solo_da_root = pytest.mark.skipif(
    os.geteuid() != 0,
    reason=(
        "il wrapper pretende un perimetro di root, e non si finge: senza "
        "root si prova solo il rifiuto. Il resto lo copre il collaudo."
    ),
)


class WrapperDiProva:
    def __init__(self, tmp_path: Path) -> None:
        self.base = tmp_path.resolve()
        self.registro = self.base / "systemd-run.argv"
        self.scope = self.base / "scope.toml"
        self.radice_script = self.base / "radice-script"
        self.script = self.base / "agents"
        self.script.mkdir()
        self.lab = self.base / "lab"
        self.lab.mkdir()

        finto = self.base / "systemd-run"
        finto.write_text(
            "#!/bin/sh\n"
            f"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{self.registro}'\n",
            encoding="utf-8",
        )
        finto.chmod(0o755)

        testo = WRAPPER.read_text(encoding="utf-8")
        for nome, valore in (
            ("SYSTEMD_RUN", finto),
            ("SYSTEMCTL", "/bin/true"),
            ("SCOPE_FILE", self.scope),
            ("RADICE_SCRIPT_FILE", self.radice_script),
            ("PYTHON", sys.executable),
        ):
            testo, n = re.subn(
                rf"^{nome}=\S+$", f"{nome}={valore}", testo, flags=re.MULTILINE
            )
            assert n == 1, f"{nome}: {n} assegnazioni nel wrapper, non 1"
        self.percorso = self.base / "hermes-tool-run"
        self.percorso.write_text(testo, encoding="utf-8")
        self.percorso.chmod(0o755)

        self.scrivi_perimetro(f'percorsi = ["{self.lab}"]\n')
        self.radice_script.write_text(f"{self.script}\n", encoding="utf-8")

    def scrivi_perimetro(self, contenuto: str) -> None:
        self.scope.write_text(contenuto, encoding="utf-8")
        self.scope.chmod(0o644)

    def esegui(self, *argomenti: str) -> subprocess.CompletedProcess:
        self.registro.unlink(missing_ok=True)
        return subprocess.run(
            [str(self.percorso), UNITA, "30", *argomenti],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    @property
    def avviato(self) -> bool:
        return self.registro.exists()

    @property
    def argv(self) -> list[str]:
        return self.registro.read_text(encoding="utf-8").splitlines()

    def proprieta(self, nome: str) -> list[str]:
        argv = self.argv
        return [
            argv[i + 1].split("=", 1)[1]
            for i, a in enumerate(argv[:-1])
            if a == "-p" and argv[i + 1].startswith(f"{nome}=")
        ]


@pytest.fixture()
def wrapper(tmp_path: Path) -> WrapperDiProva:
    return WrapperDiProva(tmp_path)


def test_senza_opzione_il_wrapper_chiede_a_systemd_quello_di_prima(wrapper):
    """Additività sul wrapper: nessuna direttiva di montaggio, e il perimetro
    non viene nemmeno letto — qui è rotto di proposito, e non importa."""
    wrapper.scrivi_perimetro("questo non è TOML [[[")
    esito = wrapper.esegui("--", "/bin/echo", "ciao")
    assert esito.returncode == 0, esito.stderr
    argv = wrapper.argv
    assert not any("TemporaryFileSystem" in a or "BindReadOnlyPaths" in a for a in argv)
    assert not any("PrivateTmp" in a or "PrivateDevices" in a for a in argv)
    assert argv[-3:] == ["--", "/bin/echo", "ciao"]
    assert wrapper.proprieta("MemorySwapMax") == ["0"]


def test_un_perimetro_non_di_root_ferma_il_wrapper_prima_di_systemd(wrapper):
    """Il file decide cosa viene montato: se chi subisce il confine può
    scriverlo, non è un confine. Vale da root e da utente: da root il file è
    scrivibile da tutti, da utente non è di root."""
    wrapper.scope.chmod(0o666)
    esito = wrapper.esegui("--percorsi", "--", "/bin/echo", "ciao")
    assert esito.returncode == 64
    assert "deve essere di root e non scrivibile da altri" in esito.stderr
    assert not wrapper.avviato, "systemd-run non deve partire"


def test_l_opzione_dopo_il_separatore_e_un_argomento_del_tool(wrapper):
    """`--percorsi` vale solo nella posizione del wrapper: dopo il `--` è
    roba del tool, e non accende niente."""
    esito = wrapper.esegui("--", "/bin/echo", "--percorsi")
    assert esito.returncode == 0, esito.stderr
    assert not any("TemporaryFileSystem" in a for a in wrapper.argv)
    assert wrapper.argv[-3:] == ["--", "/bin/echo", "--percorsi"]


def test_l_opzione_senza_comando_non_avvia_niente(wrapper):
    esito = wrapper.esegui("--percorsi", "--")
    assert esito.returncode == 64
    assert not wrapper.avviato


@solo_da_root
def test_con_l_opzione_il_wrapper_monta_solo_base_script_e_prefissi(wrapper):
    esito = wrapper.esegui("--percorsi", "--", "/bin/echo", "ciao")
    assert esito.returncode == 0, esito.stderr

    assert wrapper.proprieta("TemporaryFileSystem") == ["/:ro"]
    assert wrapper.proprieta("PrivateTmp") == ["yes"]
    assert wrapper.proprieta("PrivateDevices") == ["yes"]

    (montaggi,) = wrapper.proprieta("BindReadOnlyPaths")
    voci = montaggi.split()
    assert str(wrapper.lab) in voci
    assert str(wrapper.script) in voci
    # Tutto il resto è il sistema di base, e niente che contenga dati.
    resto = set(voci) - {str(wrapper.lab), str(wrapper.script)}
    assert resto == {
        "/usr",
        "-/bin",
        "-/sbin",
        "-/lib",
        "-/lib64",
        "-/etc/ld.so.cache",
        "-/etc/alternatives",
    }
    # I limiti di risorsa e l'identità restano quelli di ogni tool.
    assert wrapper.proprieta("MemorySwapMax") == ["0"]
    assert "--uid=hermes-tool" in wrapper.argv
    assert wrapper.argv[-3:] == ["--", "/bin/echo", "ciao"]


@solo_da_root
def test_il_wrapper_monta_tutti_i_prefissi_dichiarati(wrapper):
    altro = wrapper.base / "campioni"
    altro.mkdir()
    wrapper.scrivi_perimetro(
        f'reti = ["10.0.0.0/8"]\npercorsi = ["{wrapper.lab}", "{altro}"]\n'
    )
    assert wrapper.esegui("--percorsi", "--", "/bin/true").returncode == 0
    voci = wrapper.proprieta("BindReadOnlyPaths")[0].split()
    assert str(wrapper.lab) in voci and str(altro) in voci


@solo_da_root
@pytest.mark.parametrize(
    ("perimetro", "motivo"),
    [
        ('reti = ["10.0.0.0/8"]\n', "non dichiara nessun prefisso"),
        ("percorsi = []\n", "non dichiara nessun prefisso"),
        ('percorsi = ["/srv/a b"]\n', "prefisso non valido"),
        ('percorsi = ["/srv/a:/etc"]\n', "prefisso non valido"),
        ('percorsi = ["/srv/../etc"]\n', "prefisso non valido"),
        ('percorsi = ["/"]\n', "prefisso non valido"),
        ('percorsi = ["relativo"]\n', "prefisso non valido"),
        ('percorsi = ["/non/esiste/da/nessuna-parte"]\n', "non esiste su questa macchina"),
        ("percorsi = [[[\n", "non parsabile"),
    ],
)
def test_un_perimetro_inapplicabile_ferma_il_wrapper_prima_di_systemd(
    wrapper, perimetro: str, motivo: str
):
    """Promesso e non applicabile nega: non si ricade sull'unità normale."""
    wrapper.scrivi_perimetro(perimetro)
    esito = wrapper.esegui("--percorsi", "--", "/bin/echo", "ciao")
    assert esito.returncode == 64
    assert motivo in esito.stderr
    assert "tool non avviato" in esito.stderr
    assert not wrapper.avviato, "systemd-run non deve partire"


@solo_da_root
def test_un_prefisso_symlink_ferma_il_wrapper(wrapper):
    """Montarlo vorrebbe dire montare la sua destinazione."""
    link = wrapper.base / "finto"
    link.symlink_to("/etc")
    wrapper.scrivi_perimetro(f'percorsi = ["{link}"]\n')
    esito = wrapper.esegui("--percorsi", "--", "/bin/true")
    assert esito.returncode == 64
    assert "risolve in /etc" in esito.stderr
    assert not wrapper.avviato


@solo_da_root
@pytest.mark.parametrize(
    "contenuto",
    ["", "relativo\n", "/srv/a b\n", "{script}\n/etc\n", "/non/esiste/qui\n"],
)
def test_una_directory_degli_script_non_valida_ferma_il_wrapper(wrapper, contenuto):
    wrapper.radice_script.write_text(
        contenuto.format(script=wrapper.script), encoding="utf-8"
    )
    esito = wrapper.esegui("--percorsi", "--", "/bin/true")
    assert esito.returncode == 64
    assert not wrapper.avviato


@solo_da_root
def test_senza_il_file_della_directory_degli_script_il_wrapper_si_ferma(wrapper):
    wrapper.radice_script.unlink()
    esito = wrapper.esegui("--percorsi", "--", "/bin/true")
    assert esito.returncode == 64
    assert "non leggibile" in esito.stderr
    assert not wrapper.avviato


# --------------------------------------------------------------------------- #
# Le copie della stessa costante, fra linguaggi
# --------------------------------------------------------------------------- #


def _assegnazione(testo: str, nome: str) -> str:
    trovate = re.findall(rf"^{nome}=(\S+)$", testo, flags=re.MULTILINE)
    assert len(trovate) == 1, f"{nome}: {len(trovate)} assegnazioni, non 1"
    return trovate[0]


def test_l_opzione_del_gate_e_quella_che_il_wrapper_riconosce():
    testo = WRAPPER.read_text(encoding="utf-8")
    assert f'if [ "$1" = "{OPZIONE_PERCORSI}" ]; then' in testo


def test_bootstrap_wrapper_e_collaudo_parlano_degli_stessi_file():
    wrapper = WRAPPER.read_text(encoding="utf-8")
    bootstrap = (RADICE / "bin" / "hermes-bootstrap").read_text(encoding="utf-8")
    collaudo = (RADICE / "bin" / "hermes-collauda-percorsi").read_text(encoding="utf-8")

    dir_config = _assegnazione(bootstrap, "DIR_CONFIG")

    def espandi(valore: str) -> str:
        return valore.replace("$DIR_CONFIG", dir_config)

    assert espandi(_assegnazione(bootstrap, "SCOPE")) == _assegnazione(
        wrapper, "SCOPE_FILE"
    )
    assert espandi(_assegnazione(bootstrap, "RADICE_SCRIPT")) == _assegnazione(
        wrapper, "RADICE_SCRIPT_FILE"
    )
    assert _assegnazione(collaudo, "WRAPPER") == _assegnazione(bootstrap, "WRAPPER")
    assert _assegnazione(collaudo, "PYTHON") == _assegnazione(wrapper, "PYTHON")


def test_il_collaudo_e_uno_script_valido_ed_eseguibile():
    collaudo = RADICE / "bin" / "hermes-collauda-percorsi"
    esito = subprocess.run(
        ["sh", "-n", str(collaudo)], capture_output=True, text=True, timeout=60
    )
    assert esito.returncode == 0, esito.stderr
    assert collaudo.stat().st_mode & 0o111, "manca il bit di esecuzione"


def test_il_collaudo_non_mette_il_file_esterno_in_una_directory_privata():
    """Il difetto trovato esercitando il guasto, reso non reintroducibile.

    Con il file «fuori» in /var/tmp la prova passava anche togliendo il
    montaggio dal wrapper: lo nascondeva `PrivateTmp`, non il perimetro.
    """
    collaudo = (RADICE / "bin" / "hermes-collauda-percorsi").read_text(encoding="utf-8")
    (riga,) = re.findall(r"^FUORI=\$\(mktemp (\S+)\)$", collaudo, re.MULTILINE)
    assert not riga.startswith(("/tmp/", "/var/tmp/"))


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #


def _scope_con_percorsi(tmp_path: Path, *prefissi: str, reti: bool = True) -> Path:
    righe = ['reti = ["10.10.0.0/16"]\n'] if reti else []
    if prefissi:
        elenco = ", ".join(f'"{p}"' for p in prefissi)
        righe.append(f"percorsi = [{elenco}]\n")
    percorso = tmp_path / "scope.toml"
    percorso.write_text("".join(righe), encoding="utf-8")
    return percorso


def _sonde_percorsi(
    monkeypatch,
    scope: Path,
    *,
    libera: int = 0,
    ristretta_perimetro: int = ESITO_SONDA_NON_LEGGIBILE,
    ristretta_script: int = 0,
    stderr: str = "",
    registro: list | None = None,
    wrapper_legge: str | None = "uguale",
) -> None:
    """Sonde finte che distinguono le TRE letture del montaggio.

    Un finto che rispondesse uguale a tutte renderebbe indistinguibili il
    controllo, il rifiuto e la lettura dello script: cioè proprio le tre cose
    che il preflight tiene separate.
    """
    import subprocess as sp

    from mcp_server import doctor as mod

    def finto(argv, **kw):
        if registro is not None:
            registro.append(list(argv))
        if "--stop" in argv or mod.SONDA_LETTURA not in argv:
            return sp.CompletedProcess(argv, 0, "", "")
        ristretto = OPZIONE_PERCORSI in argv[: argv.index("--")]
        sul_perimetro = argv[-1] == str(scope)
        if not ristretto:
            codice = libera if sul_perimetro else 0
        elif sul_perimetro:
            codice = ristretta_perimetro
        else:
            codice = ristretta_script
        return sp.CompletedProcess(argv, codice, "", stderr if codice else "")

    monkeypatch.setattr(mod.subprocess, "run", finto)
    if wrapper_legge is not None:
        valore = str(scope) if wrapper_legge == "uguale" else wrapper_legge
        monkeypatch.setattr(
            mod,
            "_costante_del_wrapper",
            lambda percorso, nome: valore if nome == "SCOPE_FILE" else "/etc/x",
        )


def _nomi(referto) -> list[str]:
    return [c.nome for c in referto.controlli]


def test_un_perimetro_senza_percorsi_ha_il_referto_di_prima(
    tmp_path: Path, radice: Path
):
    """Additività sul preflight: nessuna voce nuova se non c'è niente da dire."""
    scope = _scope_con_percorsi(tmp_path)
    referto = esegui(
        scrivi_config(tmp_path, radice, scope_file=scope, target_kind="host")
    )
    assert _controllo(referto, "perimetro dei bersagli").esito is Esito.OK
    assert not [n for n in _nomi(referto) if "percors" in n]


def test_il_preflight_mostra_il_perimetro_dei_percorsi(tmp_path: Path, radice: Path):
    lab = tmp_path.resolve() / "lab"
    lab.mkdir()
    scope = _scope_con_percorsi(tmp_path, str(lab))
    referto = esegui(scrivi_config(tmp_path, radice, scope_file=scope))
    controllo = _controllo(referto, "perimetro dei percorsi")
    assert controllo.esito is Esito.OK
    assert str(lab) in controllo.messaggio
    assert "due strati" in controllo.messaggio
    # La riga di reti e alias resta com'era.
    assert "reti: 10.10.0.0/16" in _controllo(referto, "perimetro dei bersagli").messaggio


def test_un_tool_di_tipo_percorso_senza_prefissi_e_errore(tmp_path: Path, radice: Path):
    scope = _scope_con_percorsi(tmp_path)
    referto = esegui(
        scrivi_config(
            tmp_path,
            radice,
            scope_file=scope,
            target_kind="path",
            tool_runner=WRAPPER_FINTO_DOCTOR,
        )
    )
    controllo = _controllo(referto, "perimetro dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "echo.ping" in controllo.messaggio
    assert "PRIMA dell'intestazione [alias]" in controllo.rimedio
    assert referto.pronto is False


def test_un_prefisso_che_non_esiste_e_avviso_senza_tool_ed_errore_con(
    tmp_path: Path, radice: Path
):
    scope = _scope_con_percorsi(tmp_path, str(tmp_path.resolve() / "mai-creato"))

    senza = esegui(scrivi_config(tmp_path, radice, scope_file=scope))
    assert _controllo(senza, "perimetro dei percorsi").esito is Esito.AVVISO

    con = esegui(
        scrivi_config(tmp_path, radice, scope_file=scope, target_kind="path")
    )
    controllo = _controllo(con, "perimetro dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "non esiste" in controllo.messaggio


def test_un_prefisso_symlink_e_segnalato_con_la_destinazione(
    tmp_path: Path, radice: Path
):
    base = tmp_path.resolve()
    (base / "vero").mkdir()
    (base / "finto").symlink_to(base / "vero")
    scope = _scope_con_percorsi(tmp_path, str(base / "finto"))
    controllo = _controllo(
        esegui(scrivi_config(tmp_path, radice, scope_file=scope)),
        "perimetro dei percorsi",
    )
    assert controllo.esito is Esito.AVVISO
    assert f"risolve in {base / 'vero'}" in controllo.messaggio


def test_un_tool_di_tipo_percorso_senza_wrapper_e_errore(tmp_path: Path, radice: Path):
    lab = tmp_path.resolve() / "lab"
    lab.mkdir()
    scope = _scope_con_percorsi(tmp_path, str(lab))
    referto = esegui(
        scrivi_config(tmp_path, radice, scope_file=scope, target_kind="path")
    )
    controllo = _controllo(referto, "tool con bersaglio di tipo percorso")
    assert controllo.esito is Esito.ERRORE
    assert "tool_runner" in controllo.messaggio
    assert referto.pronto is False


def _config_con_montaggio(tmp_path: Path, radice: Path) -> tuple[Path, Path]:
    lab = tmp_path.resolve() / "lab"
    lab.mkdir()
    scope = _scope_con_percorsi(tmp_path, str(lab))
    config = scrivi_config(
        tmp_path, radice, scope_file=scope, tool_runner=WRAPPER_FINTO_DOCTOR
    )
    return config, scope


def test_il_montaggio_e_verificato_leggendo(tmp_path: Path, radice: Path, monkeypatch):
    config, scope = _config_con_montaggio(tmp_path, radice)
    registro: list[list[str]] = []
    _sonde_percorsi(monkeypatch, scope, registro=registro)

    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.OK
    assert "un byte chiesto davvero" in controllo.messaggio

    # Il controllo PRIMA del rifiuto: la stessa lettura senza montaggio.
    sul_perimetro = [a for a in registro if a[-1] == str(scope)]
    assert len(sul_perimetro) == 2
    assert OPZIONE_PERCORSI not in sul_perimetro[0]
    assert OPZIONE_PERCORSI in sul_perimetro[1]


def test_un_montaggio_che_non_confina_e_errore(tmp_path: Path, radice: Path, monkeypatch):
    """Il guasto, esercitato: dall'unità ristretta il perimetro si apre."""
    config, scope = _config_con_montaggio(tmp_path, radice)
    _sonde_percorsi(monkeypatch, scope, ristretta_perimetro=0)
    referto = esegui(config)
    controllo = _controllo(referto, "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "SI APRE" in controllo.messaggio
    assert referto.pronto is False


def test_un_rifiuto_non_discriminante_non_diventa_un_verde(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Se il file non si apre nemmeno senza montaggio, il rifiuto non prova
    niente: si dice che non è verificabile, non che è verificato."""
    config, scope = _config_con_montaggio(tmp_path, radice)
    registro: list[list[str]] = []
    _sonde_percorsi(
        monkeypatch,
        scope,
        libera=ESITO_SONDA_NON_LEGGIBILE,
        stderr="PermissionError: [Errno 13] Permission denied",
        registro=registro,
    )
    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.AVVISO
    assert "non verificabile leggendo" in controllo.messaggio
    # E la prova ristretta non è stata nemmeno tentata.
    assert not [a for a in registro if OPZIONE_PERCORSI in a]


def test_un_unita_ristretta_che_non_parte_riporta_il_motivo_del_wrapper(
    tmp_path: Path, radice: Path, monkeypatch
):
    config, scope = _config_con_montaggio(tmp_path, radice)
    _sonde_percorsi(
        monkeypatch,
        scope,
        ristretta_perimetro=64,
        stderr="hermes-tool-run: montaggio ristretto non applicabile: tool non avviato",
    )
    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "non è partita (esito 64)" in controllo.messaggio
    assert "montaggio ristretto non applicabile" in controllo.messaggio


def test_il_confine_c_e_ma_lo_script_non_si_apre(tmp_path: Path, radice: Path, monkeypatch):
    config, scope = _config_con_montaggio(tmp_path, radice)
    _sonde_percorsi(
        monkeypatch,
        scope,
        ristretta_script=ESITO_SONDA_NON_LEGGIBILE,
        stderr="FileNotFoundError: [Errno 2] No such file or directory",
    )
    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "non partirebbe" in controllo.messaggio
    assert "hermes-bootstrap" in controllo.rimedio


def test_un_wrapper_installato_che_precede_il_montaggio_e_errore(
    tmp_path: Path, radice: Path, monkeypatch
):
    """Dopo un aggiornamento del repo il wrapper installato può essere quello
    vecchio: è lui che gira, ed è lui che il preflight legge."""
    config, scope = _config_con_montaggio(tmp_path, radice)
    _sonde_percorsi(monkeypatch, scope, wrapper_legge=None)
    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "versione precedente" in controllo.messaggio
    assert "hermes-bootstrap" in controllo.rimedio


def test_gate_e_wrapper_su_due_file_sono_due_perimetri(
    tmp_path: Path, radice: Path, monkeypatch
):
    config, scope = _config_con_montaggio(tmp_path, radice)
    _sonde_percorsi(monkeypatch, scope, wrapper_legge="/etc/hermes/scope.toml")
    controllo = _controllo(esegui(config), "montaggio ristretto dei percorsi")
    assert controllo.esito is Esito.ERRORE
    assert "due perimetri" in controllo.messaggio
    assert 'scope_file = "/etc/hermes/scope.toml"' in controllo.rimedio


def test_senza_percorsi_dichiarati_il_montaggio_non_si_prova(
    tmp_path: Path, radice: Path, monkeypatch
):
    scope = _scope_con_percorsi(tmp_path)
    registro: list[list[str]] = []
    _sonde_percorsi(monkeypatch, scope, registro=registro)
    referto = esegui(
        scrivi_config(
            tmp_path, radice, scope_file=scope, tool_runner=WRAPPER_FINTO_DOCTOR
        )
    )
    assert not [n for n in _nomi(referto) if n.startswith("montaggio")]
    assert not [a for a in registro if OPZIONE_PERCORSI in a]


def test_il_wrapper_del_repo_dichiara_il_perimetro_che_il_preflight_cerca():
    """`_costante_del_wrapper` legge il wrapper vero, non una sua descrizione."""
    from mcp_server.doctor import _costante_del_wrapper

    assert _costante_del_wrapper(WRAPPER, "SCOPE_FILE") == "/etc/hermes/scope.toml"
    assert (
        _costante_del_wrapper(WRAPPER, "RADICE_SCRIPT_FILE")
        == "/etc/hermes/radice-script"
    )
    assert _costante_del_wrapper(Path("/bin/true"), "SCOPE_FILE") is None


# --------------------------------------------------------------------------- #
# L'indirizzo risolto, per i bersagli di rete
#
# La documentazione diceva che per un alias «nel log restano entrambi». Non
# era vero: restava il nome. Trovato scrivendo il perimetro dei percorsi.
# --------------------------------------------------------------------------- #


def _gate_di_rete(repo, registry, audit, **spec):
    import ipaddress

    registry.register(_spec(repo, target_kind=TargetKind.HOST, **spec))
    perimetro = ScopeAllowlist(
        (ipaddress.ip_network("10.10.0.0/16"),),
        {"lab-kali": ipaddress.ip_address("10.10.0.5")},
    )
    return _executor(registry, audit, repo, scope=perimetro)


def test_per_un_alias_il_log_dice_anche_dove_e_andata_l_esecuzione(
    repo, registry, audit
):
    """Dal log, senza rileggere il perimetro com'era quel giorno."""
    ex = _gate_di_rete(repo, registry, audit)
    cid = uuid.uuid4()
    call, _ = ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=cid, target="lab-kali"
    )
    riga = [
        r
        for r in audit.read_all()
        if r.action is LogAction.TOOL_CALL and r.outcome is CallOutcome.OK
    ][-1]
    assert riga.correlation_id == cid
    assert riga.target == "lab-kali", "nel campo resta ciò che è stato CHIESTO"
    assert "indirizzo risolto: 10.10.0.5" in riga.detail
    assert call.detail == riga.detail


def test_per_un_indirizzo_il_risolto_c_e_anche_se_coincide(repo, registry, audit):
    ex = _gate_di_rete(repo, registry, audit)
    ex.execute(
        "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target="10.10.3.7"
    )
    riga = [r for r in audit.read_all() if r.outcome is CallOutcome.OK][-1]
    assert riga.target == "10.10.3.7"
    assert riga.detail == "exit=0; indirizzo risolto: 10.10.3.7"


def test_una_conferma_in_sospeso_su_un_alias_registra_l_indirizzo(
    repo, registry, audit
):
    """Una conferma si chiede su un bersaglio: chi la concede deve poter
    leggere quale, non solo come l'ha chiamato il modello."""
    ex = _gate_di_rete(repo, registry, audit, default_tier=RiskTier.ROSSO)
    with pytest.raises(ConfirmationRequired):
        ex.execute(
            "echo.ping", OwnerAgent.ECHO_DUMMY, correlation_id=uuid.uuid4(), target="lab-kali"
        )
    sospesa = [r for r in audit.read_all() if r.outcome is CallOutcome.PENDING][-1]
    assert sospesa.target == "lab-kali"
    assert "indirizzo risolto: 10.10.0.5" in sospesa.detail


def test_ogni_kind_con_un_bersaglio_ha_la_sua_etichetta_nel_log():
    """Un kind nuovo senza etichetta registrerebbe solo ciò che è stato chiesto."""
    from mcp_server.executor import nota_risolto

    for kind in TargetKind:
        if kind is TargetKind.NONE:
            assert nota_risolto(kind, "qualcosa") == ""
        else:
            assert nota_risolto(kind, "X").endswith(" risolto: X"), kind
        assert nota_risolto(kind, None) == ""
