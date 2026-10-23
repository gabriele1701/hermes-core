"""Test dell'accesso alle credenziali (M0 passo 5).

La proprietà che conta è una sola e va provata, non assunta: **il valore di
un segreto non raggiunge mai il log**, per nessuna delle vie per cui un
valore di solito sfugge — f-string, ``repr``, traceback, formattazione.
"""

from __future__ import annotations

import uuid

import pytest

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome
from mcp_server.vault import (
    InvalidSecretName,
    Secret,
    SecretNotFound,
    StubBackend,
    Vault,
    VaultBackend,
    valida_nome_segreto,
)

#: Valore riconoscibile: se compare da qualche parte, è sfuggito da qui.
CANARINO = "CANARINO-valore-segreto-9f3a21"


@pytest.fixture()
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture()
def backend() -> StubBackend:
    stub = StubBackend()
    stub.semina("ssh/lab-kali", CANARINO)
    return stub


@pytest.fixture()
def vault(backend: StubBackend, audit: AuditLog) -> Vault:
    return Vault(backend, audit)


def _testo_log(audit: AuditLog) -> str:
    return audit.path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Il valore non esce
# --------------------------------------------------------------------------- #


def test_valore_non_finisce_nel_log(vault: Vault, audit: AuditLog):
    """La proprietà centrale del passo."""
    segreto = vault.get_secret("ssh/lab-kali")
    assert segreto.reveal() == CANARINO
    assert CANARINO not in _testo_log(audit)


def test_log_registra_il_nome(vault: Vault, audit: AuditLog):
    vault.get_secret("ssh/lab-kali")
    riga = audit.read_all()[0]
    assert riga.action is LogAction.SECRET_ACCESS
    assert riga.outcome is CallOutcome.OK
    assert riga.secret_name == "ssh/lab-kali"


def test_str_oscura():
    assert str(Secret("ssh/lab-kali", CANARINO)) == Secret.MASCHERA


def test_repr_oscura():
    r = repr(Secret("ssh/lab-kali", CANARINO))
    assert CANARINO not in r
    assert "ssh/lab-kali" in r


def test_fstring_oscura():
    s = Secret("ssh/lab-kali", CANARINO)
    assert CANARINO not in f"{s}"


def test_fstring_con_specificatore_oscura():
    """Senza __format__, uno specificatore aggirerebbe __str__."""
    s = Secret("ssh/lab-kali", CANARINO)
    assert CANARINO not in f"{s:>40}"
    assert CANARINO not in f"{s!s}"
    assert CANARINO not in f"{s!r}"


def test_interpolazione_percentuale_oscura():
    s = Secret("ssh/lab-kali", CANARINO)
    assert CANARINO not in "%s" % (s,)
    assert CANARINO not in "{}".format(s)


def test_valore_non_compare_in_un_traceback(vault: Vault):
    """Un segreto dentro un'eccezione non deve stamparne il valore."""
    import traceback

    s = vault.get_secret("ssh/lab-kali")
    try:
        raise RuntimeError(f"fallito con {s!r}")
    except RuntimeError:
        testo = traceback.format_exc()
    assert CANARINO not in testo


def test_reveal_e_lunica_via(vault: Vault):
    s = vault.get_secret("ssh/lab-kali")
    assert s.reveal() == CANARINO
    # Nessun attributo pubblico espone il valore.
    pubblici = [a for a in dir(s) if not a.startswith("_")]
    assert pubblici == ["MASCHERA", "name", "reveal"]


def test_slots_impedisce_attributi_accidentali():
    s = Secret("ssh/lab-kali", CANARINO)
    with pytest.raises(AttributeError):
        s.valore_in_chiaro = CANARINO  # type: ignore[attr-defined]


def test_len_senza_rivelare():
    assert len(Secret("ssh/lab-kali", CANARINO)) == len(CANARINO)


def test_confronto_solo_fra_segreti():
    a = Secret("ssh/lab-kali", CANARINO)
    b = Secret("altro", CANARINO)
    assert a == b
    assert a != Secret("ssh/lab-kali", "diverso")
    # Con una stringa nuda il confronto non riesce: va passato da reveal().
    assert (a == CANARINO) is False


def test_hash_non_usa_il_valore():
    assert hash(Secret("x.y", "uno")) == hash(Secret("x.y", "due"))


# --------------------------------------------------------------------------- #
# Validazione dei nomi
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "buono",
    ["ssh/lab-kali", "ssh/lab_kali", "api.token", "a1", "ssh/vm/kali-01"],
)
def test_nomi_validi(buono: str):
    assert valida_nome_segreto(buono) == buono


@pytest.mark.parametrize(
    "cattivo",
    [
        "",
        "/etc/shadow",            # assoluto
        "../../etc/shadow",       # traversal
        "ssh/../../../etc/passwd",  # traversal annidato
        "ssh\\lab-kali",          # separatore Windows
        "SSH/Lab-Kali",           # uppercase
        "ssh/lab kali",           # spazio
        "ssh//lab",               # segmento vuoto
        "ssh/./lab",              # segmento '.'
        "x" * 200,                # troppo lungo
        "ssh/lab-kali\n",         # newline finale (HC-08)
        "ssh/lab-kali\r\n",       # CRLF
        "ssh/lab-kali\n\n",       # piu' newline
        "ssh/lab-kali\t",         # tab
        "ssh/lab-kali ",          # spazio finale
        "\nssh/lab-kali",         # newline iniziale
    ],
)
def test_nomi_rifiutati(cattivo: str):
    """Un backend reale mappa il nome su un percorso: va confinato prima."""
    with pytest.raises(InvalidSecretName):
        valida_nome_segreto(cattivo)


def test_newline_finale_rifiutato_non_normalizzato():
    """HC-08: in `re` di Python `$` combacia anche prima di un newline finale.

    `match` accettava `'ssh/lab-kali\\n'` **col newline intatto**. Oggi è
    innocuo perché lo stub fa una ricerca per chiave, ma col backend `pass`
    quel nome diventa argomento di un processo e nome di un file — e un
    newline in un argomento è il genere di cosa che cambia il significato di
    un comando.

    Si rifiuta invece di normalizzare: un nome di credenziale che arriva
    diverso da come è scritto in configurazione è un errore da segnalare, non
    da indovinare.
    """
    with pytest.raises(InvalidSecretName):
        valida_nome_segreto("ssh/lab-kali\n")


def test_accesso_con_newline_negato_e_loggato(vault: Vault, audit: AuditLog):
    with pytest.raises(InvalidSecretName):
        vault.get_secret("ssh/lab-kali\n")
    riga = audit.read_all()[0]
    assert riga.outcome is CallOutcome.DENIED


def test_nome_non_conforme_negato_e_loggato(vault: Vault, audit: AuditLog):
    with pytest.raises(InvalidSecretName):
        vault.get_secret("../../etc/shadow")
    riga = audit.read_all()[0]
    assert riga.action is LogAction.SECRET_ACCESS
    assert riga.outcome is CallOutcome.DENIED
    assert "non conforme" in riga.detail


def test_nome_non_conforme_non_raggiunge_il_backend(audit: AuditLog):
    """La validazione precede il backend, non lo segue."""

    class BackendSpia:
        nome_backend = "spia"

        def __init__(self) -> None:
            self.chiamate: list[str] = []

        def fetch(self, name: str) -> str | None:
            self.chiamate.append(name)
            return None

    spia = BackendSpia()
    with pytest.raises(InvalidSecretName):
        Vault(spia, audit).get_secret("../../etc/shadow")
    assert spia.chiamate == []


def test_nome_non_stringa_non_rompe_il_log(vault: Vault, audit: AuditLog):
    with pytest.raises(InvalidSecretName):
        vault.get_secret({"iniezione": True})  # type: ignore[arg-type]
    assert audit.read_all()[0].secret_name is None


def test_nome_lungo_troncato_nel_log(audit: AuditLog, backend: StubBackend):
    with pytest.raises(InvalidSecretName):
        Vault(backend, audit).get_secret("a" * 500)
    nome = audit.read_all()[0].secret_name
    assert nome is not None and len(nome) <= 128


# --------------------------------------------------------------------------- #
# Segreto assente
# --------------------------------------------------------------------------- #


def test_segreto_assente_solleva_e_logga(vault: Vault, audit: AuditLog):
    """In audit conta anche chi prova a ottenere una credenziale inesistente."""
    with pytest.raises(SecretNotFound):
        vault.get_secret("ssh/non-esiste")
    riga = audit.read_all()[0]
    assert riga.outcome is CallOutcome.ERROR
    assert riga.secret_name == "ssh/non-esiste"


def test_ogni_accesso_lascia_una_riga(vault: Vault, audit: AuditLog):
    vault.get_secret("ssh/lab-kali")
    vault.get_secret("ssh/lab-kali")
    with pytest.raises(SecretNotFound):
        vault.get_secret("ssh/assente")
    righe = audit.read_all()
    assert len(righe) == 3
    assert all(r.action is LogAction.SECRET_ACCESS for r in righe)


def test_correlation_id_passato_usato(vault: Vault, audit: AuditLog):
    cid = uuid.uuid4()
    vault.get_secret("ssh/lab-kali", correlation_id=cid)
    assert audit.read_all()[0].correlation_id == cid


def test_correlation_id_di_default(vault: Vault, audit: AuditLog):
    vault.get_secret("ssh/lab-kali")
    assert audit.read_all()[0].correlation_id == vault.correlation_id


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #


def test_stub_e_dichiaratamente_finto(vault: Vault):
    assert vault.e_stub is True
    assert vault.nome_backend == "stub"


def test_stub_non_inventa_valori(audit: AuditLog):
    """Non legge nulla dal sistema: ciò che non è stato seminato non esiste."""
    with pytest.raises(SecretNotFound):
        Vault(StubBackend(), audit).get_secret("ssh/lab-kali")


def test_valore_stub_riconoscibile():
    """Un valore finto sfuggito dev'essere riconoscibile a colpo d'occhio."""
    stub = StubBackend()
    valore = stub.semina("ssh/lab-kali")
    assert valore.startswith(StubBackend.PREFISSO_FINTO)


def test_backend_sostituibile_senza_toccare_i_chiamanti(audit: AuditLog):
    """Il backend reale si collega implementando un solo metodo."""

    class BackendFinto:
        nome_backend = "finto-pass"

        def fetch(self, name: str) -> str | None:
            return CANARINO if name == "ssh/lab-kali" else None

    vault = Vault(BackendFinto(), audit)
    assert isinstance(BackendFinto(), VaultBackend)
    assert vault.e_stub is False
    assert vault.nome_backend == "finto-pass"
    assert vault.get_secret("ssh/lab-kali").reveal() == CANARINO
    assert CANARINO not in _testo_log(audit)


def test_backend_registrato_nel_log(audit: AuditLog, backend: StubBackend):
    Vault(backend, audit).get_secret("ssh/lab-kali")
    assert "stub" in audit.read_all()[0].detail
