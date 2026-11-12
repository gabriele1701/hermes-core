"""Test dei permessi effettivi e della regola che non annulla un'ACL.

Il difetto che questi test chiudono non veniva da una lettura del codice: è
emerso preparando la spedizione del log a un collector, quando si è trattato
di dare a un utente dedicato la lettura del log d'audit. L'ACL funzionava, e
smetteva di funzionare al primo avvio del server.

La causa: su un percorso con ACL i bit di gruppo di ``stat`` sono la
**maschera**, e lo scrittore — che imponeva il modo esatto — la riportava a
zero, azzerando i permessi effettivi di ogni voce nominata e lasciandola
elencata in ``getfacl``. Il preflight, dal canto suo, leggeva lo stesso
``0640`` come una fuga e suggeriva il ``chmod 600`` che rompe.

I test costruiscono l'ACL scrivendo direttamente ``system.posix_acl_access``
invece di invocare ``setfacl``: non serve il pacchetto ``acl`` installato, e
ciò che si misura è il comportamento del **kernel** (che aggiorna il modo
quando l'ACL cambia, e la maschera quando arriva una ``chmod``), non quello
di un binario di userspace.
"""

from __future__ import annotations

import errno
import os
import stat
import struct
from pathlib import Path

import pytest

from mcp_server.audit import AuditLog
from mcp_server.doctor import Esito, esegui
from mcp_server.permessi import LETTURA, accesso, leggi_acl, restringi

# Tag del formato, dal docstring di `permessi.py`.
_U_OBJ, _U, _G_OBJ, _G, _MASK, _OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_SENZA_ID = 0xFFFFFFFF

#: Un uid che quasi ovunque esiste e non è il nostro. Serve solo come
#: destinatario della concessione: i test sulla maschera non hanno bisogno
#: che quell'utente esista davvero.
UID_ALTRO = 65534


def _blob(voci: list[tuple[int, int, int]]) -> bytes:
    b = struct.pack("<I", 2)
    for tag, permessi, identificativo in voci:
        b += struct.pack("<HHI", tag, permessi, identificativo)
    return b


def concedi(
    percorso: Path,
    uid: int,
    permessi: int,
    *,
    altri: int = 0,
    proprietario: int = 0o6,
) -> None:
    """Concede a ``uid`` dei permessi, come farebbe ``setfacl -m u:uid:…``.

    Salta il test se il filesystem non regge le ACL: è una proprietà
    dell'ambiente, non del codice, e un rosso su quella base insegnerebbe a
    ignorare i rossi.
    """
    acl = _blob(
        [
            (_U_OBJ, proprietario, _SENZA_ID),
            (_U, permessi, uid),
            (_G_OBJ, 0o0, _SENZA_ID),
            (_MASK, permessi, _SENZA_ID),
            (_OTHER, altri, _SENZA_ID),
        ]
    )
    try:
        os.setxattr(percorso, "system.posix_acl_access", acl)
    except OSError as err:
        if err.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM):
            pytest.skip(f"ACL POSIX non supportate qui: {err.strerror}")
        raise


def maschera(percorso: Path) -> int:
    voci = leggi_acl(percorso)
    assert voci is not None, "ci si aspettava un'ACL estesa"
    for tag, permessi, _ in voci:
        if tag == _MASK:
            return permessi
    raise AssertionError("ACL estesa senza maschera")


@pytest.fixture()
def log(tmp_path: Path) -> Path:
    percorso = tmp_path / "audit.jsonl"
    percorso.write_text('{"ts": "x"}\n', encoding="utf-8")
    percorso.chmod(0o600)
    return percorso


# --------------------------------------------------------------------------- #
# Lettura del formato
# --------------------------------------------------------------------------- #


def test_senza_acl_non_ce_lo_xattr(log: Path):
    """Il discriminatore è l'assenza dell'attributo, non i bit del modo."""
    assert leggi_acl(log) is None
    acc = accesso(log)
    assert acc.estesa is False
    assert acc.modo == 0o600
    assert acc.gruppo_proprietario == 0
    assert acc.altri == 0
    assert acc.nominati == ()
    assert acc.leggibile_oltre_il_proprietario is False


def test_la_maschera_filtra_i_permessi_dei_nominati(log: Path):
    """I permessi riportati sono quelli *effettivi*, non quelli scritti.

    Una voce ``rw-`` sotto una maschera ``r--`` vale ``r--``: riportare il
    valore non filtrato significherebbe dire che un utente scrive su un file
    su cui non può scrivere.
    """
    acl = _blob(
        [
            (_U_OBJ, 0o6, _SENZA_ID),
            (_U, 0o6, UID_ALTRO),  # rw- richiesto
            (_G_OBJ, 0o0, _SENZA_ID),
            (_MASK, 0o4, _SENZA_ID),  # ma la maschera concede solo r--
            (_OTHER, 0o0, _SENZA_ID),
        ]
    )
    try:
        os.setxattr(log, "system.posix_acl_access", acl)
    except OSError as err:  # pragma: no cover - dipende dal filesystem
        pytest.skip(f"ACL POSIX non supportate qui: {err.strerror}")

    acc = accesso(log)
    assert acc.estesa is True
    (nominato,) = acc.nominati
    assert nominato.permessi == 0o4
    assert acc.lettori_nominati == (nominato,)


def test_un_blob_troncato_non_viene_interpretato(log: Path, monkeypatch):
    """Meglio «non lo so» che un elenco plausibile e sbagliato.

    È la forma che il metodo del progetto insegue: un'interrogazione che non
    sa rispondere non deve fabbricare una risposta credibile.
    """
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: b"\x02\x00\x00\x00\x01\x00")
    assert leggi_acl(log) is None
    assert accesso(log).estesa is False


def test_una_versione_ignota_non_viene_interpretata(log: Path, monkeypatch):
    blob = struct.pack("<I", 99) + struct.pack("<HHI", _U_OBJ, 0o6, _SENZA_ID)
    monkeypatch.setattr(os, "getxattr", lambda *a, **k: blob)
    assert leggi_acl(log) is None


# --------------------------------------------------------------------------- #
# La regola: una concessione deliberata non si annulla
# --------------------------------------------------------------------------- #


def test_restringi_impone_il_modo_quando_non_ci_sono_acl(log: Path):
    """Senza ACL i bit sono permessi veri e vanno stretti: comportamento di sempre."""
    log.chmod(0o644)
    restringi(log, 0o600)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_restringi_non_annulla_una_concessione_deliberata(log: Path):
    """Il difetto, esercitato.

    Prima della correzione questo test falliva: ``restringi`` vedeva
    ``0640 != 0600``, faceva ``chmod``, e la maschera finiva a zero —
    lasciando la voce elencata e inefficace.
    """
    concedi(log, UID_ALTRO, 0o4)
    assert stat.S_IMODE(log.stat().st_mode) == 0o640, "il kernel riflette la maschera"
    assert maschera(log) & LETTURA

    restringi(log, 0o600)

    assert maschera(log) & LETTURA, "la maschera è stata azzerata: ACL neutralizzata"
    assert accesso(log).lettori_nominati, "la voce non concede più niente"


def test_restringi_toglie_comunque_i_bit_del_mondo(log: Path):
    """Ciò che l'ACL non spiega resta da stringere.

    ``other`` è un permesso vero in entrambi i casi: nessuna concessione
    nominata lo giustifica, e va tolto anche quando un'ACL c'è.
    """
    concedi(log, UID_ALTRO, 0o4, altri=0o4)
    assert accesso(log).altri & LETTURA

    restringi(log, 0o600)

    acc = accesso(log)
    assert not acc.altri & LETTURA, "il mondo legge ancora"
    assert acc.lettori_nominati, "la concessione è stata travolta insieme a `other`"


def test_restringi_non_muore_su_un_percorso_sparito(tmp_path: Path):
    restringi(tmp_path / "non-esiste", 0o600)


# --------------------------------------------------------------------------- #
# End-to-end: lo scrittore del log
# --------------------------------------------------------------------------- #


def test_il_writer_del_log_non_annulla_l_acl(log: Path):
    """Il guasto come si presentava davvero: a ogni avvio del server.

    ``AuditLog`` si costruisce una volta per processo e irrigidisce i
    permessi in quel momento. Con la regola vecchia bastava riavviare il
    server perché la spedizione del log smettesse di funzionare, senza che
    niente lo dicesse.
    """
    concedi(log, UID_ALTRO, 0o4)

    scrittore = AuditLog(log)

    assert maschera(scrittore.path) & LETTURA
    assert stat.S_IMODE(log.stat().st_mode) == 0o640


def test_lettura_effettiva_da_un_altro_utente(log: Path):
    """La prova che conta: un byte letto davvero, non i bit guardati.

    È la stessa regola del controllo ACL del preflight — un controllo deve
    riprodurre l'operazione che diagnostica. Richiede privilegi per cambiare
    identità, quindi salta dove non ci sono, come i test di ``chattr``.
    """
    if os.geteuid() != 0:
        pytest.skip("serve root per leggere sotto un'altra identità")

    concedi(log, UID_ALTRO, 0o4)
    # Il permesso sul file non basta: serve il transito su tutta la catena.
    # Senza, il guasto è lo stesso `EACCES` che darebbe un'ACL mancante — la
    # coppia di cause indistinguibili documentata in §6.4 per `hermes-tool`,
    # e la ragione per cui la prova si fa leggendo invece che guardando.
    #
    # Sulla directory del log il transito va dato con un'ACL e non con una
    # `chmod`: `AuditLog` irrigidisce anche la directory, e un `o+x` messo a
    # mano verrebbe tolto al primo avvio. Sulle antenate, che nessuno
    # scrittore tocca, basta la chmod.
    concedi(log.parent, UID_ALTRO, 0o1, proprietario=0o7)
    for directory in log.parent.parents:
        if directory == Path(directory.root):
            break
        directory.chmod(stat.S_IMODE(directory.stat().st_mode) | 0o011)
    AuditLog(log)

    def leggibile() -> bool:
        figlio = os.fork()
        if figlio == 0:  # pragma: no cover - gira nel processo figlio
            try:
                os.setgid(UID_ALTRO)
                os.setuid(UID_ALTRO)
                with log.open("rb") as fh:
                    fh.read(1)
            except OSError:
                os._exit(1)
            os._exit(0)
        _, stato = os.waitpid(figlio, 0)
        return os.waitstatus_to_exitcode(stato) == 0

    assert leggibile(), "la concessione è elencata ma non vale"


# --------------------------------------------------------------------------- #
# L'altra metà del difetto: il rimedio suggerito dal preflight
# --------------------------------------------------------------------------- #


def _controllo(referto, prefisso: str):
    trovati = [c for c in referto.controlli if c.nome.startswith(prefisso)]
    assert trovati, f"nessun controllo che inizi per {prefisso!r}"
    return trovati[0]


@pytest.mark.slow
def test_il_preflight_non_suggerisce_il_chmod_che_rompe(tmp_path: Path):
    """Un rimedio che disattiva un altro controllo è peggio di nessun rimedio.

    Con la lettura a soli bit, un log a cui è stata concessa la lettura a un
    utente si presentava come ``0640`` e il preflight rispondeva «leggibile
    da altri utenti, chmod 600»: chi avesse seguito il consiglio avrebbe
    spento la spedizione del log credendo di aver chiuso una fuga.
    """
    from tests.test_doctor import scrivi_config

    radice = Path(__file__).resolve().parent.parent
    percorso = scrivi_config(tmp_path, radice)
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o600)
    concedi(log, UID_ALTRO, 0o4)

    controllo = _controllo(esegui(percorso), "log d'audit")

    assert controllo.esito is Esito.OK, controllo.messaggio
    assert "maschera" in controllo.messaggio
    assert "chmod 600" not in (controllo.rimedio or "")


@pytest.mark.slow
def test_il_preflight_avvisa_ancora_su_un_log_leggibile_da_tutti(tmp_path: Path):
    """La correzione non deve aver ammorbidito il caso che va segnalato."""
    from tests.test_doctor import scrivi_config

    radice = Path(__file__).resolve().parent.parent
    percorso = scrivi_config(tmp_path, radice)
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o644)

    controllo = _controllo(esegui(percorso), "log d'audit")

    assert controllo.esito is Esito.AVVISO
    assert "tutti" in controllo.messaggio
