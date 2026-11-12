"""Test della spedizione del log a una seconda macchina (A5).

Il presidio non è «fare una copia»: è **rendere rilevabile** che l'originale
sia stato accorciato o riscritto. Una copia che nessuno confronta è un
backup, non una prova. Tutto ciò che conta qui dentro sta in una regola
sola — il ricevente rifiuta qualunque offset che non sia la dimensione
attuale della sua copia — e i test che valgono sono quelli che la vedono
**dire di no**.

I due script di shell si esercitano davvero, con un `ssh` finto che chiama
il ricevente in locale. La copia su cui girano ha una riga cambiata (il
percorso della configurazione, quello dell'`ssh`, la directory delle copie):
i test verificano che la sostituzione abbia morso, così rinominare quelle
variabili fa cadere i test invece di lasciarli girare su niente.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_server.doctor import (
    MITTENTE_NEL_REPO,
    UTENTE_SPEDIZIONE,
    Esito,
    Spedizione,
    SpedizioneError,
    esegui,
    leggi_spedizione,
)

RADICE = Path(__file__).resolve().parent.parent


def _errori_di_spedizione(referto) -> list[str]:
    return [
        c.nome
        for c in referto.controlli
        if "spedizione" in c.nome and c.esito is Esito.ERRORE
    ]


def _controllo(referto, prefisso: str):
    trovati = [c for c in referto.controlli if c.nome.startswith(prefisso)]
    assert trovati, f"nessun controllo che inizi per {prefisso!r}"
    return trovati[0]


def _sostituisci_una_riga(testo: str, schema: str, nuova: str) -> str:
    """Sostituisce esattamente una riga, o fallisce dicendolo.

    Un test che patcha a vuoto gira su codice che non è quello installato e
    dice verde lo stesso: è la forma del falso verde applicata agli
    strumenti di prova.
    """
    nuovo, quante = re.subn(schema, nuova, testo, flags=re.MULTILINE)
    assert quante == 1, f"lo schema {schema!r} ha morso {quante} volte, non 1"
    return nuovo


@pytest.fixture()
def banco(tmp_path: Path):
    """Mittente, ricevente e un `ssh` finto che li mette in comunicazione."""
    for strumento in ("sh", "sha256sum", "tail", "head", "wc"):
        if shutil.which(strumento) is None:  # pragma: no cover
            pytest.skip(f"{strumento} non disponibile")

    log = tmp_path / "log"
    log.mkdir()
    remoto = tmp_path / "remoto"
    (remoto / "hermesmcp").mkdir(parents=True)
    stato = tmp_path / "stato"
    stato.mkdir()
    audit = log / "audit.jsonl"
    audit.write_text("", encoding="utf-8")

    ricevente = tmp_path / "hermes-log-receive"
    ricevente.write_text(
        _sostituisci_una_riga(
            (RADICE / "bin" / "hermes-log-receive").read_text(encoding="utf-8"),
            r"^BASE=.*$",
            f"BASE={remoto}",
        ),
        encoding="utf-8",
    )
    ricevente.chmod(0o755)

    finto_ssh = tmp_path / "ssh"
    argomenti = tmp_path / "argv-ssh"
    finto_ssh.write_text(
        "#!/bin/sh\n"
        "# L'ultimo argomento è la richiesta, come con ssh vero. Gli altri si\n"
        "# annotano: servono a verificare che il mittente passi davvero ciò\n"
        "# che crede di passare, la porta compresa.\n"
        f'printf "%s\\n" "$*" >> {argomenti}\n'
        'for ULTIMO in "$@"; do :; done\n'
        f'SSH_ORIGINAL_COMMAND="$ULTIMO" exec {ricevente} hermesmcp\n',
        encoding="utf-8",
    )
    finto_ssh.chmod(0o755)

    config = tmp_path / "log-shipping.conf"
    chiave = tmp_path / "chiave"
    chiave.write_text("non una chiave vera\n", encoding="utf-8")
    known = tmp_path / "known_hosts"
    known.write_text("", encoding="utf-8")
    config.write_text(
        "COLLECTOR_HOST=192.0.2.50\n"
        "COLLECTOR_UTENTE=hermes-collect\n"
        f"CHIAVE={chiave}\n"
        f"KNOWN_HOSTS={known}\n"
        f"STATO_DIR={stato}\n"
        f"CANALE_audit={audit}\n",
        encoding="utf-8",
    )

    testo = (RADICE / MITTENTE_NEL_REPO).read_text(encoding="utf-8")
    testo = _sostituisci_una_riga(testo, r"^CONFIG=.*$", f"CONFIG={config}")
    testo = _sostituisci_una_riga(testo, r"^SSH=.*$", f"SSH={finto_ssh}")
    mittente = tmp_path / "hermes-log-ship"
    mittente.write_text(testo, encoding="utf-8")
    mittente.chmod(0o755)

    class Banco:
        def __init__(self) -> None:
            self.argomenti = argomenti
            self.config = config
            self.audit = audit
            self.copia = remoto / "hermesmcp" / "audit.jsonl"
            self.stato = stato / "audit.stato"
            self.ricevente = ricevente
            self.remoto = remoto

        def spedisci(self) -> subprocess.CompletedProcess:
            return subprocess.run(
                [str(mittente)], capture_output=True, text=True, timeout=60
            )

        def chiedi(self, richiesta: str, dati: bytes = b"") -> subprocess.CompletedProcess:
            return subprocess.run(
                [str(ricevente), "hermesmcp"],
                input=dati,
                capture_output=True,
                timeout=60,
                env={**os.environ, "SSH_ORIGINAL_COMMAND": richiesta},
            )

    return Banco()


# --------------------------------------------------------------------------- #
# Il giro normale
# --------------------------------------------------------------------------- #


def test_la_copia_e_identica_byte_per_byte(banco):
    """Non «equivalente»: identica. È ciò che rende confrontabili i due file.

    Se la copia fosse una ricostruzione riga per riga, confrontarla con
    l'originale richiederebbe di interpretare entrambi, e due
    interpretazioni che divergono non dicono quale dei due file è cambiato.
    """
    banco.audit.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")

    esito = banco.spedisci()

    assert esito.returncode == 0, esito.stderr
    assert banco.copia.read_bytes() == banco.audit.read_bytes()


def test_spedisce_solo_il_delta(banco):
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")
    banco.spedisci()
    primo = banco.copia.stat().st_size

    with banco.audit.open("a", encoding="utf-8") as fh:
        fh.write('{"n": 2}\n')
    esito = banco.spedisci()

    assert esito.returncode == 0, esito.stderr
    assert banco.copia.stat().st_size > primo
    assert banco.copia.read_bytes() == banco.audit.read_bytes()


def test_un_giro_senza_novita_non_e_un_errore(banco):
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")
    banco.spedisci()

    esito = banco.spedisci()

    assert esito.returncode == 0, esito.stderr
    assert "esito=ok" in banco.stato.read_text(encoding="utf-8")


def test_riprende_dopo_una_connessione_caduta_a_meta(banco):
    """Un blocco interrotto non deve né duplicare né lasciare buchi.

    È il caso che obbliga a chiedere `stato` prima di ogni invio invece di
    fidarsi dell'offset annotato in locale: la verità su dove siamo arrivati
    ce l'ha il collector.
    """
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")
    banco.spedisci()
    with banco.audit.open("a", encoding="utf-8") as fh:
        fh.write('{"n": 2}\n{"n": 3}\n')
    # Un blocco arrivato a metà, come lo lascerebbe una connessione caduta.
    with banco.copia.open("ab") as fh:
        fh.write(b'{"n": 2}\n{"n')

    esito = banco.spedisci()

    assert esito.returncode == 0, esito.stderr
    assert banco.copia.read_bytes() == banco.audit.read_bytes()


# --------------------------------------------------------------------------- #
# Il rifiuto, che è il presidio
# --------------------------------------------------------------------------- #


def test_un_troncamento_locale_e_una_divergenza(banco):
    """Lo scenario per cui A5 esiste: root ripulisce il log.

    La copia è più lunga dell'originale. Non si spedisce niente: scriverci
    sopra costruirebbe una copia che non corrisponde a nulla, cioè
    distruggerebbe la prova mentre si crede di salvarla.
    """
    banco.audit.write_text('{"n": 1}\n{"n": 2}\n{"n": 3}\n', encoding="utf-8")
    banco.spedisci()
    intera = banco.copia.read_bytes()

    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")
    esito = banco.spedisci()

    assert esito.returncode == 3, esito.stderr
    assert "DIVERGENZA" in esito.stderr
    assert banco.copia.read_bytes() == intera, "la copia è stata toccata"
    assert "esito=divergenza" in banco.stato.read_text(encoding="utf-8")


def test_una_riscrittura_a_parita_di_lunghezza_e_una_divergenza(banco):
    """Il caso che la sola dimensione non vedrebbe.

    Chi manomette con attenzione sostituisce righe senza cambiare la
    lunghezza del file. È per questo che a ogni giro si confronta anche
    l'impronta della coda, e non solo i byte.
    """
    banco.audit.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")
    banco.spedisci()

    testo = banco.audit.read_text(encoding="utf-8").replace('{"n": 2}', '{"n": 9}')
    banco.audit.write_text(testo, encoding="utf-8")
    assert banco.audit.stat().st_size == banco.copia.stat().st_size
    esito = banco.spedisci()

    assert esito.returncode == 3, esito.stderr
    assert "DIVERGENZA" in esito.stderr


def test_il_ricevente_rifiuta_un_offset_che_non_combacia(banco):
    """Il rifiuto preso da solo, senza passare dal mittente.

    Serve perché è questa la riga che rende inutile riscrivere lo stato del
    mittente: l'offset lo valida chi custodisce la copia.
    """
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")
    banco.spedisci()

    esito = banco.chiedi("audit appendi 0", b'{"falso": 1}\n')

    assert esito.returncode == 3
    assert b"rifiutato" in esito.stderr
    assert b"falso" not in banco.copia.read_bytes()


@pytest.mark.parametrize(
    "richiesta",
    [
        "segreti stato",
        "../../etc/passwd stato",
        "audit cancella",
        "audit stato ciao",
        "audit appendi meno-uno",
        "AUDIT stato",
    ],
)
def test_il_ricevente_accetta_solo_cio_che_conosce(banco, richiesta):
    """Il nome del canale è una chiave, mai un pezzo di percorso."""
    esito = banco.chiedi(richiesta)
    assert esito.returncode == 64, esito.stderr


def test_un_canale_illeggibile_non_ferma_gli_altri(banco, tmp_path: Path):
    """Sono prove distinte: perderne due perché una ha un problema è peggio."""
    assente = tmp_path / "log" / "overrides.jsonl"
    config = tmp_path / "log-shipping.conf"
    # Il canale rotto va PRIMA di quello sano: messo dopo, il test
    # passerebbe anche se il primo guasto interrompesse il ciclo, cioè
    # proverebbe qualcosa di più debole di quello che afferma.
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "CANALE_audit=", f"CANALE_overrides={assente}\nCANALE_audit="
        ),
        encoding="utf-8",
    )
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")

    esito = banco.spedisci()

    assert esito.returncode != 0
    assert banco.copia.read_bytes() == banco.audit.read_bytes(), (
        "il canale sano non è stato spedito"
    )


def test_la_porta_del_collector_arriva_a_ssh(banco):
    """La 22 è la porta solita, non l'unica.

    Trovato sul campo, al primo collaudo: il collector ascoltava sulla 2222 e
    il mittente ci andava con la 22 implicita. Nessun errore di
    configurazione — semplicemente non poteva funzionare, e il sintomo
    (`Connection refused`) non puntava alla causa.
    """
    banco.config.write_text(
        banco.config.read_text(encoding="utf-8").replace(
            "COLLECTOR_HOST=", "COLLECTOR_PORTA=2222\nCOLLECTOR_HOST="
        ),
        encoding="utf-8",
    )
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")

    banco.spedisci()

    assert "-p 2222" in banco.argomenti.read_text(encoding="utf-8")


def test_senza_porta_dichiarata_si_usa_la_22(banco):
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")

    banco.spedisci()

    assert "-p 22 " in banco.argomenti.read_text(encoding="utf-8")


@pytest.mark.parametrize("porta", ["0", "70000", "ventidue", "22a"])
def test_una_porta_non_valida_non_passa(porta):
    base = (
        "COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        "KNOWN_HOSTS=/kh\nSTATO_DIR=/s\nCANALE_audit=/a\n"
    )
    with pytest.raises(SpedizioneError):
        leggi_spedizione(base + f"COLLECTOR_PORTA={porta}\n")


def test_un_guasto_banale_non_maschera_una_divergenza(banco, tmp_path: Path):
    """Gli esiti non sono ordinati per gravità, e prendere il massimo no.

    Difetto trovato rileggendo il diff: l'esito peggiore veniva
    sovrascritto, quindi un canale illeggibile (1) incontrato DOPO uno
    divergente (3) abbassava il codice d'uscita. Il servizio avrebbe
    segnalato un guasto di configurazione mentre il log veniva manomesso —
    cioè avrebbe spento esattamente il segnale per cui A5 esiste.
    """
    banco.audit.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")
    banco.spedisci()
    banco.audit.write_text('{"n": 1}\n', encoding="utf-8")  # troncato

    # Un secondo canale, rotto in modo banale, DOPO quello divergente.
    config = tmp_path / "log-shipping.conf"
    config.write_text(
        config.read_text(encoding="utf-8")
        + f"CANALE_overrides={tmp_path}/non-esiste.jsonl\n",
        encoding="utf-8",
    )

    esito = banco.spedisci()

    assert esito.returncode == 3, (
        f"la divergenza è stata mascherata: esito {esito.returncode}\n{esito.stderr}"
    )


# --------------------------------------------------------------------------- #
# Le copie della stessa costante, in linguaggi diversi
# --------------------------------------------------------------------------- #


def test_la_finestra_e_la_stessa_nei_due_script():
    """Se divergessero, ogni giro riporterebbe una divergenza che non c'è.

    Un falso rosso quotidiano su un presidio di manomissione è il modo più
    rapido di insegnare a ignorarlo.
    """
    def finestra(nome: str) -> str:
        testo = (RADICE / "bin" / nome).read_text(encoding="utf-8")
        trovate = re.findall(r"^FINESTRA=(\d+)$", testo, flags=re.MULTILINE)
        assert len(trovate) == 1, f"{nome}: {len(trovate)} definizioni di FINESTRA"
        return trovate[0]

    assert finestra("hermes-log-ship") == finestra("hermes-log-receive")


def test_l_utente_dell_unita_e_quello_del_preflight():
    """La stessa costante in un'unità di systemd e in un modulo Python."""
    unita = (RADICE / "config" / "systemd" / "hermes-log-ship.service").read_text(
        encoding="utf-8"
    )
    assert f"User={UTENTE_SPEDIZIONE}\n" in unita
    assert f"Group={UTENTE_SPEDIZIONE}\n" in unita


def test_l_unita_usa_il_tetto_di_tempo_che_un_oneshot_rispetta():
    """`RuntimeMaxSec` su un `Type=oneshot` viene ignorato da systemd.

    Trovato al primo avvio su macchina vera, dall'avviso nel journal. Non
    era cosmetico: per un oneshot `TimeoutStartSec` vale **infinito** di
    default, quindi il tetto che credevamo di aver messo non c'era e un giro
    appeso sarebbe rimasto appeso, con il timer a guardare.
    """
    unita = (RADICE / "config" / "systemd" / "hermes-log-ship.service").read_text(
        encoding="utf-8"
    )
    assert "Type=oneshot" in unita
    assert not re.search(r"^RuntimeMaxSec=", unita, flags=re.MULTILINE)
    assert re.search(r"^TimeoutStartSec=\d+$", unita, flags=re.MULTILINE)


def test_l_unita_lancia_il_mittente_dove_viene_installato():
    from mcp_server.doctor import MITTENTE_INSTALLATO

    unita = (RADICE / "config" / "systemd" / "hermes-log-ship.service").read_text(
        encoding="utf-8"
    )
    assert f"ExecStart={MITTENTE_INSTALLATO}\n" in unita


# --------------------------------------------------------------------------- #
# La configurazione, letta dalle due parti con le stesse regole
# --------------------------------------------------------------------------- #


def test_il_modello_del_repo_e_valido():
    """Un modello che non si lascia leggere è un modello che nessuno proverà."""
    sped = leggi_spedizione(
        (RADICE / "config" / "log-shipping.example.conf").read_text(encoding="utf-8")
    )
    assert isinstance(sped, Spedizione)
    assert dict(sped.canali).keys() == {"audit", "overrides"}


@pytest.mark.parametrize(
    "riga, atteso",
    [
        ("ROBA=1", "non riconosciuta"),
        ("CANALE_Audit=/tmp/x", "non valido"),
        ("CANALE_audit=relativo/x", "assoluto"),
        ("senza uguale", "manca '='"),
    ],
)
def test_una_configurazione_sbagliata_non_passa(riga, atteso):
    base = (
        "COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        "KNOWN_HOSTS=/kh\nSTATO_DIR=/s\nCANALE_audit=/a\n"
    )
    with pytest.raises(SpedizioneError) as err:
        leggi_spedizione(base + riga + "\n")
    assert atteso in str(err.value)


def test_una_chiave_obbligatoria_assente_non_passa():
    with pytest.raises(SpedizioneError) as err:
        leggi_spedizione("COLLECTOR_HOST=h\nCANALE_audit=/a\n")
    assert "CHIAVE" in str(err.value)


# --------------------------------------------------------------------------- #
# Il preflight
# --------------------------------------------------------------------------- #


def _config_con_spedizione(tmp_path: Path, spedizione: Path | None) -> Path:
    from tests.test_doctor import scrivi_config

    percorso = scrivi_config(tmp_path, RADICE)
    if spedizione is not None:
        testo = percorso.read_text(encoding="utf-8").replace(
            "container_available = false",
            f'container_available = false\nlog_shipping = "{spedizione}"',
        )
        percorso.write_text(testo, encoding="utf-8")
    return percorso


@pytest.mark.slow
def test_non_configurata_e_un_avviso_non_un_errore(tmp_path: Path):
    """Assente è diverso da rotto: il server funziona, manca una proprietà."""
    referto = esegui(_config_con_spedizione(tmp_path, None))

    controllo = _controllo(referto, "spedizione del log")
    assert controllo.esito is Esito.AVVISO
    assert "solo su questa macchina" in controllo.messaggio
    # La proprietà è «non blocca», e si verifica sui controlli della
    # spedizione: `referto.pronto` dipende anche dall'ambiente in cui gira
    # la suite, e asserirlo qui misurerebbe quello invece di questo.
    assert not _errori_di_spedizione(referto)


@pytest.mark.slow
def test_una_destinazione_riscrivibile_e_un_errore(tmp_path: Path):
    """Chi spedisce non deve poter scegliere dove spedisce."""
    spedizione = tmp_path / "log-shipping.conf"
    spedizione.write_text(
        "COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        "KNOWN_HOSTS=/kh\nSTATO_DIR=/s\nCANALE_audit=/a\n",
        encoding="utf-8",
    )
    spedizione.chmod(0o666)

    referto = esegui(_config_con_spedizione(tmp_path, spedizione))

    controllo = _controllo(referto, "configurazione della spedizione")
    assert controllo.esito is Esito.ERRORE


@pytest.mark.slow
def test_una_destinazione_riscrivibile_non_zittisce_gli_altri_controlli(
    tmp_path: Path,
):
    """Chi ripara deve vedere tutti i problemi, non il primo.

    Trovato dalla CI, e per il motivo giusto: i primi test di questo blocco
    speravano di girare da root — dove il file di configurazione nasce di
    root e il controllo sulla proprietà non scatta — invece di imporre la
    proprietà che stavano misurando. Sul runner scattava, il preflight si
    fermava lì, e i controlli successivi non esistevano.

    La correzione non è stata nel test: quel controllo segnala e prosegue,
    che è la regola già applicata al perimetro e al wrapper.
    """
    spedizione = tmp_path / "log-shipping.conf"
    spedizione.write_text(
        "COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        "KNOWN_HOSTS=/kh\nSTATO_DIR=/s\n"
        "CANALE_audit=/var/log/un-altro-file.jsonl\n",
        encoding="utf-8",
    )
    spedizione.chmod(0o666)

    referto = esegui(_config_con_spedizione(tmp_path, spedizione))

    assert _controllo(referto, "configurazione della spedizione").esito is Esito.ERRORE
    secondo = _controllo(referto, "canale del log d'audit")
    assert secondo.esito is Esito.ERRORE, "il secondo problema è stato zittito"


@pytest.mark.slow
def test_spedire_un_file_diverso_da_quello_che_si_scrive_e_un_errore(tmp_path: Path):
    """Due fonti per lo stesso file sono due fonti che divergono.

    Il guasto che questo controllo intercetta è silenzioso e perfetto: la
    spedizione funziona, il collector riceve, tutto è verde — e il file che
    arriva non è quello su cui il server scrive.
    """
    spedizione = tmp_path / "log-shipping.conf"
    spedizione.write_text(
        "COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        "KNOWN_HOSTS=/kh\nSTATO_DIR=/s\n"
        "CANALE_audit=/var/log/un-altro-file.jsonl\n",
        encoding="utf-8",
    )
    spedizione.chmod(0o644)

    referto = esegui(_config_con_spedizione(tmp_path, spedizione))

    controllo = _controllo(referto, "canale del log d'audit")
    assert controllo.esito is Esito.ERRORE
    assert "un-altro-file" in controllo.messaggio


@pytest.mark.slow
def test_una_divergenza_annotata_arriva_al_referto(tmp_path: Path):
    """Il sintomo deve arrivare a chi guarda, o non è un sintomo."""
    stato = tmp_path / "stato"
    stato.mkdir()
    (stato / "audit.stato").write_text(
        "ts=2026-11-12T10:00:00Z\nesito=divergenza\nlocale=10\nremoto=400\n",
        encoding="utf-8",
    )
    spedizione = tmp_path / "log-shipping.conf"
    spedizione.write_text(
        f"COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        f"KNOWN_HOSTS=/kh\nSTATO_DIR={stato}\n"
        f"CANALE_audit={tmp_path}/audit.jsonl\n",
        encoding="utf-8",
    )
    spedizione.chmod(0o644)

    referto = esegui(_config_con_spedizione(tmp_path, spedizione))

    controllo = _controllo(referto, "spedizione di audit")
    assert controllo.esito is Esito.ERRORE
    assert "DIVERGENZA" in controllo.messaggio


@pytest.mark.slow
def test_il_preflight_dichiara_di_non_vedere_la_copia_remota(tmp_path: Path):
    """Un limite non dichiarato diventa una garanzia che nessuno ha dato."""
    spedizione = tmp_path / "log-shipping.conf"
    spedizione.write_text(
        f"COLLECTOR_HOST=h\nCOLLECTOR_UTENTE=u\nCHIAVE=/k\n"
        f"KNOWN_HOSTS=/kh\nSTATO_DIR={tmp_path}\n"
        f"CANALE_audit={tmp_path}/audit.jsonl\n",
        encoding="utf-8",
    )
    spedizione.chmod(0o644)

    controllo = _controllo(
        esegui(_config_con_spedizione(tmp_path, spedizione)), "spedizione del log"
    )

    assert "NON è verificabile da qui" in controllo.messaggio


# --------------------------------------------------------------------------- #
# «Non lo so» non deve diventare «non è mai successo»
# --------------------------------------------------------------------------- #


def test_uno_stato_illeggibile_non_diventa_mai_girato(monkeypatch, tmp_path: Path):
    """Trovato sulla VM: il referto diceva il falso su una spedizione viva.

    `/var/lib/hermes-ship` è `750` e appartiene al mittente: il preflight,
    che gira come utente di servizio, non la attraversa. Il codice trattava
    «non riesco a leggere» e «non c'è» come la stessa cosa, e riportava «il
    mittente non è mai girato» mentre il mittente aveva appena spedito.

    È la forma censita nel metodo del progetto — un'interrogazione che non sa
    rispondere ne fabbrica una plausibile — e qui era peggio del solito:
    rassicurava su un presidio di cui non sapeva niente.
    """
    from mcp_server import doctor

    def nega(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", nega)

    valori, motivo = doctor._stato_di_un_canale(tmp_path, "audit")

    assert valori is None
    assert motivo, "il motivo dev'essere riportato, non ingoiato"


def test_il_referto_dice_che_non_sa_invece_di_rassicurare(
    monkeypatch, tmp_path: Path
):
    from mcp_server import doctor

    def nega(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", nega)
    sped = doctor.Spedizione(
        collector_host="h",
        collector_utente="u",
        collector_porta=22,
        chiave=Path("/k"),
        known_hosts=Path("/kh"),
        stato_dir=tmp_path / "hermes-ship" / "stato",
        canali=(("audit", tmp_path / "audit.jsonl"),),
    )
    referto = doctor.Referto()

    doctor._ultimo_giro(referto, sped, "hermes")

    controllo = _controllo(referto, "spedizione di audit")
    assert "mai girato" not in controllo.messaggio
    assert "non si puo' dire niente" in controllo.messaggio
    # Il rimedio deve nominare il transito, che è la causa vera.
    assert "setfacl" in controllo.rimedio
    assert str(sped.stato_dir.parent) in controllo.rimedio


def test_uno_stato_assente_resta_mai_girato(tmp_path: Path):
    """La distinzione non deve aver perso il caso normale."""
    from mcp_server import doctor

    sped = doctor.Spedizione(
        collector_host="h",
        collector_utente="u",
        collector_porta=22,
        chiave=Path("/k"),
        known_hosts=Path("/kh"),
        stato_dir=tmp_path,
        canali=(("audit", tmp_path / "audit.jsonl"),),
    )
    referto = doctor.Referto()

    doctor._ultimo_giro(referto, sped, "hermes")

    assert "mai girato" in _controllo(referto, "spedizione di audit").messaggio
