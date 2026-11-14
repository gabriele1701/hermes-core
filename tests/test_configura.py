"""`bin/hermes-configura` — compila i valori per-installazione.

Lo script si esercita in `--prova`: valida tutto e non scrive niente, quindi
i test girano senza root e senza poter fare danni. È la ragione per cui quella
modalità esiste — uno script di dispiegamento che solo una persona con `sudo`
può lanciare è uno script che nessun test ha mai visto sbagliare.

I casi che contano qui sono i RIFIUTI. Compilare un valore giusto è facile;
il valore di questo script è che un valore sbagliato non arrivi su disco,
perché ognuno di quei valori sbagliati passa i controlli a valle e si
manifesta come una macchina irraggiungibile o un perimetro che non è quello
che l'operatore crede di aver scritto.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
SCRIPT = RADICE / "bin" / "hermes-configura"

CHIAVE_VALIDA = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIIAsLQ8jYqi5BWJihh6tL7ypJsFM1VtyR2SHYo670oDg "
    "hermes-core@windows"
)


@pytest.fixture
def radice_finta(tmp_path: Path) -> Path:
    """Gli artefatti che il bootstrap genera, con i segnaposti dentro."""
    (tmp_path / "sshd").mkdir()
    (tmp_path / "hermes").mkdir()
    (tmp_path / "chiavi").mkdir()
    (tmp_path / "sshd" / "09-hermes-allowusers.conf").write_text(
        "# generato dal bootstrap\nAllowUsers DA_COMPILARE hermes\n",
        encoding="utf-8",
    )
    (tmp_path / "hermes" / "scope.toml").write_text(
        'reti = [\n    "DA_COMPILARE",\n]\n\n[alias]\n', encoding="utf-8"
    )
    return tmp_path


def esegui(radice: Path, *argomenti: str) -> subprocess.CompletedProcess[str]:
    ambiente = dict(os.environ)
    ambiente.update(
        HERMES_DIR_CONFIG=str(radice / "hermes"),
        HERMES_DIR_SSHD=str(radice / "sshd"),
        HERMES_DIR_CHIAVI=str(radice / "chiavi"),
        HERMES_NETPLAN=str(radice / "99-hermes-static.yaml"),
    )
    return subprocess.run(
        [str(SCRIPT), "--prova", *argomenti],
        capture_output=True,
        text=True,
        env=ambiente,
        stdin=subprocess.DEVNULL,
        cwd=str(RADICE),
        timeout=120,
    )


def completo(**sostituzioni: str) -> list[str]:
    base = {
        "--utente": "root",
        "--chiave": CHIAVE_VALIDA,
        "--reti": "192.168.56.0/24",
        "--alias": "lab-web=192.168.56.20",
        "--postazione": "192.168.56.1",
    }
    base.update(sostituzioni)
    return [p for coppia in base.items() for p in coppia]


# --- Il caso che riesce ---------------------------------------------------- #


def test_una_configurazione_valida_arriva_in_fondo(radice_finta: Path):
    esito = esegui(radice_finta, *completo())
    assert esito.returncode == 0, esito.stderr
    assert "tutto validato, niente scritto" in esito.stdout
    assert "AllowUsers root hermes" in esito.stdout


def test_la_prova_non_scrive_niente(radice_finta: Path):
    """`--prova` è una proprietà dello script, non di chi si ricorda.

    Ogni scrittura passa da una funzione sola, così la modalità di prova non
    dipende dal fatto che ogni ramo controlli una variabile.
    """
    prima = {
        p: p.read_bytes()
        for p in radice_finta.rglob("*")
        if p.is_file()
    }

    assert esegui(radice_finta, *completo()).returncode == 0

    dopo = {p: p.read_bytes() for p in radice_finta.rglob("*") if p.is_file()}
    assert dopo == prima


def test_un_valore_gia_compilato_non_viene_sovrascritto_da_sola(
    radice_finta: Path,
):
    """Senza terminale non c'è nessuno a cui chiedere, quindi non si tocca.

    Un automatismo che sovrascrive una decisione dell'operatore solo perché è
    stato rilanciato è la regola di idempotenza del bootstrap al contrario.
    """
    (radice_finta / "sshd" / "09-hermes-allowusers.conf").write_text(
        "AllowUsers gabri hermes\n", encoding="utf-8"
    )
    esito = esegui(radice_finta, *completo())
    assert esito.returncode == 0, esito.stderr
    assert "già compilato (gabri hermes)" in esito.stdout


def test_con_forza_un_valore_gia_compilato_viene_sostituito(radice_finta: Path):
    """`--forza` è la risposta «sì» data in anticipo.

    Serve dove la domanda non si può fare: senza terminale, e nei test.
    """
    (radice_finta / "sshd" / "09-hermes-allowusers.conf").write_text(
        "AllowUsers gabri hermes\n", encoding="utf-8"
    )
    esito = esegui(radice_finta, "--forza", *completo())
    assert esito.returncode == 0, esito.stderr
    assert "AllowUsers root hermes" in esito.stdout


def test_il_perimetro_generato_passa_il_caricatore_vero(radice_finta: Path):
    """Non si riscrivono le regole delle reti: si usa il caricatore.

    Due verità divergono col tempo, e quella sbagliata sarebbe la prima che
    l'operatore vede. Lo script scrive il perimetro in un file temporaneo e
    lo installa solo se `ScopeAllowlist.carica` lo accetta; questo test
    verifica che un caso buono arrivi fino a quel punto.
    """
    esito = esegui(radice_finta, *completo(**{"--reti": "192.168.56.0/255.255.255.0"}))
    assert esito.returncode == 0, esito.stderr
    # Forma canonica, non quella battuta: il file deve contenere ciò che il
    # caricatore confronterà.
    assert "192.168.56.0/24" in esito.stdout


# --- I rifiuti, che sono il punto ----------------------------------------- #


def test_un_utente_inesistente_viene_rifiutato(radice_finta: Path):
    """Un refuso nel nome passa `sshd -t`, passa il preflight, e chiude fuori.

    È l'unico valore di tutta la procedura il cui errore non si ripara in
    SSH, perché toglie proprio l'SSH.
    """
    esito = esegui(radice_finta, *completo(**{"--utente": "nessun-utente-cosi"}))
    assert esito.returncode != 0
    assert "non esiste su questa macchina" in esito.stdout + esito.stderr


def test_un_utente_di_servizio_viene_rifiutato(radice_finta: Path):
    """`hermes` è già in elenco: qui va l'amministratore, non il servizio."""
    esito = esegui(radice_finta, *completo(**{"--utente": "hermes"}))
    assert esito.returncode != 0
    assert "utente di servizio" in esito.stdout + esito.stderr


def test_una_chiave_privata_incollata_per_sbaglio_viene_rifiutata(
    radice_finta: Path, tmp_path: Path
):
    """Il refuso più caro: la privata al posto della pubblica.

    Finirebbe in `authorized_keys`, dove non autentica nessuno, e la
    copia leggibile da `sshd` di una chiave privata è un problema di suo. Si
    riconosce dal numero di righe, che è l'unica differenza robusta fra le
    due senza interpretarne il contenuto.
    """
    privata = tmp_path / "finta_privata"
    privata.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    esito = esegui(radice_finta, *completo(**{"--chiave": str(privata)}))
    assert esito.returncode != 0
    assert "una riga sola" in esito.stdout + esito.stderr


def test_una_chiave_senza_forma_di_chiave_viene_rifiutata(radice_finta: Path):
    esito = esegui(radice_finta, *completo(**{"--chiave": "questa non è una chiave"}))
    assert esito.returncode != 0
    assert "forma di una chiave pubblica" in esito.stdout + esito.stderr


def test_un_host_al_posto_di_una_rete_viene_rifiutato(radice_finta: Path):
    """`192.168.56.1/24` non è una rete: è un host dentro una rete.

    Accettarlo e correggerlo in silenzio darebbe un perimetro diverso da
    quello che l'operatore crede di aver scritto — e in un verso che allarga,
    non restringe.
    """
    esito = esegui(radice_finta, *completo(**{"--reti": "192.168.56.1/24"}))
    assert esito.returncode != 0
    assert "host bits set" in (esito.stdout + esito.stderr).lower()


def test_un_alias_fuori_dalle_reti_viene_rifiutato(radice_finta: Path):
    """Un bersaglio che il gate rifiuterebbe, dichiarato come ammesso."""
    esito = esegui(radice_finta, *completo(**{"--alias": "altrove=10.0.2.15"}))
    assert esito.returncode != 0
    assert "non è in nessuna delle reti" in esito.stdout + esito.stderr


def test_una_interfaccia_inesistente_viene_rifiutata(radice_finta: Path):
    """Un nome sbagliato produce un netplan valido che non configura niente.

    E lo scopri applicandolo, cioè quando l'indirizzo vecchio è già sparito.
    """
    esito = esegui(
        radice_finta,
        *completo(),
        "--interfaccia",
        "enp0s99",
        "--indirizzo",
        "192.168.56.10/24",
    )
    assert esito.returncode != 0
    assert "non esiste" in esito.stdout + esito.stderr


def test_un_indirizzo_senza_prefisso_viene_rifiutato(radice_finta: Path):
    esito = esegui(
        radice_finta, *completo(), "--interfaccia", "lo", "--indirizzo", "192.168.56.10"
    )
    assert esito.returncode != 0
    assert "lunghezza del prefisso" in esito.stdout + esito.stderr


# --- Non interattivo ------------------------------------------------------- #


def test_senza_terminale_un_valore_mancante_nomina_la_sua_opzione(
    radice_finta: Path,
):
    """Non si aspetta un umano che non c'è.

    Senza terminale lo script non può chiedere: deve dire quale opzione
    manca e uscire, invece di leggere una riga vuota e proseguire con un
    valore che nessuno ha scelto.
    """
    esito = esegui(radice_finta, "--chiave", CHIAVE_VALIDA)
    assert esito.returncode != 0
    assert "--utente" in esito.stdout + esito.stderr


# --- Invarianti di sicurezza ---------------------------------------------- #


def test_non_ricarica_sshd_e_non_tocca_le_regole_aperte():
    """Le due azioni irreversibili restano all'operatore.

    Ricaricare `sshd` con un AllowUsers sbagliato, o cancellare la regola
    aperta della 22 con un indirizzo sbagliato, producono lo stesso esito: una
    macchina remota che non si raggiunge più, con il sintomo alla prossima
    connessione e non adesso. Durante il test di accettazione è successo due
    volte in un giorno, entrambe seguendo la procedura.

    Si guarda che non vengano ESEGUITE: le stesse parole compaiono di
    proposito nei promemoria, che è il modo giusto di nominarle.
    """
    righe = SCRIPT.read_text(encoding="utf-8").splitlines()
    eseguite = [
        r.strip()
        for r in righe
        if r and not r.lstrip().startswith("#") and not r.startswith((" ", "\t"))
    ]
    for proibito in ("systemctl", "ufw delete", "netplan try", "netplan apply"):
        assert not [r for r in eseguite if r.startswith(proibito)], proibito


def test_i_percorsi_coincidono_con_quelli_del_bootstrap():
    """Dove la copia è inevitabile, la coincidenza va verificata.

    I due script scrivono negli stessi file. Se un percorso cambia in uno
    solo, `configura` compila un file che nessuno legge — e il preflight
    continua a segnalare il segnaposto nel file vero, mandando a cercare un
    guasto che non c'è.
    """
    configura = SCRIPT.read_text(encoding="utf-8")
    bootstrap = (RADICE / "bin" / "hermes-bootstrap").read_text(encoding="utf-8")

    for atteso in (
        "09-hermes-allowusers.conf",
        "10-hermes.conf",
        "scope.toml",
        "DA_COMPILARE",
    ):
        assert atteso in configura, atteso
        assert atteso in bootstrap, atteso
