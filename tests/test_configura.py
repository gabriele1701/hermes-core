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

Gli indirizzi sono quelli che la RFC 5737 riserva alla documentazione:
192.0.2.0/24 per i valori buoni, 198.51.100.0/24 per quelli «altrove».
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

RADICE = Path(__file__).resolve().parent.parent
SCRIPT = RADICE / "bin" / "hermes-configura"

# Lo script valida le chiavi con `ssh-keygen -l`, e senza non parte. Qui non
# si può imporre la sua presenza, quindi lo si dice invece di fallire per una
# ragione che non è il codice sotto test.
pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None,
    reason="manca ssh-keygen (openssh-client): è il validatore delle chiavi",
)


@dataclass(frozen=True)
class Chiavi:
    admin_file: Path
    servizio_file: Path

    @property
    def admin(self) -> str:
        return self.admin_file.read_text(encoding="utf-8").strip()

    @property
    def servizio(self) -> str:
        return self.servizio_file.read_text(encoding="utf-8").strip()


@pytest.fixture(scope="session")
def chiavi(tmp_path_factory: pytest.TempPathFactory) -> Chiavi:
    """Due chiavi vere, con i commenti che la procedura fa dare.

    Vere perché lo script le passa a `ssh-keygen -l`: una stringa che ne ha
    solo la forma oggi viene rifiutata, ed è il punto.
    """
    cartella = tmp_path_factory.mktemp("chiavi")
    for nome, commento in (("admin", "admin@vm-di-prova"),
                           ("servizio", "hermes-core@postazione")):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", commento,
             "-f", str(cartella / nome)],
            check=True,
        )
    return Chiavi(cartella / "admin.pub", cartella / "servizio.pub")


@pytest.fixture
def radice_finta(tmp_path: Path) -> Path:
    """Gli artefatti che il bootstrap genera, con i segnaposti dentro."""
    for cartella in ("sshd", "hermes", "chiavi", "home"):
        (tmp_path / cartella).mkdir()
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
        HERMES_HOME_AMMINISTRATORE=str(radice / "home"),
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


def completo(chiavi: Chiavi, **sostituzioni: str) -> list[str]:
    base = {
        "--utente": "root",
        "--chiave-admin": str(chiavi.admin_file),
        "--chiave": str(chiavi.servizio_file),
        "--reti": "192.0.2.0/24",
        "--alias": "lab-web=192.0.2.20",
        "--postazione": "192.0.2.1",
    }
    base.update(sostituzioni)
    return [p for coppia in base.items() for p in coppia]


def uscita(esito: subprocess.CompletedProcess[str]) -> str:
    return esito.stdout + esito.stderr


# --- Il caso che riesce ---------------------------------------------------- #


def test_una_configurazione_valida_arriva_in_fondo(radice_finta: Path, chiavi: Chiavi):
    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert "tutto validato, niente scritto" in esito.stdout
    assert "AllowUsers root hermes" in esito.stdout


def test_la_prova_non_scrive_niente(radice_finta: Path, chiavi: Chiavi):
    """`--prova` è una proprietà dello script, non di chi si ricorda.

    Ogni scrittura passa da una funzione sola, così la modalità di prova non
    dipende dal fatto che ogni ramo controlli una variabile.
    """
    prima = {p: p.read_bytes() for p in radice_finta.rglob("*") if p.is_file()}

    assert esegui(radice_finta, *completo(chiavi)).returncode == 0

    dopo = {p: p.read_bytes() for p in radice_finta.rglob("*") if p.is_file()}
    assert dopo == prima


def test_un_valore_gia_compilato_non_viene_sovrascritto_da_sola(
    radice_finta: Path, chiavi: Chiavi
):
    """Senza terminale non c'è nessuno a cui chiedere, quindi non si tocca.

    Un automatismo che sovrascrive una decisione dell'operatore solo perché è
    stato rilanciato è la regola di idempotenza del bootstrap al contrario.
    """
    (radice_finta / "sshd" / "09-hermes-allowusers.conf").write_text(
        "AllowUsers nobody hermes\n", encoding="utf-8"
    )
    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert "già compilato (nobody hermes)" in esito.stdout


def test_con_forza_un_valore_gia_compilato_viene_sostituito(
    radice_finta: Path, chiavi: Chiavi
):
    """`--forza` è la risposta «sì» data in anticipo.

    Serve dove la domanda non si può fare: senza terminale, e nei test.
    """
    (radice_finta / "sshd" / "09-hermes-allowusers.conf").write_text(
        "AllowUsers nobody hermes\n", encoding="utf-8"
    )
    esito = esegui(radice_finta, "--forza", *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert "AllowUsers root hermes" in esito.stdout


def test_il_perimetro_generato_passa_il_caricatore_vero(
    radice_finta: Path, chiavi: Chiavi
):
    """Non si riscrivono le regole delle reti: si usa il caricatore.

    Due verità divergono col tempo, e quella sbagliata sarebbe la prima che
    l'operatore vede. Lo script scrive il perimetro in un file temporaneo e
    lo installa solo se `ScopeAllowlist.carica` lo accetta.
    """
    esito = esegui(radice_finta, *completo(chiavi, **{"--reti": "192.0.2.0/255.255.255.0"}))
    assert esito.returncode == 0, esito.stderr
    # Forma canonica, non quella battuta.
    assert "192.0.2.0/24" in esito.stdout


# --- Le chiavi ------------------------------------------------------------- #


def test_la_chiave_dellamministratore_va_nella_sua_authorized_keys(
    radice_finta: Path, chiavi: Chiavi
):
    """Va messa prima del ricarico di sshd, o l'amministratore resta fuori.

    E il file deve essere del suo utente con modo 600: con un altro
    proprietario StrictModes lo ignora in silenzio, e il sintomo è lo stesso
    `Permission denied` di una chiave rotta.
    """
    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    ak = radice_finta / "home" / ".ssh" / "authorized_keys"
    assert f"{ak} (modo 600, di root:" in esito.stdout
    assert chiavi.admin in esito.stdout


def test_le_chiavi_gia_presenti_non_si_toccano(radice_finta: Path, chiavi: Chiavi):
    """Si aggiunge, non si sostituisce.

    Una authorized_keys può contenere chiavi che servono ad altro: cancellarle
    per installare la nostra chiuderebbe fuori qualcun altro, o noi stessi da
    un'altra postazione.
    """
    ssh = radice_finta / "home" / ".ssh"
    ssh.mkdir()
    preesistente = "ssh-ed25519 AAAApreesistente chiave@altra-postazione"
    (ssh / "authorized_keys").write_text(preesistente + "\n", encoding="utf-8")

    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert preesistente in esito.stdout
    assert chiavi.admin in esito.stdout


def test_una_chiave_gia_presente_non_si_aggiunge_due_volte(
    radice_finta: Path, chiavi: Chiavi
):
    ssh = radice_finta / "home" / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text(chiavi.admin + "\n", encoding="utf-8")

    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert "già presente" in esito.stdout


def test_una_chiave_spezzata_dallincollata_viene_rifiutata(
    radice_finta: Path, chiavi: Chiavi
):
    """Il guasto del collaudo: il terminale consegna solo la prima riga.

    Il validatore di prima la accettava — una riga sola, inizia con
    `ssh-ed25519` — e finiva in authorized_keys. Al passo di verifica arrivava
    un `Permission denied (publickey)` che non nominava la causa, e ci sono
    volute quattro diagnosi per trovarla. `ssh-keygen -l` la rifiuta.
    """
    spezzata = chiavi.admin[:50]
    esito = esegui(radice_finta, *completo(chiavi, **{"--chiave-admin": spezzata}))
    assert esito.returncode != 0
    assert "spezzata o incompleta" in uscita(esito)


def test_una_chiave_con_un_carattere_in_meno_viene_rifiutata(
    radice_finta: Path, chiavi: Chiavi
):
    tipo, blob, commento = chiavi.servizio.split(" ", 2)
    mutila = f"{tipo} {blob[:-1]} {commento}"
    esito = esegui(radice_finta, *completo(chiavi, **{"--chiave": mutila}))
    assert esito.returncode != 0
    assert "spezzata o incompleta" in uscita(esito)


def test_le_chiavi_scambiate_vengono_rifiutate(radice_finta: Path, chiavi: Chiavi):
    """Stessa forma, stessa lunghezza: l'unico appiglio è il commento.

    Con le chiavi scambiate, la chiave del servizio — quella con il comando
    vincolato — finirebbe nella authorized_keys dell'amministratore, e la sua
    nel canale del servizio.
    """
    esito = esegui(
        radice_finta,
        *completo(chiavi, **{"--chiave-admin": str(chiavi.servizio_file),
                             "--chiave": str(chiavi.admin_file)}),
    )
    assert esito.returncode != 0
    assert "è la chiave del SERVIZIO" in uscita(esito)


def test_la_stessa_chiave_due_volte_viene_rifiutata(
    radice_finta: Path, chiavi: Chiavi, tmp_path: Path
):
    """Anche quando il commento non aiuta, il blob sì."""
    neutra = tmp_path / "neutra.pub"
    tipo, blob, _ = chiavi.admin.split(" ", 2)
    neutra.write_text(f"{tipo} {blob} senza-indizi\n", encoding="utf-8")

    esito = esegui(
        radice_finta,
        *completo(chiavi, **{"--chiave-admin": str(neutra), "--chiave": str(neutra)}),
    )
    assert esito.returncode != 0
    assert "devono essere diverse" in uscita(esito)


def test_un_ssh_che_e_un_link_simbolico_viene_rifiutato(
    radice_finta: Path, chiavi: Chiavi, tmp_path: Path
):
    """Da root, seguire il link vorrebbe dire scrivere dove punta.

    Cioè dove ha deciso chi l'ha creato. Lo script scrive nella home di un
    altro utente con i privilegi di root: un link al posto di ~/.ssh è
    esattamente il modo di dirottare quella scrittura.
    """
    altrove = tmp_path / "altrove"
    altrove.mkdir()
    (radice_finta / "home" / ".ssh").symlink_to(altrove)

    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode != 0
    assert "link simbolico" in uscita(esito)


def test_un_allowusers_con_un_utente_inesistente_lo_dice_adesso(
    radice_finta: Path, chiavi: Chiavi
):
    """Meglio scoprirlo qui che al ricarico di sshd.

    Un AllowUsers compilato a mano prima che questo script lo validasse può
    nominare un utente che sulla macchina non c'è: con le password spente,
    quello è un lockout.
    """
    (radice_finta / "sshd" / "09-hermes-allowusers.conf").write_text(
        "AllowUsers nessun-utente-cosi hermes\n", encoding="utf-8"
    )
    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode != 0
    assert "non esiste su questa macchina" in uscita(esito)


def test_una_chiave_privata_incollata_per_sbaglio_viene_rifiutata(
    radice_finta: Path, chiavi: Chiavi, tmp_path: Path
):
    """Il refuso più caro: la privata al posto della pubblica."""
    privata = tmp_path / "finta_privata"
    privata.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    esito = esegui(radice_finta, *completo(chiavi, **{"--chiave": str(privata)}))
    assert esito.returncode != 0
    assert "una riga sola" in uscita(esito)


def test_una_chiave_senza_forma_di_chiave_viene_rifiutata(
    radice_finta: Path, chiavi: Chiavi
):
    esito = esegui(radice_finta, *completo(chiavi, **{"--chiave": "questa non è una chiave"}))
    assert esito.returncode != 0
    assert "forma di una chiave pubblica" in uscita(esito)


# --- Gli altri rifiuti ----------------------------------------------------- #


def test_un_utente_inesistente_viene_rifiutato(radice_finta: Path, chiavi: Chiavi):
    """Un refuso nel nome passa `sshd -t`, passa il preflight, e chiude fuori."""
    esito = esegui(radice_finta, *completo(chiavi, **{"--utente": "nessun-utente-cosi"}))
    assert esito.returncode != 0
    assert "non esiste su questa macchina" in uscita(esito)


def test_un_utente_di_servizio_viene_rifiutato(radice_finta: Path, chiavi: Chiavi):
    """`hermes` è già in elenco: qui va l'amministratore, non il servizio."""
    esito = esegui(radice_finta, *completo(chiavi, **{"--utente": "hermes"}))
    assert esito.returncode != 0
    assert "utente di servizio" in uscita(esito)


def test_un_host_al_posto_di_una_rete_viene_rifiutato(radice_finta: Path, chiavi: Chiavi):
    """`192.0.2.1/24` non è una rete: è un host dentro una rete.

    Accettarlo e correggerlo in silenzio darebbe un perimetro diverso da
    quello che l'operatore crede di aver scritto — e in un verso che allarga.
    """
    esito = esegui(radice_finta, *completo(chiavi, **{"--reti": "192.0.2.1/24"}))
    assert esito.returncode != 0
    assert "host bits set" in uscita(esito).lower()


def test_un_alias_fuori_dalle_reti_viene_rifiutato(radice_finta: Path, chiavi: Chiavi):
    """Un bersaglio che il gate rifiuterebbe, dichiarato come ammesso."""
    esito = esegui(radice_finta, *completo(chiavi, **{"--alias": "altrove=198.51.100.15"}))
    assert esito.returncode != 0
    assert "non è in nessuna delle reti" in uscita(esito)


def test_una_interfaccia_inesistente_viene_rifiutata(radice_finta: Path, chiavi: Chiavi):
    """Un nome sbagliato produce un netplan valido che non configura niente."""
    esito = esegui(
        radice_finta, *completo(chiavi),
        "--interfaccia", "inesistente0", "--indirizzo", "192.0.2.10/24",
    )
    assert esito.returncode != 0
    assert "non esiste" in uscita(esito)


def test_un_indirizzo_senza_prefisso_viene_rifiutato(radice_finta: Path, chiavi: Chiavi):
    esito = esegui(
        radice_finta, *completo(chiavi), "--interfaccia", "lo", "--indirizzo", "192.0.2.10"
    )
    assert esito.returncode != 0
    assert "lunghezza del prefisso" in uscita(esito)


# --- Il blocco Host del passo 7 ------------------------------------------- #


def test_il_blocco_host_esce_compilato_con_i_valori_veri(
    radice_finta: Path, chiavi: Chiavi
):
    """L'ultimo segnaposto della procedura lo scrive chi conosce i valori.

    Nome, indirizzo e utente sono tre valori che la macchina sa e la persona
    deve ricordare — e l'indirizzo cambia a metà procedura, dal DHCP a quello
    fisso. Nel collaudo un segnaposto `INDIRIZZO` usato per entrambi ha
    confuso chi installava.
    """
    esito = esegui(
        radice_finta, *completo(chiavi), "--interfaccia", "lo", "--indirizzo", "192.0.2.10/24"
    )
    assert esito.returncode == 0, esito.stderr
    nome = platform.node()
    assert f"Host {nome}" in esito.stdout
    assert "HostName 192.0.2.10" in esito.stdout
    assert "User root" in esito.stdout
    assert f"IdentityFile ~/.ssh/id_ed25519_{nome}_admin" in esito.stdout
    assert "IdentitiesOnly yes" in esito.stdout


def test_senza_indirizzo_fisso_il_blocco_host_lo_dice(radice_finta: Path, chiavi: Chiavi):
    """Un segnaposto, ma uno che si dichiara tale e dice cosa metterci."""
    esito = esegui(radice_finta, *completo(chiavi))
    assert esito.returncode == 0, esito.stderr
    assert "HostName INDIRIZZO-DELLA-VM" in esito.stdout
    assert "Nessun indirizzo fisso configurato" in esito.stdout


# --- Non interattivo ------------------------------------------------------- #


def test_senza_terminale_un_valore_mancante_nomina_la_sua_opzione(
    radice_finta: Path, chiavi: Chiavi
):
    """Non si aspetta un umano che non c'è."""
    esito = esegui(radice_finta, "--chiave", str(chiavi.servizio_file))
    assert esito.returncode != 0
    assert "--utente" in uscita(esito)


# --- Invarianti ------------------------------------------------------------ #


def test_non_ricarica_sshd_e_non_tocca_le_regole_aperte():
    """Le azioni irreversibili restano all'operatore.

    Ricaricare `sshd` con un AllowUsers sbagliato, o cancellare la regola
    aperta della 22 con un indirizzo sbagliato, producono lo stesso esito: una
    macchina remota che non si raggiunge più. Si guarda che non vengano
    ESEGUITE: le stesse parole compaiono di proposito nei promemoria.
    """
    righe = SCRIPT.read_text(encoding="utf-8").splitlines()
    eseguite = [
        r.strip()
        for r in righe
        if r and not r.lstrip().startswith("#") and not r.startswith((" ", "\t"))
    ]
    for proibito in ("systemctl", "ufw delete", "netplan try", "netplan apply"):
        assert not [r for r in eseguite if r.startswith(proibito)], proibito


def test_ogni_valore_dice_da_dove_ricavarlo():
    """Ogni domanda ha il suo comando per andare a guardare, come «prova».

    Un comando presentato come definitivo diventa un valore incollato senza
    riletture: il nome utente in AllowUsers e la rete nel modello del
    perimetro sono arrivati dove sono arrivati esattamente così.
    """
    script = SCRIPT.read_text(encoding="utf-8")

    assert "prova:" in script
    for comando in (
        "$SUDO_USER",               # utente amministrativo
        "id_ed25519_${VM}_admin",   # la sua chiave, sulla postazione
        "id_ed25519_hermes_$VM",    # quella del servizio
        "route show scope link",    # reti del perimetro
        "ip neigh",                 # candidati per gli alias
        "$SSH_CONNECTION",          # indirizzo della postazione
        "ip -br a",                 # interfaccia e indirizzo
    ):
        assert comando in script, comando

    assert script.count("suggerimento ") >= 8


SPECIFICI_DI_LABORATORIO = (
    "192.168.", "10.0.2.", "enp0s", "ens33", "VMnet", "hermesmcp", "@windows",
)


def _distribuiti():
    """Ciò che arriva a chi installa: tutto tranne i test e git.

    I test restano fuori di proposito: lì un indirizzo privato è un dato di
    prova, non un esempio che qualcuno copierà in una configurazione.
    """
    for percorso in sorted(RADICE.rglob("*")):
        relativo = percorso.relative_to(RADICE)
        if not percorso.is_file() or relativo.parts[0] in {
            ".git", "tests", ".venv", ".pytest_cache",
        } or "__pycache__" in relativo.parts:
            continue
        try:
            yield relativo, percorso.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


def test_il_repo_non_contiene_riferimenti_a_un_laboratorio_specifico():
    """Una cassetta degli attrezzi portabile non porta il nome di chi l'ha fatta.

    Gli esempi stanno nelle reti riservate alla documentazione (RFC 5737): un
    esempio copiato per sbaglio in un perimetro non autorizza niente di reale.
    Una rete di laboratorio vera, invece, sì — ed è già successo, con il
    modello del perimetro, e di nuovo con il collector della spedizione.
    """
    trovati = [
        f"{relativo}: {specifico}"
        for relativo, testo in _distribuiti()
        for specifico in SPECIFICI_DI_LABORATORIO
        if specifico in testo
    ]
    assert not trovati, "\n".join(trovati)


def test_i_percorsi_coincidono_con_quelli_del_bootstrap():
    """Dove la copia è inevitabile, la coincidenza va verificata."""
    configura = SCRIPT.read_text(encoding="utf-8")
    bootstrap = (RADICE / "bin" / "hermes-bootstrap").read_text(encoding="utf-8")

    for atteso in ("09-hermes-allowusers.conf", "10-hermes.conf", "scope.toml", "DA_COMPILARE"):
        assert atteso in configura, atteso
        assert atteso in bootstrap, atteso


def test_riscrivere_il_perimetro_conserva_i_prefissi_di_percorso(
    radice_finta: Path, chiavi: Chiavi
):
    """I prefissi non li chiede questo script, ma riscrivendo li perdeva.

    Il perimetro si riscrive per cambiare le reti; i `percorsi` li aggiunge
    l'operatore a mano. Perderli in silenzio darebbe a un tool di tipo
    percorso un perimetro che nessuno ha deciso di restringere, scoperto al
    primo uso. E il riepilogo di ciò che c'era prima mostrava i prefissi come
    se fossero reti.
    """
    (radice_finta / "hermes" / "scope.toml").write_text(
        'reti = [\n    "198.51.100.0/24",\n]\n'
        'percorsi = [\n    "/srv/lab/campioni",\n    "/srv/lab/esiti",\n]\n\n[alias]\n',
        encoding="utf-8",
    )
    esito = esegui(radice_finta, *completo(chiavi), "--forza")
    testo = uscita(esito)
    assert esito.returncode == 0, testo
    generato = testo[testo.index("scope.toml (modo"):]
    generato = generato[: generato.index("--->8---")]
    assert '"/srv/lab/campioni",' in generato
    assert '"/srv/lab/esiti",' in generato
    assert generato.index("percorsi = [") < generato.index("[alias]")
    assert '"192.0.2.0/24",' in generato
