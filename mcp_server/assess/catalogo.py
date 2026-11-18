"""Il catalogo delle minacce di ``hermes-assess``.

Una voce del catalogo non è un controllo: è la **dichiarazione** di una
minaccia, di ciò che si tenterà per vedere se la difesa regge e di ciò che
deve riuscire perché quel tentativo provi qualcosa. Le implementazioni delle
prove arrivano in M1 e si agganciano per ``id``; la dichiarazione viene prima,
ed è versionata qui, perché una prova di cui non si è scritto cosa deve
dimostrare finisce per dimostrare ciò che le riesce.

Due nature, e la differenza è il punto
--------------------------------------

* :attr:`Natura.TENTATIVO` — si esegue l'operazione vietata, sotto l'identità
  o nel montaggio in cui deve fallire. **Ha sempre un controllo positivo**: la
  stessa sonda, nella condizione in cui deve riuscire. Un «non si apre» non
  prova niente se il file non si aprirebbe comunque: è la regola di
  ``bin/hermes-collauda-percorsi``, estesa a tutto il catalogo. Se il
  controllo positivo fallisce, l'esito è *non verificabile*, mai *tiene*.
* :attr:`Natura.MISURA` — si interroga l'oggetto stesso (``sshd -T``,
  ``sudo -l``, il log), perché non c'è un'operazione da tentare o perché
  tentarla sarebbe irreversibile. Deve **dire perché** non è un tentativo: una
  misura che potrebbe essere un tentativo è un controllo del preflight
  travestito.

Una prova *indiretta* è un tentativo fatto su un'esca, non sul bersaglio vero,
perché sul bersaglio vero il tentativo distruggerebbe ciò che la difesa
protegge se la difesa mancasse (troncare il log per vedere se ``+a`` lo
impedisce). Il referto la dichiara tale.

Il catalogo è il solo posto in cui le minacce sono elencate: ``docs/assess.md``
non lo ripete, e ``tests/test_assess_catalogo.py`` pretende che ogni voce sia
completa.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcp_server.contracts import Severity, TargetKind


class Natura(StrEnum):
    TENTATIVO = "tentativo"
    MISURA = "misura"


class Copertura(StrEnum):
    """Da dove guarda la prova, e quindi chi potrebbe falsificarne l'esito.

    ``LOCALE``: eseguita sull'host sorvegliato. Un root compromesso può
    mentire a qualunque prova locale, e il referto lo dice in testa invece di
    lasciarlo dedurre. ``ESTERNA``: eseguita da un'altra macchina (M3).
    """

    LOCALE = "locale"
    ESTERNA = "esterna"


#: Condizione di applicabilità di una minaccia che si applica sempre.
SEMPRE = "sempre"


@dataclass(frozen=True, slots=True)
class Minaccia:
    """Una voce del catalogo. Tutti i campi testuali sono obbligatori."""

    id: str
    #: Cosa succede se la difesa cede, formulato dal lato dell'attaccante.
    titolo: str
    #: Da dove viene: finding della security review (``HC-04``), debolezza
    #: architetturale (``A1``), difetto del collaudo (``D-21``), decisione di
    #: progetto (``decisione 7``).
    origine: tuple[str, ...]
    natura: Natura
    #: Cosa si fa. Per un tentativo: l'operazione che **deve fallire**.
    prova: str
    #: Per un tentativo: cosa **deve riuscire** perché il fallimento provi
    #: qualcosa. ``None`` per una misura.
    controllo_positivo: str | None
    #: Per una misura: perché non è un tentativo. ``None`` per un tentativo.
    perche_misura: str | None
    #: ``SEMPRE``, oppure la condizione sulla configurazione.
    applicabile_se: str
    gravita: Severity
    #: Cosa lascia sulla macchina. «nessuno» va scritto, non sottinteso.
    effetti: str
    #: Il rimedio deterministico: scritto e collaudato insieme alla prova.
    #: Uno strato agentico lo può spiegare, non sostituire.
    rimedio: str
    copertura: Copertura = Copertura.LOCALE
    indiretta: bool = False
    #: Titolo esatto di una voce aperta o accettata di
    #: ``docs/debito-sicurezza.md`` che descrive già questo cedimento.
    #: Contro una voce ACCETTATA un cedimento è *accettato*; contro una voce
    #: aperta resta un cedimento, con il rimando.
    debito: str | None = None
    #: I tipi di bersaglio il cui perimetro questa minaccia esercita.
    target_kind: frozenset[TargetKind] = frozenset()


CATALOGO: tuple[Minaccia, ...] = (
    Minaccia(
        id="AS-01",
        titolo="Il servizio si auto-autorizza in SSH: si toglie il comando "
        "vincolato o aggiunge una propria chiave",
        origine=("HC-04",),
        natura=Natura.TENTATIVO,
        prova="Come utente di servizio: aprire in scrittura il proprio file "
        "in /etc/ssh/authorized_keys.d/ e verificare la creabilità di ~/.ssh "
        "nella propria home. Da `sshd -T -C user=<servizio>`: forcecommand "
        "presente, permituserrc no, authorizedkeysfile fuori dalla home.",
        controllo_positivo="La stessa apertura da root riesce.",
        perche_misura=None,
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="nessuno: le aperture non scrivono, e la creabilità di una "
        "directory si prova con O_TMPFILE, che non lascia nomi",
        rimedio="Drop-in di sshd e chiavi di root come in "
        "docs/setup-vm-hermes.md §4.1–4.2; `bin/hermes-bootstrap` reinstalla "
        "il drop-in.",
    ),
    Minaccia(
        id="AS-02",
        titolo="Codice non verificato gira prima dello script: un .pth, uno "
        "user site, un modulo omonimo",
        origine=("HC-03",),
        natura=Natura.TENTATIVO,
        prova="Il canary riporta dall'interno sys.flags.isolated, "
        "sys.flags.no_site e un sys.path senza user site. Come utente dei tool "
        "e come utente di servizio: creabilità nello user site e nella home. "
        "Ricerca di file .pth nei site-packages di tool_python e del venv, "
        "confrontati con l'elenco generato dal lock all'installazione.",
        controllo_positivo="La creabilità nella directory temporanea della "
        "prova riesce, sotto le stesse identità.",
        perche_misura=None,
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="nessuno: creabilità con O_TMPFILE, ricerca in sola lettura",
        rimedio="tool_python assoluto e tool_python_flags = [\"-I\", \"-S\"] "
        "in config/hermes.example.toml; permessi della home in "
        "docs/setup-vm-hermes.md §2.",
    ),
    Minaccia(
        id="AS-03",
        titolo="Un tool raggiunge i file del servizio: legge config e vault, "
        "scrive righe false nella traccia che lo registra",
        origine=("A1",),
        natura=Natura.TENTATIVO,
        prova="Dal wrapper installato, nell'unità normale (la meno ristretta "
        "in cui un tool può girare), come utente dei tool: lettura della "
        "configurazione e dello store degli override, apertura in scrittura "
        "del log d'audit, creabilità in state_dir. Non dal canary: per sapere "
        "dove stanno quei file dovrebbe leggere la configurazione, cioè fare "
        "ciò che la prova deve dimostrare impossibile.",
        controllo_positivo="Le stesse operazioni come utente di servizio "
        "riescono.",
        perche_misura=None,
        applicabile_se="server.tool_runner configurato, esecuzione da root",
        gravita=Severity.HIGH,
        effetti="due unità transienti per file, terminate e rimosse; le "
        "aperture non scrivono",
        rimedio="Permessi di log e state_dir come in docs/setup-vm-hermes.md "
        "§3, «Le directory scrivibili dal servizio»; il preflight nomina il "
        "comando.",
    ),
    Minaccia(
        id="AS-04",
        titolo="Il log d'audit o lo store degli override si possono troncare "
        "o riscrivere",
        origine=("A5",),
        natura=Natura.TENTATIVO,
        prova="Attributo append-only letto sul log e sullo store veri. Come "
        "utente di servizio: troncamento e riscrittura di un'esca con lo "
        "stesso attributo, nella stessa directory.",
        controllo_positivo="Le stesse operazioni sull'esca senza attributo "
        "riescono.",
        perche_misura=None,
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="un'esca creata e rimossa nella directory del log",
        rimedio="`sudo chattr +a` su log e store dopo il primo avvio: "
        "docs/setup-vm-hermes.md §7, «Rendere log e store non riscrivibili».",
        indiretta=True,
    ),
    Minaccia(
        id="AS-05",
        titolo="Un'esecuzione avviene senza traccia completa nel log",
        origine=("HC-01", "HC-07"),
        natura=Natura.MISURA,
        prova="Dopo un'invocazione del canary lungo la catena vera: le righe "
        "agent_invoked, tool_call e agent_result con lo stesso "
        "correlation_id, e il manifesto nel log uguale a quello ricalcolato "
        "sulla directory degli esiti.",
        controllo_positivo=None,
        perche_misura="La prova è positiva: si esegue un'invocazione "
        "legittima e si misura la traccia che lascia. Non c'è un'operazione "
        "vietata da tentare.",
        applicabile_se="assess.canary registrato per l'agente dell'istanza",
        gravita=Severity.MEDIUM,
        effetti="un'invocazione del canary: righe nel log e una directory di "
        "esiti, come qualunque invocazione",
        rimedio="Un cedimento qui è un difetto del server, non della "
        "configurazione: va aperta una issue con le righe di log citate dal "
        "referto.",
    ),
    Minaccia(
        id="AS-06",
        titolo="Il perimetro dei bersagli di rete non regge: un tool parte "
        "verso un bersaglio non autorizzato",
        origine=("A2", "decisione 7"),
        natura=Natura.TENTATIVO,
        prova="assess.canary, che dichiara target_kind none, invocato con un "
        "bersaglio → denied. assess.canary_host invocato su 192.0.2.1, fuori "
        "perimetro → denied. Il canary non apre connessioni: se il gate "
        "cedesse, partirebbe uno script che stampa il bersaglio.",
        controllo_positivo="assess.canary_host invocato su un alias dentro il "
        "perimetro, o sul primo indirizzo della prima rete se non ci sono "
        "alias → ok.",
        perche_misura=None,
        applicabile_se="server.scope_file configurato, assess.canary e "
        "assess.canary_host registrati per l'agente dell'istanza",
        gravita=Severity.HIGH,
        effetti="tre invocazioni dei canary, registrate nel log",
        rimedio="Un cedimento qui è un difetto del gate: va aperta una issue. "
        "Il perimetro si configura come in docs/setup-vm-hermes.md §5.",
        target_kind=frozenset({TargetKind.NONE, TargetKind.HOST}),
    ),
    Minaccia(
        id="AS-07",
        titolo="Un tier innalzato torna basso a una connessione nuova",
        origine=("HC-02",),
        natura=Natura.MISURA,
        prova="Due processi server distinti riportano, con describe_tool, lo "
        "stesso tier effettivo per ogni tool, uguale al massimo fra tier "
        "dichiarato, override_tier e store.",
        controllo_positivo=None,
        perche_misura="Il tentativo sarebbe alzare un tier e riconnettersi, "
        "ma un innalzamento è irreversibile dall'interfaccia: si confrontano "
        "due processi senza alzare niente.",
        applicabile_se="server.state_dir configurata",
        gravita=Severity.MEDIUM,
        effetti="due avvii del server, registrati nel log",
        rimedio="state_dir configurata e scrivibile dal servizio: "
        "config/hermes.example.toml, commento di state_dir.",
    ),
    Minaccia(
        id="AS-08",
        titolo="L'unità non contiene il tool: un processo sopravvive alla "
        "fine dell'unità, o la memoria oltre il tetto va in swap",
        origine=("A1",),
        natura=Natura.TENTATIVO,
        prova="Dal wrapper installato, con due sonde: una avvia un processo "
        "nipote ed esce, l'altra alloca oltre MemoryMax. Il nipote non deve "
        "sopravvivere all'unità, l'allocazione deve far terminare la sonda.",
        controllo_positivo="Un'allocazione sotto il tetto, nella stessa "
        "unità, riesce.",
        perche_misura=None,
        applicabile_se="server.tool_runner configurato",
        gravita=Severity.MEDIUM,
        effetti="tre unità transienti, terminate e rimosse",
        rimedio="Il wrapper installato aggiornato: docs/setup-vm-hermes.md "
        "§6.2.",
        debito="MEDIA — i tetti di risorsa dei tool non sono calibrati",
    ),
    Minaccia(
        id="AS-09",
        titolo="Un tool apre connessioni verso destinazioni fuori perimetro",
        origine=("A2",),
        natura=Natura.TENTATIVO,
        prova="Dal canary, connessione TCP a un listener che hermes-assess "
        "apre su 127.0.0.2, indirizzo fuori perimetro.",
        controllo_positivo="La stessa connessione da root riesce.",
        perche_misura=None,
        applicabile_se="server.tool_runner configurato",
        gravita=Severity.MEDIUM,
        effetti="un listener su loopback per la durata della prova: nessun "
        "pacchetto lascia la macchina",
        rimedio="Voce aperta nel registro del debito "
        "(docs/debito-sicurezza.md): regola nftables con meta skuid "
        "generata dal file di perimetro.",
        debito="MEDIA — il traffico dei tool non è confinato a livello di rete",
    ),
    Minaccia(
        id="AS-10",
        titolo="La superficie esposta è più larga di quella dichiarata",
        origine=("HC-04",),
        natura=Natura.MISURA,
        prova="Porte in ascolto confrontate con l'atteso; regole effettive di "
        "ufw (la 22 raggiungibile da qualunque sorgente); da `sshd -T`: "
        "autenticazione a password, accesso di root, keyboard-interactive, "
        "algoritmi deboli; drop-in che precedono il nostro.",
        controllo_positivo=None,
        perche_misura="sshd -T e le regole caricate sono l'interrogazione "
        "dell'oggetto stesso. Un tentativo di connessione da questa macchina "
        "vedrebbe il loopback, non la rete: la vista dall'esterno è una prova "
        "del collector.",
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="nessuno",
        rimedio="docs/setup-vm-hermes.md §4.3 per ufw, §4.2 per il drop-in "
        "e l'ordine dei drop-in.",
    ),
    Minaccia(
        id="AS-11",
        titolo="Un utente di servizio ha privilegi sudo oltre l'unica riga "
        "concessa",
        origine=("A1",),
        natura=Natura.MISURA,
        prova="`sudo -l -U` per ogni utente di servizio: l'unica regola "
        "ammessa è quella del wrapper. Il file installato confrontato con "
        "config/sudoers.example.",
        controllo_positivo=None,
        perche_misura="sudo -l chiede a sudo la regola che applicherebbe: è "
        "la stessa decisione che prenderebbe all'uso, senza eseguire niente.",
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="nessuno",
        rimedio="config/sudoers.example, installato come descritto nel suo "
        "commento; docs/setup-vm-hermes.md §6.3.",
    ),
    Minaccia(
        id="AS-12",
        titolo="Il codice privilegiato installato è stato sostituito o è "
        "modificabile dal servizio",
        origine=("decisione 14",),
        natura=Natura.TENTATIVO,
        prova="Wrapper, mittente e ricevente installati: proprietario root e "
        "contenuto uguale alla versione del commit. Come utente di servizio: "
        "apertura in scrittura di ciascuno, e degli script dei tool "
        "registrati.",
        controllo_positivo="La stessa apertura da root riesce.",
        perche_misura=None,
        applicabile_se="almeno uno dei tre installato",
        gravita=Severity.HIGH,
        effetti="nessuno: le aperture non scrivono",
        rimedio="`bin/hermes-bootstrap` reinstalla wrapper e mittente; "
        "docs/setup-vm-hermes.md §6.2 e §10.",
    ),
    Minaccia(
        id="AS-13",
        titolo="Un'identità di servizio è usabile per entrare o per "
        "persistere",
        origine=("A1",),
        natura=Natura.MISURA,
        prova="Per ogni utente di servizio: shell (nologin dove atteso), "
        "password bloccata, appartenenza a gruppi privilegiati (sudo, adm, "
        "docker, lxd), crontab, unità systemd utente, linger.",
        controllo_positivo=None,
        perche_misura="passwd, shadow e lo stato di logind sono le fonti che "
        "login, sshd e systemd consultano: interrogarle è riprodurre la loro "
        "decisione.",
        applicabile_se=SEMPRE,
        gravita=Severity.HIGH,
        effetti="nessuno",
        rimedio="docs/setup-vm-hermes.md §2 e §6.1.",
    ),
    Minaccia(
        id="AS-14",
        titolo="La traccia nel log è incoerente: esecuzioni senza esito, "
        "catene mescolate, tempo che torna indietro",
        origine=("HC-01", "HC-07"),
        natura=Natura.MISURA,
        prova="Scansione dell'intero log d'audit: catene agent_invoked senza "
        "tool_call, correlation_id riusati fra catene distinte, timestamp "
        "che decrescono fra righe consecutive.",
        controllo_positivo=None,
        perche_misura="La traccia è il dato stesso: non c'è un'operazione da "
        "tentare.",
        applicabile_se=SEMPRE,
        gravita=Severity.MEDIUM,
        effetti="nessuno",
        rimedio="Le righe citate dal referto vanno confrontate con la copia "
        "sul collector (docs/setup-vm-hermes.md §10) prima di concludere.",
    ),
    Minaccia(
        id="AS-15",
        titolo="L'orologio è sbagliato: le righe del log non sono correlabili "
        "con nessun'altra fonte",
        origine=("D-21",),
        natura=Natura.MISURA,
        prova="Lo stato di sincronizzazione dello strumento NTP in uso, letto "
        "come lo legge il preflight.",
        controllo_positivo=None,
        perche_misura="Si chiede allo strumento che corregge l'orologio: non "
        "c'è un'operazione da tentare.",
        applicabile_se=SEMPRE,
        gravita=Severity.LOW,
        effetti="nessuno",
        rimedio="Il rimedio che il preflight stampa per lo strumento NTP "
        "rilevato.",
    ),
    Minaccia(
        id="AS-16",
        titolo="Una dipendenza o un pacchetto di sistema ha una vulnerabilità "
        "nota",
        origine=("HC-05",),
        natura=Natura.MISURA,
        prova="Sul server: inventario del lock, del venv, dei pacchetti di "
        "sistema, di OpenSSH e di Python. Sul PC: pip-audit e consultazione "
        "OSV contro l'inventario. Il server non usa la rete.",
        controllo_positivo=None,
        perche_misura="È una consultazione di advisory: non c'è "
        "un'operazione da tentare.",
        applicabile_se=SEMPRE,
        gravita=Severity.MEDIUM,
        effetti="nessuno sul server: l'inventario si copia sul PC",
        rimedio="Aggiornamento del lock come in docs/dipendenze.md; per i "
        "pacchetti di sistema, apt.",
    ),
    Minaccia(
        id="AS-17",
        titolo="Il perimetro dei percorsi non confina: un tool legge fuori "
        "dai prefissi ammessi",
        origine=("A2",),
        natura=Natura.TENTATIVO,
        prova="Nell'unità ristretta ai prefissi del perimetro, come utente "
        "dei tool: lettura di un file fuori dai prefissi.",
        controllo_positivo="La stessa lettura, stesso utente e stesso file, "
        "nell'unità normale riesce.",
        perche_misura=None,
        applicabile_se="un tool con target_kind = \"path\" registrato",
        gravita=Severity.HIGH,
        effetti="un file creato e rimosso in /var/lib, come fa "
        "bin/hermes-collauda-percorsi",
        rimedio="Wrapper installato aggiornato e prefissi nel file di "
        "perimetro: docs/setup-vm-hermes.md §5, «I bersagli di tipo "
        "percorso».",
        target_kind=frozenset({TargetKind.PATH}),
    ),
)


def per_id() -> dict[str, Minaccia]:
    return {m.id: m for m in CATALOGO}


__all__ = ["CATALOGO", "SEMPRE", "Copertura", "Minaccia", "Natura", "per_id"]
