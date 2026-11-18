"""Lo schema del referto di ``hermes-assess``.

Il referto è ciò che esce da un giro: va letto dall'operatore, copiato sul PC
e, in M4, letto da uno strato agentico. Per questo due regole stanno qui e
non nelle prove, che sono molte e cambieranno:

**I dati raccolti dalla macchina non sono fidati.** Un nome di file, un nome
di unità, una riga di log li può scegliere chi ha già messo piede sulla
macchina. Ogni campo che li porta passa da :func:`dato_non_fidato`, che
toglie i caratteri di controllo e mette un tetto alla lunghezza, ed è
applicato nella costruzione dell':class:`Evidenza`, non al momento della
stampa: un invariante che si applica «quando ci si ricorda» non è un
invariante. Un a-capo in un referto è una riga che nessuno ha scritto; un
carattere di direzione bidirezionale è un testo che si legge diverso da come
è memorizzato; e un testo libero lungo dentro il contesto di un modello è
un'istruzione candidata.

**I codici d'uscita sono distinti, non un massimo.** Ogni codice dice una
cosa sola. Prendere il massimo numerico fra esiti diversi è un errore già
pagato: abbassava il codice a un canale divergente.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import asdict, dataclass, field
from enum import IntEnum, StrEnum

from mcp_server.contracts import Severity

#: Versione dello schema. Cambia quando cambia il significato di un campo,
#: non quando se ne aggiunge uno facoltativo.
SCHEMA = "hermes-assess/1"

#: Tetto di un campo di dato non fidato, in caratteri.
TETTO_NON_FIDATO = 512

_ORDINE_GRAVITA = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class EsitoProva(StrEnum):
    #: La difesa ha impedito l'operazione, e il controllo positivo è riuscito.
    TIENE = "tiene"
    #: L'operazione che doveva fallire è riuscita.
    CEDE = "cede"
    #: Il controllo positivo è fallito, o il fatto non si può leggere: la
    #: prova non dimostra niente in nessuna direzione.
    NON_VERIFICABILE = "non_verificabile"
    #: La condizione di applicabilità è falsa; la voce dice quale.
    NON_APPLICABILE = "non_applicabile"
    #: Ha ceduto, e il cedimento corrisponde a una voce ACCETTATA del
    #: registro del debito, citata.
    ACCETTATO = "accettato"


class CodiceUscita(IntEnum):
    #: Nessun cedimento, e nessuna minaccia alta rimasta non verificabile.
    NESSUN_CEDIMENTO = 0
    #: Almeno un cedimento non accettato.
    CEDIMENTI = 1
    #: Nessun cedimento, ma almeno una minaccia di gravità alta o critica
    #: che non si è potuta verificare: «non so» non è «tiene».
    ALTE_NON_VERIFICABILI = 2
    #: hermes-assess non ha potuto girare: non è un esito sulle difese.
    NON_ESEGUITO = 3


def gravita_almeno(valore: Severity, soglia: Severity) -> bool:
    return _ORDINE_GRAVITA[valore] >= _ORDINE_GRAVITA[soglia]


def _da_sostituire(carattere: str) -> bool:
    # Cc: controlli C0 e C1 (a-capo, escape, DEL…). Cf: formato, che include
    # i caratteri di direzione bidirezionale e quelli a larghezza zero.
    # Zl, Zp: separatori di riga e di paragrafo Unicode.
    return unicodedata.category(carattere) in {"Cc", "Cf", "Zl", "Zp"}


def dato_non_fidato(valore: object, tetto: int = TETTO_NON_FIDATO) -> str:
    """Una stringa raccolta dalla macchina, resa sicura da stampare e da far
    leggere a un modello.

    I caratteri di controllo diventano ``\\uXXXX`` visibili invece di
    sparire: un nome di file con un a-capo dentro è un'informazione, e
    toglierlo in silenzio farebbe sembrare normale un nome che non lo è. Oltre
    il tetto il valore è tagliato e il taglio è **dichiarato**.
    """
    testo = valore if isinstance(valore, str) else str(valore)
    pulito = "".join(
        f"\\u{ord(c):04x}" if _da_sostituire(c) else c for c in testo
    )
    if len(pulito) <= tetto:
        return pulito
    return f"{pulito[:tetto]}…[troncato: {len(pulito) - tetto} caratteri]"


@dataclass(frozen=True, slots=True)
class Evidenza:
    """Una singola operazione eseguita da una prova, e com'è andata."""

    #: Nome dell'operazione della sonda: ``apri_scrittura``, ``leggi``…
    operazione: str
    #: Utente sotto cui è stata eseguita, o ``unità ristretta`` e simili.
    identita: str
    #: Su cosa: un percorso, un indirizzo, un tool. Dato non fidato.
    oggetto: str
    riuscita: bool
    #: ``True`` se questa è l'operazione che doveva riuscire.
    controllo_positivo: bool = False
    #: errno, messaggio, riga di log. Dato non fidato.
    dettaglio: str = ""
    #: ``False`` se la sonda non ha risposto: wrapper che rifiuta, timeout,
    #: output illeggibile. Allora ``riuscita`` è falso ma **non** è un
    #: rifiuto dell'operazione, e una prova che lo contasse come tale
    #: direbbe *tiene* su una difesa che nessuno ha messo alla prova.
    eseguita: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "oggetto", dato_non_fidato(self.oggetto))
        object.__setattr__(self, "dettaglio", dato_non_fidato(self.dettaglio))


@dataclass(frozen=True, slots=True)
class Voce:
    """L'esito di una minaccia del catalogo in questo giro."""

    minaccia: str
    esito: EsitoProva
    gravita_base: Severity
    #: Gravità nel contesto di questa macchina: la base più i modificatori.
    gravita: Severity
    #: Un modificatore applicato è sempre scritto, con il motivo.
    modificatori: tuple[str, ...] = ()
    evidenze: tuple[Evidenza, ...] = ()
    #: Perché non applicabile, perché non verificabile, quale debito. Può
    #: riportare testo arrivato dalla catena — il ``summary`` di un risultato,
    #: il messaggio di un'eccezione — quindi è dato non fidato anche lei.
    nota: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "nota", dato_non_fidato(self.nota, 2 * TETTO_NON_FIDATO))


@dataclass(frozen=True, slots=True)
class VoceEsterna:
    """Una voce letta dal referto di uno strumento esterno (M1.5).

    Non è l'esito di una prova del catalogo: dice «lo strumento X segnala
    questo», non «questa difesa cede». Per questo sta in un elenco a parte e
    non entra nel codice d'uscita. Tutto ciò che viene dal file dello
    strumento è dato non fidato: il file sta sull'host sorvegliato.
    """

    #: Strumento e versione dichiarata nel suo referto, es. ``lynis 3.1.1``.
    origine: str
    #: Codice del test nello strumento, es. ``SSH-7408``.
    test: str
    #: ``avviso`` o ``suggerimento``, nella classificazione dello strumento.
    tipo: str
    messaggio: str
    dettaglio: str = ""
    soluzione: str = ""

    def __post_init__(self) -> None:
        for nome in ("origine", "test", "tipo", "messaggio", "dettaglio", "soluzione"):
            object.__setattr__(self, nome, dato_non_fidato(getattr(self, nome)))


@dataclass(frozen=True, slots=True)
class Referto:
    generato: str
    host: str
    config: str
    commit: str
    albero_pulito: bool
    voci: tuple[Voce, ...]
    #: Limiti del giro, in testa al referto: per esempio che ogni prova
    #: locale è falsificabile da root compromesso.
    limiti: tuple[str, ...] = ()
    #: Voci di strumenti esterni, separate dalle prove e fuori dal codice
    #: d'uscita.
    esterne: tuple[VoceEsterna, ...] = ()
    schema: str = field(default=SCHEMA)


def codice_uscita(voci: tuple[Voce, ...] | list[Voce]) -> CodiceUscita:
    """Il codice d'uscita di un giro completato.

    Un cedimento accettato non conta come cedimento. Una minaccia non
    verificabile conta solo se la sua gravità **nel contesto** è alta o
    critica: un «non so» su una minaccia bassa non deve rendere il giro
    rosso, uno su una minaccia alta non deve renderlo verde.
    """
    if any(v.esito is EsitoProva.CEDE for v in voci):
        return CodiceUscita.CEDIMENTI
    if any(
        v.esito is EsitoProva.NON_VERIFICABILE
        and gravita_almeno(v.gravita, Severity.HIGH)
        for v in voci
    ):
        return CodiceUscita.ALTE_NON_VERIFICABILI
    return CodiceUscita.NESSUN_CEDIMENTO


def in_json(referto: Referto) -> str:
    """Il referto serializzato. Solo ASCII, come il manifesto degli esiti."""
    return json.dumps(asdict(referto), ensure_ascii=True, indent=2)


__all__ = [
    "SCHEMA",
    "TETTO_NON_FIDATO",
    "CodiceUscita",
    "EsitoProva",
    "Evidenza",
    "Referto",
    "Voce",
    "VoceEsterna",
    "codice_uscita",
    "dato_non_fidato",
    "gravita_almeno",
    "in_json",
]
