"""Permessi effettivi di un percorso, maschera ACL compresa.

Perché questo modulo esiste
---------------------------

Tre scrittori — il log d'audit, lo store degli override, i posti di esecuzione
— impongono i permessi dei file che creano, e ciascuno aveva la propria copia
della stessa funzione. La regola del progetto dice che una regola resta vera
se c'è **un solo posto** che la applica: le tre copie si sono smentite appena
la regola è dovuta cambiare, che è il momento in cui ci si accorge della
duplicazione, cioè quando si è già sbagliato.

La regola è dovuta cambiare perché imporre un modo esatto **neutralizza
un'ACL POSIX**.

Il difetto, misurato
--------------------

Su un filesystem con ACL, i bit di gruppo di ``stat`` non sono i permessi del
gruppo proprietario: sono la **maschera**, cioè il tetto applicato a tutte le
voci nominate. Concedere a un utente la lettura di un file ``0600``::

    setfacl -m u:hermes-ship:r audit.jsonl

porta il modo a ``0640`` — la maschera ``r--`` letta nei bit di gruppo — e la
lettura funziona. Lo scrittore, trovando ``0640 != 0600``, faceva ``chmod
0600``: la maschera torna a zero, e con essa i permessi *effettivi* di ogni
voce nominata. Misurato::

    user:hermes-ship:r--        → lettura riuscita
    (dopo chmod 0600)
    user:hermes-ship:r--        #effective:---  → Permission denied

La voce **non viene rimossa**: resta elencata in ``getfacl`` e non funziona
più. È la forma, già censita nel metodo del progetto, del campo che mente —
chi verifica con ``getfacl`` vede un permesso che c'è e non vale, e il
sintomo non punta alla causa.

Due conseguenze, e la seconda è peggiore della prima: il modulo che *scrive*
il log disattivava in silenzio ogni accesso concesso a quel log, a ogni
avvio; e il preflight, vedendo ``0640``, suggeriva come rimedio proprio il
``chmod 600`` che rompe. Un controllo il cui rimedio disattiva un altro
controllo.

La regola nuova
---------------

Un'ACL estesa è una **concessione deliberata**, messa da chi amministra la
macchina: lo scrittore non ha l'autorità per annullarla. Quindi
:func:`restringi` tocca solo ciò che l'ACL non spiega — i bit di ``other``,
che sono permessi veri in entrambi i casi — e lascia stare i bit di gruppo
quando una maschera c'è davvero.

Chi legge davvero lo dice :func:`accesso`, che è ciò di cui il preflight ha
bisogno per riportare il vero invece di dedurlo dai bit: *«0640, ma i bit di
gruppo sono la maschera; oltre al proprietario legge hermes-ship»* è
un'informazione diversa da *«0640, leggibile da altri utenti»*, e solo una
delle due è corretta.

Il formato, misurato e non dedotto
----------------------------------

``system.posix_acl_access`` è un blob little-endian: ``uint32`` di versione
(vale 2), poi voci da 8 byte — ``uint16`` tag, ``uint16`` permessi,
``uint32`` id (``0xffffffff`` dove non si applica).

L'attributo **non esiste** quando l'ACL è minimale, cioè quando i permessi
sono esattamente i tre gruppi classici: ``getxattr`` fallisce con ``ENODATA``.
È il discriminatore pulito fra «questo file ha un'ACL» e «questo file ha solo
i bit», e non richiede di interpretare i bit per indovinarlo. Un filesystem
senza supporto risponde ``ENOTSUP``, che va trattato allo stesso modo —
nessuna ACL — e non come un guasto.

Si legge l'attributo invece di invocare ``getfacl`` per la stessa ragione per
cui la configurazione si parsa invece di eseguirla: un controllo di sicurezza
non dovrebbe dipendere dalla presenza di un binario esterno né dal formato
testuale della sua uscita.
"""

from __future__ import annotations

import errno
import grp
import os
import pwd
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

#: Attributo esteso che porta l'ACL d'accesso.
XATTR_ACL = "system.posix_acl_access"

#: Versione del blob che sappiamo leggere. Una diversa non si interpreta: si
#: dichiara sconosciuta, perché leggere male un'ACL è peggio che non leggerla.
_VERSIONE = 2

_TAG_USER_OBJ = 0x01
_TAG_USER = 0x02
_TAG_GROUP_OBJ = 0x04
_TAG_GROUP = 0x08
_TAG_MASK = 0x10
_TAG_OTHER = 0x20

#: Id presente nel blob dove non si applica.
_SENZA_ID = 0xFFFFFFFF

LETTURA = 0o4

#: Errori che significano «qui ACL non ce ne sono», non «qualcosa è rotto».
_NESSUNA_ACL = frozenset({errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP})


@dataclass(frozen=True, slots=True)
class Nominato:
    """Una voce d'ACL intestata a un utente o a un gruppo specifico."""

    tipo: str  # "utente" | "gruppo"
    nome: str
    permessi: int  # già filtrati dalla maschera: i permessi *effettivi*

    def __str__(self) -> str:
        return f"{self.tipo} {self.nome}"


@dataclass(frozen=True, slots=True)
class Accesso:
    """Chi può fare cosa su un percorso, oltre al proprietario.

    I permessi sono quelli **effettivi**: le voci nominate e il gruppo
    proprietario arrivano già filtrati dalla maschera, perché è il valore
    filtrato quello che il kernel applica — ed è l'unico che vale la pena
    riportare.
    """

    modo: int
    #: ``True`` se il percorso ha un'ACL oltre alle tre voci classiche. Quando
    #: è ``True`` i bit di gruppo di :attr:`modo` sono la maschera, non i
    #: permessi del gruppo proprietario.
    estesa: bool
    gruppo_proprietario: int
    altri: int
    nominati: tuple[Nominato, ...] = ()

    @property
    def lettori_nominati(self) -> tuple[Nominato, ...]:
        """Voci nominate che leggono davvero."""
        return tuple(n for n in self.nominati if n.permessi & LETTURA)

    @property
    def leggibile_oltre_il_proprietario(self) -> bool:
        """Vero se qualcuno che non sia il proprietario può leggere.

        Include le concessioni deliberate: serve a dire *se* qualcuno legge,
        non *se è un problema*. La differenza fra una concessione e una
        fuga la fa chi chiama, perché dipende da cosa è stato chiesto.
        """
        return bool(
            self.gruppo_proprietario & LETTURA
            or self.altri & LETTURA
            or self.lettori_nominati
        )

    def descrivi_lettori(self) -> str:
        """Elenco leggibile di chi legge oltre al proprietario."""
        voci = []
        if self.altri & LETTURA:
            voci.append("tutti")
        if self.gruppo_proprietario & LETTURA:
            voci.append("il gruppo proprietario")
        voci.extend(str(n) for n in self.lettori_nominati)
        return ", ".join(voci) if voci else "nessuno"


def leggi_acl(percorso: Path) -> tuple[tuple[int, int, int], ...] | None:
    """Legge e decodifica l'ACL d'accesso, o ``None`` se non ce n'è una.

    ``None`` copre tre casi che per chi chiama sono lo stesso: ACL minimale
    (``ENODATA``), filesystem senza supporto (``ENOTSUP``), versione del blob
    che non sappiamo leggere. In tutti e tre i bit del modo sono i permessi
    veri, che è l'unica cosa che il chiamante deve sapere.

    Un blob troncato o di versione ignota **non viene interpretato**: una
    lettura parziale di un'ACL produrrebbe un elenco plausibile e sbagliato,
    che è esattamente la forma di guasto che questo progetto insegue.
    """
    try:
        blob = os.getxattr(percorso, XATTR_ACL)
    except OSError as err:
        if err.errno in _NESSUNA_ACL:
            return None
        # Permesso negato, percorso sparito: non sappiamo, e non inventiamo.
        return None

    if len(blob) < 4 or (len(blob) - 4) % 8 != 0:
        return None
    (versione,) = struct.unpack_from("<I", blob, 0)
    if versione != _VERSIONE:
        return None

    voci = []
    for offset in range(4, len(blob), 8):
        tag, permessi, identificativo = struct.unpack_from("<HHI", blob, offset)
        voci.append((tag, permessi, identificativo))
    return tuple(voci)


def accesso(percorso: Path) -> Accesso:
    """Calcola chi accede a un percorso, applicando la maschera.

    Su un percorso senza ACL i bit del modo si leggono come sempre. Con
    un'ACL, i bit di gruppo sono la maschera e i permessi effettivi di ogni
    voce nominata — e del gruppo proprietario — sono il loro ``AND`` con
    essa.
    """
    modo = stat.S_IMODE(percorso.stat().st_mode)
    voci = leggi_acl(percorso)

    if voci is None:
        return Accesso(
            modo=modo,
            estesa=False,
            gruppo_proprietario=(modo >> 3) & 0o7,
            altri=modo & 0o7,
        )

    maschera = 0o7
    for tag, permessi, _ in voci:
        if tag == _TAG_MASK:
            maschera = permessi
            break

    gruppo_proprietario = 0
    altri = modo & 0o7
    nominati: list[Nominato] = []
    for tag, permessi, identificativo in voci:
        if tag == _TAG_GROUP_OBJ:
            gruppo_proprietario = permessi & maschera
        elif tag == _TAG_OTHER:
            altri = permessi
        elif tag == _TAG_USER and identificativo != _SENZA_ID:
            nominati.append(
                Nominato("utente", _nome_utente(identificativo), permessi & maschera)
            )
        elif tag == _TAG_GROUP and identificativo != _SENZA_ID:
            nominati.append(
                Nominato("gruppo", _nome_gruppo(identificativo), permessi & maschera)
            )

    return Accesso(
        modo=modo,
        estesa=True,
        gruppo_proprietario=gruppo_proprietario,
        altri=altri,
        nominati=tuple(nominati),
    )


def restringi(percorso: Path, modo: int) -> None:
    """Toglie i permessi di troppo, senza annullare un'ACL deliberata.

    ``open`` e ``mkdir`` rispettano la umask, che può solo *togliere* bit:
    un file appena creato non è mai più permissivo del modo richiesto. Questa
    funzione serve quindi al caso in cui il percorso **esisteva già** con
    permessi larghi — un file creato a mano, o da una versione precedente.

    Due ragioni per non insistere:

    * un file irrigidito con ``chattr +a`` **rifiuta la chmod con EPERM**,
      anche al proprietario: insistere significherebbe che indurire il log
      impedisce di scriverlo, cioè che la misura di protezione mette fuori
      uso ciò che protegge;
    * con un'ACL estesa i bit di gruppo sono la **maschera**, e riportarli al
      modo richiesto azzera i permessi effettivi di ogni voce nominata
      lasciandola elencata — vedere il docstring del modulo.

    Resta ``other``, che è un permesso vero in entrambi i casi e che nessuna
    ACL giustifica: quello viene tolto. Che i permessi siano davvero
    restrittivi lo verifica il preflight, che è il posto giusto per
    segnalarlo — un controllo che *riporta* non deve stare sul percorso che
    *scrive*.
    """
    try:
        corrente = stat.S_IMODE(percorso.stat().st_mode)
    except OSError:
        return

    if leggi_acl(percorso) is None:
        voluto = modo
    else:
        # Solo i bit di `other` che il modo richiesto non concede. I bit di
        # gruppo sono la maschera e restano dove li ha messi chi amministra.
        voluto = corrente & ~(0o7 & ~modo)

    if corrente == voluto:
        return
    try:
        os.chmod(percorso, voluto)
    except OSError:
        # Append-only, filesystem non POSIX, directory di qualcun altro: in
        # tutti i casi il percorso resta utilizzabile, che è ciò che conta qui.
        pass


def _nome_utente(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def _nome_gruppo(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return f"gid {gid}"


__all__ = [
    "Accesso",
    "LETTURA",
    "Nominato",
    "XATTR_ACL",
    "accesso",
    "leggi_acl",
    "restringi",
]
