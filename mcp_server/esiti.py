"""Gli esiti di un'invocazione: la directory che un tool isolato può scrivere.

Un tool che gira nell'unità ristretta vede il filesystem in sola lettura,
tranne ``/esiti``: una directory sua, creata dal wrapper per quella sola
invocazione e chiamata col suo ``correlation_id``, sotto :data:`DIR_ESITI`
sulla macchina. Quando l'unità finisce la directory **resta** — è il punto —
e il wrapper la sigilla: di root, leggibile dal gruppo del servizio, non più
scrivibile da nessun tool.

Questo modulo fa una cosa sola: il **manifesto**. Un elenco ordinato di ciò
che la directory contiene, con lo SHA-256 di ogni file, e lo SHA-256
dell'elenco intero. Il gate lo calcola a fine esecuzione e lo scrive nella
riga di audit; ``bin/hermes-esiti`` lo ricalcola quando si portano gli esiti
altrove, e lo confronta con quello del log. Se differiscono, qualcosa è stato
cambiato dopo l'esecuzione, e la traccia lo dice.

Una sola implementazione, usata da entrambi: due copie dello stesso
algoritmo sono due algoritmi, e il confronto fra le loro uscite non
proverebbe niente.

Il contenuto lo ha scritto il tool
----------------------------------

Quindi è **dato non fidato**, e il manifesto lo tratta così:

* i link simbolici **non si seguono**: si registra dove puntano, non cosa c'è
  lì. Un link verso un file del servizio farebbe altrimenti entrare nel
  manifesto l'hash di un file che il tool non poteva leggere;
* i nomi si scrivono come stringhe JSON con soli caratteri ASCII: un nome di
  file può contenere un a-capo, e un a-capo in un manifesto è una riga in più
  che nessuno ha scritto.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

#: Dove il wrapper crea le directory degli esiti. **Deve coincidere con
#: ``ESITI_DIR`` in ``bin/hermes-tool-run``**: un test della suite li confronta.
DIR_ESITI = Path("/var/lib/hermes-tool/esiti")

_BLOCCO = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Manifesto:
    """Cosa contiene una directory di esiti, e la sua impronta."""

    righe: tuple[str, ...]
    file: int
    byte: int

    @property
    def testo(self) -> str:
        return "".join(f"{riga}\n" for riga in self.righe)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.testo.encode("ascii")).hexdigest()

    @property
    def riassunto(self) -> str:
        """Per il ``detail`` della riga di audit."""
        if not self.righe:
            return "esiti: directory vuota"
        return (
            f"esiti: {self.file} file, {self.byte} byte, "
            f"manifesto sha256:{self.sha256}"
        )


def _nome(valore: str) -> str:
    return json.dumps(valore, ensure_ascii=True)


def _sha256(percorso: str) -> str:
    digest = hashlib.sha256()
    # O_NOFOLLOW: fra l'lstat e l'apertura il file non deve poter diventare
    # un link. Il tool è finito, ma un controllo non si fida di un «è finito».
    fd = os.open(percorso, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        while blocco := fh.read(_BLOCCO):
            digest.update(blocco)
    return digest.hexdigest()


def manifesto(cartella: Path) -> Manifesto:
    """Il manifesto di ``cartella``. Solleva ``OSError`` se non è leggibile."""
    righe: list[tuple[str, str]] = []
    file = byte = 0
    base = os.fspath(cartella)
    for radice, sottocartelle, nomi in os.walk(base, followlinks=False):
        # Un link a una directory compare fra le sottocartelle, non fra i
        # file, e os.walk non ci entra: lo si registra come link.
        collegate = [d for d in sottocartelle if os.path.islink(os.path.join(radice, d))]
        for nome in sorted(nomi + collegate):
            percorso = os.path.join(radice, nome)
            relativo = os.path.relpath(percorso, base)
            st = os.lstat(percorso)
            if stat.S_ISLNK(st.st_mode):
                riga = f"link  {_nome(os.readlink(percorso))}  {_nome(relativo)}"
            elif stat.S_ISREG(st.st_mode):
                riga = f"{_sha256(percorso)}  {st.st_size}  {_nome(relativo)}"
                file += 1
                byte += st.st_size
            else:
                riga = f"altro  {stat.filemode(st.st_mode)}  {_nome(relativo)}"
            righe.append((relativo, riga))
    righe.sort()
    return Manifesto(tuple(riga for _, riga in righe), file, byte)


def nota_esiti(cartella: Path) -> str:
    """Coda per il ``detail``: cosa ha lasciato il tool, o perché non si sa.

    Non solleva mai: si chiama dopo che il tool è già girato, e un errore qui
    non deve togliere la riga di audit a un'esecuzione avvenuta.
    """
    try:
        # lstat e non exists(): exists() solleva se la directory madre non è
        # attraversabile, e questa funzione non deve sollevare. Trovato
        # eseguendo la suite da un utente fuori dal gruppo del servizio.
        os.lstat(cartella)
    except FileNotFoundError:
        # Il wrapper rimuove la directory se il tool non vi ha scritto niente:
        # mille preflight non lasciano mille directory vuote.
        return "; esiti: nessuno"
    except OSError as err:
        return (
            f"; esiti: non leggibili dal servizio ({type(err).__name__}: "
            f"{err.strerror or err}) — la directory resta in {cartella}"
        )
    try:
        return f"; {manifesto(cartella).riassunto}"
    except OSError as err:
        return (
            f"; esiti: non leggibili dal servizio ({type(err).__name__}: "
            f"{err.strerror or err}) — la directory resta in {cartella}"
        )


__all__ = ["DIR_ESITI", "Manifesto", "manifesto", "nota_esiti"]
