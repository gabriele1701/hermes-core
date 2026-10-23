"""Accesso alle credenziali.

Interfaccia unica con cui i componenti ottengono un segreto, e punto unico in
cui ogni accesso viene registrato. In Milestone 0 il backend è uno **stub
dichiaratamente finto**: l'interfaccia è reale, le credenziali no.

Il principio
------------

Il vault espone l'*accesso* ai segreti, non i segreti. Ogni chiamata lascia
una riga di audit con il **nome** del segreto e l'esito; il valore non compare
mai, né nel log né in una rappresentazione testuale accidentale.

Il valore è avvolto in :class:`Secret`
--------------------------------------

Restituire una ``str`` nuda sarebbe la via più breve verso una fuga
involontaria: basta un f-string in un messaggio d'errore, un ``repr()`` in un
traceback, un ``print`` di debug dimenticato. :class:`Secret` oscura il valore
in ``str``, ``repr`` e ``format``, e lo cede solo a chi chiama
:meth:`Secret.reveal` — che è esplicito, cercabile con un grep, e cosa da
fare il più tardi possibile nel codice.

I nomi dei segreti sono validati
--------------------------------

Un backend reale mappa il nome su una risorsa: ``pass`` lo mappa su un
percorso di file sotto il proprio store. Un nome con ``..`` o assoluto
diventerebbe quindi una lettura arbitraria del filesystem, con i privilegi del
server. I nomi sono perciò confinati con le stesse regole di ``exec_path``,
prima che raggiungano qualunque backend.

Perimetro
---------

Nel vault entrano solo le credenziali delle macchine di laboratorio di
proprietà (``ssh/lab-kali`` e simili), come previsto dal documento di scope.
L'interfaccia non impone quel perimetro — lo impone cosa ci si mette dentro.
"""

from __future__ import annotations

import re
import uuid
from typing import Protocol, runtime_checkable

from mcp_server.audit import AuditLog, LogAction
from mcp_server.contracts import CallOutcome

_NOME_SEGRETO = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
_LUNGHEZZA_MASSIMA = 128


# --------------------------------------------------------------------------- #
# Errori
# --------------------------------------------------------------------------- #


class VaultError(Exception):
    """Base degli errori del vault."""


class InvalidSecretName(VaultError):
    """Il nome del segreto non è conforme."""


class SecretNotFound(VaultError):
    """Nessun segreto con quel nome nel backend."""


# --------------------------------------------------------------------------- #
# Valore protetto
# --------------------------------------------------------------------------- #


class Secret:
    """Contenitore di un valore riservato.

    Oscura il valore in ogni rappresentazione testuale. L'unico modo di
    ottenerlo è :meth:`reveal`, che è esplicito e rintracciabile con un grep:
    i punti in cui un segreto diventa una stringa nuda sono pochi e
    individuabili, invece di essere ovunque.
    """

    __slots__ = ("_name", "_value")

    #: Testo mostrato al posto del valore.
    MASCHERA = "***"

    def __init__(self, name: str, value: str) -> None:
        self._name = name
        self._value = value

    @property
    def name(self) -> str:
        """Nome del segreto. Non riservato: è ciò che finisce nel log."""
        return self._name

    def reveal(self) -> str:
        """Restituisce il valore in chiaro.

        Da chiamare il più tardi possibile, nel punto d'uso, e mai per
        costruire un messaggio di log o d'errore.
        """
        return self._value

    # -- ogni via testuale è chiusa ----------------------------------------- #

    def __str__(self) -> str:
        return self.MASCHERA

    def __repr__(self) -> str:
        return f"Secret({self._name!r}, {self.MASCHERA})"

    def __format__(self, format_spec: str) -> str:
        # Senza questo, un f-string con specificatore aggirerebbe __str__.
        return self.MASCHERA

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        """Lunghezza del valore. Non lo rivela, e serve a validarlo."""
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        """Confronto solo fra segreti, in tempo costante.

        Il confronto con una stringa nuda è deliberatamente ``False``: chi
        vuole confrontare un valore deve passare da :meth:`reveal`, e
        renderlo visibile nel codice.
        """
        if not isinstance(other, Secret):
            return NotImplemented
        import hmac

        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        """Basato sul nome: il valore non entra in una tabella hash."""
        return hash(("Secret", self._name))


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #


@runtime_checkable
class VaultBackend(Protocol):
    """Sorgente dei segreti.

    L'interfaccia è deliberatamente minima: un backend reale (``pass``,
    KeePass, Vault) si collega implementando questo unico metodo, senza che i
    chiamanti del vault cambino di una riga.
    """

    #: Etichetta mostrata nel log, per sapere da dove viene un segreto.
    nome_backend: str

    def fetch(self, name: str) -> str | None:
        """Restituisce il valore, o ``None`` se il nome non esiste."""
        ...


class StubBackend:
    """Backend finto per lo sviluppo. Non contiene credenziali reali.

    Va seminato esplicitamente: non inventa valori e non legge nulla dal
    sistema. Serve a esercitare l'interfaccia e il logging mentre il backend
    reale non è ancora collegato.
    """

    nome_backend = "stub"

    #: Prefisso dei valori finti, perché un valore sfuggito sia riconoscibile
    #: a colpo d'occhio come non reale.
    PREFISSO_FINTO = "STUB-NON-REALE:"

    def __init__(self, segreti: dict[str, str] | None = None) -> None:
        self._segreti: dict[str, str] = dict(segreti or {})

    def semina(self, name: str, value: str | None = None) -> str:
        """Aggiunge un segreto finto. Senza valore ne genera uno marcato."""
        valore = value if value is not None else f"{self.PREFISSO_FINTO}{name}"
        self._segreti[name] = valore
        return valore

    def fetch(self, name: str) -> str | None:
        return self._segreti.get(name)


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #


def valida_nome_segreto(name: str) -> str:
    """Valida un nome di segreto, o solleva :class:`InvalidSecretName`.

    Le stesse regole di ``exec_path``, per la stessa ragione: un backend reale
    mappa il nome su un percorso, e un nome non confinato diventa una lettura
    arbitraria del filesystem.
    """
    if not isinstance(name, str) or not name:
        raise InvalidSecretName("il nome del segreto deve essere una stringa non vuota")
    if len(name) > _LUNGHEZZA_MASSIMA:
        raise InvalidSecretName(
            f"nome troppo lungo ({len(name)} > {_LUNGHEZZA_MASSIMA})"
        )
    if name.startswith(("/", "\\")):
        raise InvalidSecretName("il nome non può essere un percorso assoluto")
    if "\\" in name:
        raise InvalidSecretName("il nome deve usare '/' come separatore")
    if ".." in name.split("/"):
        raise InvalidSecretName("il nome non può contenere '..'")
    # fullmatch e non match: in `re` di Python il metacarattere `$` combacia
    # anche *prima* di un newline finale, quindi 'ssh/lab-kali\n' superava la
    # validazione col newline intatto. Oggi è innocuo perché lo stub fa una
    # ricerca per chiave, ma col backend `pass` quel nome diventa argomento di
    # un processo e nome di un file — e un newline in un argomento è il genere
    # di cosa che cambia il significato di un comando.
    #
    # Si rifiuta invece di normalizzare: un nome di credenziale che arriva
    # diverso da come è scritto in configurazione è un errore da segnalare,
    # non da indovinare.
    if not _NOME_SEGRETO.fullmatch(name):
        raise InvalidSecretName(
            f"nome non conforme: {name!r} "
            "(lowercase, separatori . _ - e / fra segmenti)"
        )
    return name


class Vault:
    """Punto unico di accesso alle credenziali.

    Parameters
    ----------
    backend:
        Sorgente dei segreti. In M0 :class:`StubBackend`.
    audit:
        Log su cui registrare ogni accesso: nome ed esito, mai il valore.
    correlation_id:
        Correlazione di default per gli accessi che non ne portano una.
    """

    def __init__(
        self,
        backend: VaultBackend,
        audit: AuditLog,
        *,
        correlation_id: uuid.UUID | None = None,
    ) -> None:
        self._backend = backend
        self._audit = audit
        self._correlation_id = correlation_id or uuid.uuid4()

    @property
    def correlation_id(self) -> uuid.UUID:
        return self._correlation_id

    @property
    def nome_backend(self) -> str:
        return getattr(self._backend, "nome_backend", type(self._backend).__name__)

    @property
    def e_stub(self) -> bool:
        """Se il backend collegato è finto. Da mostrare, non da nascondere."""
        return isinstance(self._backend, StubBackend)

    def get_secret(
        self, name: str, *, correlation_id: uuid.UUID | None = None
    ) -> Secret:
        """Recupera un segreto, registrando l'accesso.

        Ogni esito è registrato — riuscito, nome non conforme, segreto assente
        — perché in audit conta tanto chi ha ottenuto una credenziale quanto
        chi ha provato a ottenerne una che non doveva esistere.
        """
        cid = correlation_id or self._correlation_id

        try:
            nome = valida_nome_segreto(name)
        except InvalidSecretName as err:
            self._audit.log(
                correlation_id=cid,
                action=LogAction.SECRET_ACCESS,
                outcome=CallOutcome.DENIED,
                secret_name=_nome_per_log(name),
                detail=f"nome non conforme, accesso negato: {err}",
            )
            raise

        valore = self._backend.fetch(nome)
        if valore is None:
            self._audit.log(
                correlation_id=cid,
                action=LogAction.SECRET_ACCESS,
                outcome=CallOutcome.ERROR,
                secret_name=nome,
                detail=f"segreto non presente nel backend '{self.nome_backend}'",
            )
            raise SecretNotFound(f"segreto non trovato: {nome!r}")

        self._audit.log(
            correlation_id=cid,
            action=LogAction.SECRET_ACCESS,
            outcome=CallOutcome.OK,
            secret_name=nome,
            detail=f"accesso concesso dal backend '{self.nome_backend}'",
        )
        return Secret(nome, valore)


def _nome_per_log(name: object) -> str | None:
    """Rende loggabile un nome non valido, senza fidarsene.

    Il nome è stato rifiutato, quindi è input non fidato: solo stringhe,
    troncate alla lunghezza del campo di log.
    """
    if isinstance(name, str) and name:
        return name[:_LUNGHEZZA_MASSIMA]
    return None


__all__ = [
    "InvalidSecretName",
    "Secret",
    "SecretNotFound",
    "StubBackend",
    "Vault",
    "VaultBackend",
    "VaultError",
    "valida_nome_segreto",
]
