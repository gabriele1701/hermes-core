# Dipendenze

Come sono vincolate, perché, come si genera il lockfile e come si installa un
dispiegamento.

## Lo stato

```toml
dependencies = [
    "mcp>=2.3,<3",
    "pydantic>=2.12,<3",
]
```

Prima era `mcp>=1.2.0`, che **dichiarava il falso**: il codice importa
`mcp.server.mcpserver.MCPServer`, che esiste solo dalla 2.x. Un vincolo
sbagliato in quella direzione fa due danni. Fa passare per compatibili
versioni che non partirebbero, e fa comparire nelle scansioni di sicurezza
advisory su versioni che non useremmo mai — rumore che nasconde i segnali
veri.

## Il tetto non è la protezione

`<3` serve a non accogliere una major nuova senza averla provata. **Non**
protegge da un rilascio compromesso dentro l'intervallo: se la 2.4.0 fosse
pubblicata manomessa, `pip install -e .` la prenderebbe.

Quella protezione è il lockfile, ed è l'oggetto di questo documento.

## Perché conta più di quanto sembri

Il server custodisce il log d'audit e l'interfaccia del vault. Un pacchetto
compromesso fra le sue dipendenze non è un tool che gira isolato: è codice
dentro il processo che decide cosa può essere eseguito e che scrive la traccia
di ciò che è avvenuto. Un loader `.pth` dentro una dipendenza girerebbe a
ogni avvio del server — tecnica vista in compromissioni reali di pacchetti,
non teorica.

Da cui due conseguenze pratiche già applicate: i tool girano con `-I -S`,
quindi **non** caricano `site-packages` né `.pth`, e il virtualenv è compreso
nel controllo di scrivibilità del preflight, perché un `.venv` che l'utente di
servizio può scrivere è peggio di uno script modificabile — lo script almeno
ha uno SHA che non corrisponderebbe più.

---

## Generare il lockfile

### Dove, e perché lì

**Sulla macchina che esegue il server.** Non per gli hash — su quelli mi ero
sbagliato: `pip-compile --generate-hashes` raccoglie gli hash di *tutte* le
distribuzioni di una versione, tutte le ruote per tutte le piattaforme e tutti
gli interpreti, più l'sdist. Misurato: per `pydantic-core` sono 140 hash. Un
lock generato altrove si installerebbe benissimo qui.

Il motivo è la **risoluzione**. `mcp` dichiara vincoli che dipendono
dall'interprete:

```
anyio>=4.10; python_version >= '3.14'
anyio>=4.9;  python_version < '3.14'
starlette>=0.27;   python_version < '3.14'
starlette>=0.48.0; python_version >= '3.14'
```

`pip-compile` valuta i marker con il Python su cui gira e produce un elenco
piatto di versioni fissate: su un interprete diverso risolve contro la colonna
sbagliata. Oggi i due rami coincidono — generato su 3.13 e su 3.14 della VM, le
28 versioni risultano identiche — quindi è una precauzione, non la correzione
di un guasto osservato. Ma il vincolo dichiarato è diverso, e nulla garantisce
che il prossimo rilascio continui a farli coincidere.

### Il comando

`pip-tools` va in un virtualenv **usa-e-getta, fuori dal repo e fuori da
`.venv`**. Metterlo nel venv del dispiegamento aggiungerebbe `pip-tools` e le
sue dipendenze al processo che custodisce log e vault, cioè superficie
aggiunta proprio dal passo che la vuole ridurre.

```sh
python3 -m venv /tmp/venv-lock
/tmp/venv-lock/bin/pip install pip-tools

cd /opt/hermes-core
/tmp/venv-lock/bin/pip-compile \
    --generate-hashes \
    --strip-extras \
    --allow-unsafe \
    --output-file=requirements.txt \
    pyproject.toml requirements-build.in
```

Le flag, una per una:

| Flag | Cosa fa, e cosa succede senza |
|---|---|
| `--generate-hashes` | Scrive gli hash. Senza, il lock fissa le versioni ma non i contenuti: un rilascio sostituito a monte con lo stesso numero di versione passerebbe |
| `--strip-extras` | Toglie gli extra dai nomi (`pyjwt[crypto]` → `pyjwt`), che pip non accetta insieme agli hash. Le dipendenze dell'extra restano risolte e pinnate |
| `--allow-unsafe` | Pinna `setuptools`. **Senza questa flag il passo non serve a niente**: vedi sotto |
| due input | `pyproject.toml` dà il runtime, `requirements-build.in` il backend di build |

### `--allow-unsafe`, e perché non è opzionale

`pip-tools` classifica `setuptools`, `pip` e `wheel` come «unsafe to pin» —
cautela storica, da quando `pip-compile` rischiava di declassare gli strumenti
dell'ambiente in cui girava — e per default li lascia **fuori**, scrivendo solo
un'avvertenza in fondo al file:

```
# WARNING: The following packages were not pinned, but pip requires them to be
# pinned when the requirements file includes hashes […]
# setuptools
```

Il nostro caso è l'opposto: `setuptools` lo vogliamo pinnato *proprio perché*
viene eseguito. Vedere `requirements-build.in` per il perché per esteso.

**Un lock senza una riga `setuptools==` non chiude niente.** Dopo averlo
generato, verificare:

```sh
grep -E '^setuptools==' requirements.txt || echo "ASSENTE: rigenerare con --allow-unsafe"
grep -i 'not pinned' requirements.txt && echo "avvertenze rimaste: leggerle"
```

### Quando si rigenera

- `pyproject.toml` cambia (dipendenza aggiunta, intervallo spostato);
- si aggiorna di proposito qualcosa;
- **cambia la versione di Python della macchina**, per la ragione dei marker
  spiegata sopra.

Non si rigenera «per igiene». Un lock rigenerato senza una ragione è un
aggiornamento di massa che nessuno ha rivisto.

### Perché si chiama `requirements.txt`

Si chiamava `requirements.lock`, che è la convenzione di `pip-compile` e dice
meglio cos'è. **Dependabot però non lo guardava.** Misurato invece che
supposto: al primo giro ha esaminato quattro pacchetti — `mcp`, `pydantic`,
`pytest`, `setuptools`, tutti dichiarati in `pyproject.toml` — e nessuno dei
29 fissati nel lock. Un file che nessuno aggiorna in automatico è un file che
invecchia in silenzio, cioè l'opposto di ciò per cui esiste.

Due conseguenze da conoscere, perché rendono l'intestazione del file meno
affidabile di quanto sembri.

La prima: l'intestazione dice ancora `--output-file=requirements.lock`, perché
il file **non** è stato rigenerato per il rinomina. Rigenerarlo a una
settimana di distanza avrebbe trasformato un cambio di nome in un
aggiornamento di massa non rivisto, e correggerlo a mano avrebbe reso falso
proprio ciò che l'intestazione serve a garantire — che quel contenuto viene da
quel comando. Si sistema alla prossima rigenerazione vera.

La seconda, più duratura: **Dependabot modifica questo file in posizione**,
aggiornando un pacchetto per volta con i suoi hash. Dopo la prima di quelle
PR, l'intestazione descrive la generazione originale e non il contenuto
corrente. Resta il comando di riferimento per un rinfresco completo, non un
certificato di come il file è fatto adesso.

Una PR di Dependabot su questo file va quindi guardata per quello che è: un
cambiamento alle versioni che girano, verificato dalla CI — che installa
proprio da qui, su 3.11 e 3.14 — e non un atto formale.

---

## Installare un dispiegamento

Tre regole, e la terza è quella che si dimentica.

**Da un commit verificato, non da `main`.** `main` cambia; un dispiegamento
deve poter dire quale codice sta eseguendo.

```sh
git -C /opt/hermes-core fetch origin
git -C /opt/hermes-core checkout <sha-verificato>
```

**Con gli hash obbligatori, e senza gli extra di sviluppo.** `pytest` e le sue
dipendenze non servono a un server che esegue: ogni pacchetto in più è
superficie in più.

```sh
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
```

> **Lo stesso comando riallinea un ambiente che ha derivato.** Un `.venv`
> creato *prima* del lockfile ha le versioni più recenti di allora, non quelle
> fissate: è la situazione trovata sulla VM l'11 novembre, nove pacchetti
> indietro di una patch o due. Il preflight la riporta come errore, e il
> rimedio è questo comando.
>
> Non è un'operazione neutra: cambia le versioni di ciò che gira. Vale la pena
> guardare l'elenco degli scostamenti che il preflight stampa **prima** di
> lanciarlo, perché quello è il momento in cui l'aggiornamento viene rivisto —
> e dopo non ci sarà un altro.

**Senza isolamento di build.** È il passo che rende vera la frase «con gli hash
obbligatori»:

```sh
.venv/bin/pip install --no-deps --no-build-isolation -e .
```

Senza `--no-build-isolation`, pip costruisce un ambiente temporaneo e vi
scarica il backend di build al momento — **senza hash e senza pin** — e poi lo
esegue. Il comando precedente avrebbe appena verificato 29 pacchetti, e
l'ultimo passo ne scaricherebbe uno non verificato ed eseguirebbe il suo
codice. Con la flag, pip usa il `setuptools` già installato dal lock.

> `--no-deps` in entrambi i comandi non è pigrizia: dice a pip che l'elenco
> completo è già nel lock. Senza, pip potrebbe risolvere da sé qualcosa che il
> lock non copre, cioè installare un pacchetto che nessuno ha fissato.

In alternativa all'intera procedura, `uv lock` e `uv sync --frozen --no-dev`.
Non è la strada scelta: aggiunge un attrezzo, e `pip-compile` fa ciò che serve.

---

## Il controllo nel preflight

`--require-hashes` garantisce il **momento** dell'installazione, non i mesi
successivi. Un `pip install` dato a mano per provare qualcosa non lascia tracce
da nessuna parte, e il server continuerebbe a girare con dipendenze che nessuna
revisione ha visto.

Il preflight confronta quindi il lock con l'ambiente **vero** — ciò che
`importlib.metadata` elenca per l'interprete in esecuzione — e non con la
configurazione:

| Situazione | Esito |
|---|---|
| Lock assente | **Avviso**. Il server parte, ma l'installazione prende le ultime versioni compatibili con gli intervalli |
| Lock presente e senza pin leggibili | **Errore**. Un lock illeggibile non blocca niente, ma sembra che lo faccia |
| Pacchetto di runtime fissato e non installato, o a versione diversa | **Errore**. Ciò che è stato rivisto e ciò che gira sono due cose diverse |
| Dipendenza di **installazione** assente | **Avviso**, con un nome proprio. Vedi sotto |
| Pacchetto installato e non fissato | **Avviso**. Non smentisce il lock, ma qualcuno l'ha messo lì a mano |

### Le dipendenze di installazione sono un caso a parte

`setuptools` è nel lock per essere verificato **quando `pip install -e .` lo
esegue**, non perché il server lo importi: a runtime non serve a nessuno, e da
Python 3.12 `python3 -m venv` non lo installa nemmeno. Trattare la sua assenza
come una mancanza grave direbbe **`NON PRONTO`** a un dispiegamento che
funziona.

Questo è il *falso rosso* — l'immagine speculare del falso verde inseguito per
tutta la patch, e con un difetto in più: un rosso che si sa essere ingiusto
insegna a ignorare i rossi.

Il controllo legge quindi `requirements-build.in` per sapere quali pacchetti
sono di installazione. Non c'è un elenco ricopiato nel codice: una seconda
fonte per lo stesso confine divergerebbe dalla prima, ed è la regola già
applicata al perimetro e a `nftables`.

Una dipendenza di build a **versione diversa** resta un errore: se c'è, è
quella che `pip install -e .` eseguirebbe, e il lock dice quale dovrebbe
essere. Se `requirements-build.in` manca, si confronta tutto e l'assenza
risulta grave — il lato prudente: dice troppo, non troppo poco.

> **Come è stato trovato.** Mettendo il lockfile reale in posizione, 9 test
> sono diventati rossi: il controllo segnalava `setuptools` mancante e il
> referto passava a non pronto. Non l'ha trovato un test scritto per
> l'occasione, l'ha trovato il file vero appena è entrato nel repo. I test
> coprivano il meccanismo del confronto, non il significato di ciò che
> confrontava.

Il referto nomina **l'interprete** su cui ha risposto. Lanciare il preflight con
il Python di sistema invece che con quello del venv risponderebbe sulla
macchina giusta e sull'ambiente sbagliato, e un controllo che non dice su cosa
ha guardato non è verificabile.

L'avviso sui pacchetti in più compare su un dispiegamento installato con
`pip install -e '.[dev]'`, perché `pytest` e le sue dipendenze non sono nel
lock. Non è un falso positivo: è la regola «senza gli extra di sviluppo» che
chiede di essere applicata.

### Il lock è verificato anche dalla suite

`tests/test_doctor.py` confronta il lock **versionato** con l'ambiente in cui
girano i test. Non è una tautologia: se qualcuno aggiorna una dipendenza in
`pyproject.toml` senza rigenerare il lock, o rigenera il lock senza
reinstallare, quel test lo dice. È il solo posto dove la coerenza fra i due
file viene misurata invece che assunta.

Quel test è **uno**, e di proposito. La prima stesura non isolava gli altri:
molti test usano la radice vera del repo, quindi leggevano il lock vero e
confrontavano con l'ambiente vero. Eseguita sulla VM, dove il `.venv` era
stato creato prima del lockfile, la suite ha prodotto **nove** rossi su
configurazione, store, perimetro e wrapper — nessuno dei quali riguardava le
dipendenze.

Il controllo aveva ragione: la deriva c'era. Era la suite a essere accoppiata
a uno stato che non dichiarava. Ora una fixture `autouse` presenta ai test le
dipendenze **fissate dal lock**, e i casi il cui soggetto è l'ambiente vero si
marcano `dipendenze_reali`:

```sh
pytest -m dipendenze_reali      # solo i casi che interrogano la macchina
```

Così una deriva reale fa cadere **un** test che la nomina, con le versioni
divergenti nel messaggio, invece di nove che la nascondono. Il controllo resta
nel referto del preflight: quello guarda sempre la macchina vera, ed è il suo
mestiere.

> **Il precedente.** Il 4 novembre «scrivibilità del codice» aveva rotto
> quattro test allo stesso modo, e la risposta fu correggere il controllo,
> perché non sapeva rispondere quando lo lanciava il proprietario del repo.
> Qui il controllo sa rispondere e dice il vero, quindi la correzione va
> dall'altra parte. Distinguere i due casi è il punto: un controllo che
> sbaglia si corregge, un controllo che ha ragione si ascolta.

---

## Le dipendenze di sviluppo

`pytest` **non** è nel lockfile di runtime, e non deve esserlo: il
dispiegamento non lo installa. Arriverà un `requirements-dev.lock` separato
insieme alla CI.

Quando sarà il momento, va compilato con il lock di runtime **come vincolo**:

```sh
pip-compile --generate-hashes --allow-unsafe \
    -c requirements.txt \
    -o requirements-dev.lock requirements-dev.in
```

`-c` dice al resolver che su quei pacchetti non può scegliere. Senza, `pytest`
può tirarsi dietro una versione diversa di qualcosa che il runtime ha già — per
esempio `typing-extensions` — e la CI testerebbe un insieme di dipendenze che
non è quello in produzione. Due lockfile che si contraddicono senza che niente
lo segnali sono due fonti per lo stesso confine: divergono.

---

## Aggiornamenti

Quando ci sarà una CI, conviene Dependabot o Renovate con un **periodo di
attesa** prima di proporre una versione appena pubblicata: le compromissioni
di pacchetti vengono tipicamente scoperte e ritirate in poche ore, e
aspettare qualche giorno elimina gran parte della finestra senza costare
nulla.

```yaml
# .github/dependabot.yml
updates:
  - package-ecosystem: pip
    directory: /
    schedule: { interval: weekly }
    cooldown: { default-days: 7 }
```

E in CI, su ogni pull request:

```sh
pip-audit -r requirements.txt
```

---

## Quello che il lock non risolve

Il lock fissa **29 pacchetti**. Fra questi `cryptography`, `pyjwt`, `uvicorn`,
`starlette`, `httpx2`, `opentelemetry-api`, `truststore`, `python-multipart`:
dipendenze dure di `mcp`, nessuna delle quali serve al trasporto stdio che
questo server usa. Verificato nei metadati di `mcp 2.3.0`: non c'è un extra che
le escluda, sono richieste sempre.

Il lockfile le fissa, non le toglie. La superficie resta, ed è una voce per il
debito, non per questo documento.
