# Dipendenze

Come sono vincolate, perché, e come si installa un dispiegamento.

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

Quella protezione è un'altra cosa, e va fatta dove si installa.

## Installazione di un dispiegamento

Sulla macchina che esegue il server, tre regole:

**Da un commit verificato, non da `main`.** `main` cambia; un dispiegamento
deve poter dire quale codice sta eseguendo.

```sh
git -C /opt/hermes-core fetch origin
git -C /opt/hermes-core checkout <sha-verificato>
```

**Senza gli extra di sviluppo.** `pytest` e le sue dipendenze non servono a
un server che esegue: ogni pacchetto in più è superficie in più.

```sh
.venv/bin/pip install --no-deps -e .
```

**Con un lockfile e gli hash**, quando si passa a un uso continuativo. È la
misura che rende l'installazione ripetibile e immune a un rilascio sostituito
a monte: `--require-hashes` fa fallire l'installazione se un pacchetto non
corrisponde all'hash registrato.

```sh
# in sviluppo, per generare il lockfile
pip install pip-tools
pip-compile --generate-hashes -o requirements.lock pyproject.toml

# sul dispiegamento
.venv/bin/pip install --require-hashes --no-deps -r requirements.lock
.venv/bin/pip install --no-deps -e .
```

In alternativa `uv lock` e `uv sync --frozen --no-dev`.

> Il lockfile non è ancora in questo repo: va generato e versionato quando si
> fissa il primo dispiegamento stabile. Finché non c'è, l'installazione prende
> le ultime versioni compatibili con gli intervalli sopra, e quella è una
> finestra aperta su chiunque pubblichi a monte.

## Perché conta più di quanto sembri

Il server custodisce il log d'audit e l'interfaccia del vault. Un pacchetto
compromesso fra le sue dipendenze non è un tool che gira isolato: è codice
dentro il processo che decide cosa può essere eseguito e che scrive la traccia
di ciò che è avvenuto. Un loader `.pth` dentro una dipendenza girerebbe a
ogni avvio del server — tecnica vista in compromissioni reali di pacchetti,
non teorica.

Da cui due conseguenze pratiche già applicate: i tool girano con
`-I -S`, quindi **non** caricano `site-packages` né `.pth`, e il virtualenv è
compreso nel controllo di scrivibilità del preflight, perché un `.venv` che
l'utente di servizio può scrivere è peggio di uno script modificabile — lo
script almeno ha uno SHA che non corrisponderebbe più.

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
pip-audit -r requirements.lock
```
