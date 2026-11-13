# Integrazione continua

Cosa gira a ogni modifica, cosa gira una volta a settimana, e — la parte che
conta di più — **cosa la CI non verifica**.

## Perché due job e non uno

| Job | Quando | Come installa | Cosa trova |
|---|---|---|---|
| `dal-lock` | ogni push e PR | `--require-hashes` da `requirements.txt` | regressioni del nostro codice |
| `dagli-intervalli` | lunedì mattina | risolve dagli intervalli di `pyproject.toml` | rotture a monte |

Sono due domande diverse e confonderle produce una CI che non risponde a
nessuna delle due.

Il job `dal-lock` riproduce il dispiegamento esatto: le stesse 29 versioni
che girano sulla VM, con gli stessi hash. È deterministico, quindi quando
diventa rosso la causa è nella modifica che lo ha fatto diventare rosso.

Il job `dagli-intervalli` fa il contrario: prende le ultime versioni
compatibili, cioè proprio ciò che il lockfile nasconde di proposito. Serve a
sapere che una release nuova rompe il progetto **prima** di rigenerare il
lock. Gira a cadenza settimanale e non sulle PR, perché altrimenti una PR
diventerebbe rossa per qualcosa che qualcun altro ha pubblicato stanotte — e
un rosso che non dipende da chi lo riceve è un rosso che si impara a
ignorare.

## La matrice: solo gli estremi

`pyproject.toml` dichiara `requires-python = ">=3.11"`, la VM gira su 3.14.
La CI prova **3.11 e 3.14**, non le quattro versioni intermedie: gli estremi
sono dove le differenze si manifestano, e una matrice che cresce senza
ragione si inizia a saltare.

Che non sia teoria lo dice il primo bug che questa configurazione ha trovato,
prima ancora di esistere: `Path.resolve()` solleva `RuntimeError` su un
anello di symlink fino a 3.12 e non solleva nulla da 3.13. `load_config` non
lo gestiva, quindi su 3.11 e 3.12 — due delle quattro versioni dichiarate —
il **server** moriva all'avvio con un traceback invece di un errore
diagnosticabile. Nessun test lo aveva visto in nove passi, perché la suite
gira su 3.13 e la macchina su 3.14.

Entrambe le versioni girano anche nel job `dal-lock`, non solo in quello
settimanale: se 3.11 fosse coperto solo di lunedì, una PR potrebbe romperlo
e si scoprirebbe sei giorni dopo.

## Cosa questa CI NON verifica

Un verde qui dice che **il codice è coerente**, non che il dispiegamento è
sicuro. La distinzione non è accademica: quasi tutti i presidi di sicurezza
di questo progetto stanno fuori dalla portata di un runner.

Misurato, non supposto: nella suite, **tre test** hanno bisogno di
privilegi — due per `chattr +a`, uno per leggere un file sotto un'altra
identità — e saltano da soli dove non si può. Tutto il resto che riguarda
`sudo` e `systemd-run` verifica **stringhe**: l'`argv` che costruiremmo, o
il testo del rimedio. Nessuno di quei comandi viene eseguito.

Un'eccezione, dal novembre 2026: la **semantica** delle ACL POSIX è
verificata davvero, perché `tests/test_permessi.py` scrive e rilegge
`system.posix_acl_access` sul filesystem del runner. È così che si misura
che una `chmod` azzera la maschera — il difetto che faceva annullare dal
writer del log ogni concessione di lettura su quel log. Verificata è la
regola; **non** la sua applicazione su una macchina vera, che resta sotto.

Quindi la CI non dice niente su:

- **l'isolamento dei tool**: che `sudo` sia autorizzato, che il wrapper sia
  di root, che `systemd-run` applichi davvero `MemoryMax` e `TasksMax`, che
  l'utente dei tool non abbia una shell;
- **le ACL della macchina**: che `hermes-tool` riesca ad aprire gli script e
  **non** riesca a leggere `config/`, `docs/`, `mcp_server/`. Che la regola
  sulla maschera sia giusta lo dice la CI; che l'ACL giusta sia stata messa
  su `/opt/hermes-core` no;
- **l'append-only** del log d'audit (`chattr +a`): il test salta sui runner;
- **il canale SSH**: drop-in, `ForceCommand`, chiavi fuori dalla home;
- **il perimetro** come fatto di rete: `scope.toml` è validato come dato, non
  come confine effettivo;
- **il bootstrap**: `bin/hermes-bootstrap` crea utenti, applica ACL, scrive
  una riga di sudoers e installa unità di systemd. Niente di tutto ciò è
  eseguibile qui. La CI ne verifica la sintassi, che si fermi senza
  privilegi, e che le costanti duplicate fra shell, Python e unità
  coincidano — non che faccia la cosa giusta. Quello lo dice eseguirlo;
- **la spedizione del log verso una macchina vera.** Il protocollo sì: il
  mittente e il ricevente girano davvero nella suite, con un `ssh` finto che
  li mette in comunicazione, e la divergenza viene esercitata. Restano fuori
  il canale SSH, il `ForceCommand` sul collector, il timer, e l'unica cosa
  che conta davvero — che la copia remota esista.

Tutto questo è verificato **solo dal preflight su una macchina vera**, ed è
il motivo per cui il preflight esiste come programma e non come documento. Le
due metà non si sostituiscono:

> La CI dice che il codice fa quello che crediamo. Il preflight dice che la
> macchina è come crediamo. Un verde solo non autorizza a dire «funziona».

Il workflow stampa questo elenco a ogni esecuzione, in un passo apposta.
Scriverlo solo qui non basterebbe: chi guarda un verde guarda il log, non la
documentazione.

### Un'assunzione non ovvia

La suite dà per scontato che **chi la lancia possieda il checkout**. È vero
su un runner e sulla VM; eseguita da un altro utente, due test cadono perché
il controllo di scrivibilità cambia risposta. Non è un difetto — è una
condizione che vale la pena conoscere prima di stupirsi.

## `pip-audit`

Gira sul lockfile a ogni PR e **blocca**. Una CVE in una dipendenza del
processo che custodisce log e vault non è una cosa da rimandare a quando
capita.

Il problema noto di questa scelta: una CVE senza correzione disponibile a
monte ferma tutto il lavoro, compreso quello che la correggerebbe. La via
d'uscita non è un `|| true` nel workflow — che spegnerebbe il controllo per
sempre, in silenzio — ma una sospensione **scritta e motivata**:

`.github/pip-audit-sospese.txt` elenca una CVE per riga, con tre cose
obbligatorie: l'identificativo, **perché** non è sfruttabile qui o perché non
è correggibile, e **la data in cui va riesaminata**. Il workflow fallisce se
una riga non le ha tutte e tre, e fallisce se la data è passata.

Una sospensione senza scadenza diventa permanente senza che nessuno lo
decida; con la scadenza, il silenzio costa una riga da riscrivere, e chi la
riscrive deve guardarla di nuovo.

## Permessi e superficie del workflow

- `permissions: contents: read` a livello di workflow: i job leggono il
  codice e non scrivono niente.
- Le action sono **pinnate per SHA**, non per tag. Un'action è codice che
  gira con il token del repository, e un tag si può spostare: `v5` oggi e
  `v5` domani possono essere due commit diversi, decisi da qualcun altro. È
  lo stesso ragionamento per cui `setuptools` sta nel lockfile. Dependabot
  aggiorna lo SHA e tiene il commento con la versione.
- Nessun segreto è usato né necessario. Un workflow senza segreti è un
  workflow che non può perderne.
- `concurrency` annulla le esecuzioni superate sullo stesso ramo.
