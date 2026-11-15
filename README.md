# hermes-core

Scaffolding condiviso della **toolbox multi-agente difensiva Hermes**.

Questo repository contiene il nucleo comune su cui poggiano gli agenti della toolbox:
l'**orchestratore** minimo, il **server MCP** con il contratto di registrazione dei
tool (risk tier tecnico + flag dati personali + override utente), il **logging
strutturato JSONL** e l'**interfaccia vault** per le credenziali.

Non è uno strumento d'uso diretto: è il prerequisito (Milestone 0) che abilita gli
agenti operativi delle milestone successive (vulnerability assessment, pentest/Kali
containerizzato).

## Installazione

Da zero a server funzionante su una VM Debian/Ubuntu. Qui solo la sequenza; il
perché di ogni scelta, le trappole e cosa fare quando qualcosa non torna sono
in [docs/setup-vm-hermes.md](docs/setup-vm-hermes.md).

> **Tutti i comandi sulla VM si eseguono dentro `/opt/hermes-core`**, dove il
> passo 1 ti lascia. `bin/hermes-bootstrap`, `bin/hermes-configura` e il
> preflight sono percorsi relativi: fuori da quella directory non esistono, e
> l'errore che ricevi parla di un file che non c'è invece del fatto che sei
> altrove. Dove un comando va dato sulla **postazione** o dalla **console
> della VM**, è scritto nel passo.

**1. Il repo**, prima di tutto: contiene gli script e la documentazione.

```sh
sudo git clone https://github.com/gabriele1701/hermes-core.git /opt/hermes-core
sudo chown -R "$USER:$USER" /opt/hermes-core
cd /opt/hermes-core
```

**2. I pacchetti.** `acl` su Ubuntu Server non c'è, e senza `setfacl` il passo
3 si ferma subito.

```sh
sudo apt update && sudo apt install -y git python3-venv openssh-server acl
```

**3. Il bootstrap:** utenti, directory, permessi, ACL, artefatti fuori
dall'albero di git, configurazione dai modelli, e poi il preflight. `--dev`
aggiunge `pytest`.

```sh
sudo bin/hermes-bootstrap --dev
```

→ Atteso **`NON PRONTO`**: i valori di questa macchina sono ancora
`DA_COMPILARE`, e li compila il passo 4.

**4. Le due chiavi**, generate sulla **postazione** — non sulla VM. Servono
adesso: il passo 5 chiede quella del servizio, e il passo 9 disattiva le
password, quindi senza la tua resti fuori.

Sulla **postazione**, in PowerShell. Sostituisci `NOME-VM` con il nome di
questa macchina, e `UTENTE@INDIRIZZO` con i tuoi:

```powershell
ssh-keygen -t ed25519 -C "hermes-core@postazione" -f $env:USERPROFILE\.ssh\id_ed25519_hermes_NOME-VM
ssh-keygen -t ed25519 -C "UTENTE@NOME-VM"         -f $env:USERPROFILE\.ssh\id_ed25519_NOME-VM_admin
```

Il nome del file porti il nome della VM: con un nome fisso, la seconda VM
servita dalla stessa postazione fa chiedere *«already exists. Overwrite?»*, e
un sì distratto cancella la chiave della prima.

Ora le due chiavi vanno sulla VM, **senza copiarle e incollarle**. Le password
funzionano ancora — il ricarico di `sshd` è al passo 9 — quindi passano da lì:

```powershell
# la TUA chiave, diretta in authorized_keys
type $env:USERPROFILE\.ssh\id_ed25519_NOME-VM_admin.pub | ssh UTENTE@INDIRIZZO "mkdir -p ~/.ssh && chmod 700 ~/.ssh && tr -d '\r' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

# quella del SERVIZIO, come file: la installa il passo 5
scp $env:USERPROFILE\.ssh\id_ed25519_hermes_NOME-VM.pub UTENTE@INDIRIZZO:/tmp/
```

Niente incollate, e non è pigrizia: **una chiave incollata che si spezza su
due righe `sshd` non la legge**, e l'errore che ricevi al passo 8 è `Permission
denied (publickey)`, che non nomina la causa. Lo stesso vale per lo scambio
fra le due, che hanno la stessa forma e la stessa lunghezza e si distinguono
solo dal commento finale: passandole per nome di file, lo scambio si vede
mentre si scrive il comando.

`tr -d '\r'` al posto di `cat` c'è perché PowerShell manda le righe con il
fine-riga di Windows, e un `\r` in coda alla chiave finisce dentro il
commento — innocuo nove volte su dieci, e la decima si cerca per mezz'ora.

Se qualcosa non torna, i due comandi che lo dicono sulla VM sono
`cut -d' ' -f1,3- ~/.ssh/authorized_keys`, che stampa tipo e commento di ogni
chiave installata, e `sudo journalctl -u ssh`.

**5. I valori di questa macchina:** utente ammesso da SSH, chiave del servizio
(quella stampata al passo 4), perimetro dei bersagli, regola `ufw`, e il file
dell'indirizzo fisso. Chiede, valida, scrive. Non ricarica `sshd` e non
applica la rete — quelle restano tue, e sono le due da cui non si torna
indietro.

```sh
sudo bin/hermes-configura --chiave /tmp/id_ed25519_hermes_NOME-VM.pub
```

`--chiave` indica il file arrivato col passo 4, così quella risposta non si
incolla. Tutto il resto lo chiede, e per ogni domanda suggerisce il comando
che mostra da dove ricavare la risposta. `--prova` valida tutto e non scrive
niente.

**6. L'indirizzo fisso**, applicato **dalla console della VM** e non da SSH:
cambiando indirizzo la sessione cade, non puoi confermare, e `netplan`
annulla tutto dopo 120 secondi senza dirti perché. Il file l'ha scritto il
passo 5.

```sh
sudo netplan try
```

Poi riconnettiti al nuovo indirizzo — le password funzionano ancora, il passo
9 non è stato fatto. **Viene prima dei passi che seguono per una ragione:
l'indirizzo va fissato prima che qualcosa lo registri**, e da qui in avanti lo
registrano la configurazione ssh, e più tardi Hermes. Se preferisci restare in
DHCP, salta questo passo e usa l'indirizzo corrente, sapendo che cambierà.

**7. Lega la chiave alla VM**, sulla postazione. Il nome del file non è fra
quelli che `ssh` prova da sé, quindi senza questo ogni comando va passato con
`-i` — e dimenticarlo dà `Permission denied (publickey)`, che non dice perché.

```powershell
Add-Content -Path $env:USERPROFILE\.ssh\config -Value @'

Host NOME-VM
    HostName INDIRIZZO
    User UTENTE
    IdentityFile ~/.ssh/id_ed25519_NOME-VM_admin
    IdentitiesOnly yes
'@
```

`NOME-VM` è il nome con cui chiamerai la VM nei comandi `ssh`: scegli il nome
della macchina, non la parola `VM`.

Su Linux lo stesso blocco in `~/.ssh/config`. `IdentitiesOnly yes` non è di
contorno: senza, `ssh` offre anche le altre chiavi che trova, e su una
postazione che serve più di una VM la prima che offre può non essere quella
giusta — lo stesso errore del passo 4, dal lato del client.

**8. Verifica la tua chiave da una finestra nuova**, senza chiudere quella
aperta. Senza le due opzioni `ssh` ricade sulla password senza dirlo, e
concluderesti che funziona.

```sh
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no NOME-VM
```

Qui `NOME-VM` è il nome del blocco `Host` scritto al passo 7, non l'indirizzo:
è quel blocco a dire quale chiave offrire.

**9. Il ricarico di `sshd`**, solo dopo che il passo 8 è entrato.

```sh
sudo sshd -t && sudo systemctl reload ssh
```

**10. Il preflight**, come utente di servizio. È il criterio di accettazione:
non «ho eseguito i passi», ma «i controlli passano».

```sh
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml
```

→ Atteso **`PRONTO`**.

Fuori da questa sequenza: la registrazione in Hermes desktop
([§8–9](docs/setup-vm-hermes.md)) e la spedizione del log d'audit a una
seconda macchina ([§10](docs/setup-vm-hermes.md)), che richiede un collector.

## Natura del progetto

Hermes è una **toolbox difensiva di postura di sicurezza**, sviluppata come progetto
formativo nell'ambito di un percorso ITS in reti e sicurezza informatica (Pisa). Lo
scopo è automatizzare e rendere ripetibili attività di **assessment difensivo** su
sistemi di proprietà dell'autore: inventario della superficie esposta, verifica della
configurazione di sicurezza, rilevamento di vulnerabilità note, hardening guidato e
produzione di report.

Hermes **non è** uno strumento offensivo. Non contiene, non genera e non è destinato a
contenere exploit, payload, codice di persistenza, tecniche di evasione o capacità di
attacco verso sistemi terzi.

## Uso autorizzato e responsabilità

La toolbox è destinata **esclusivamente** ad attività di sicurezza autorizzate, su
target per cui esiste un mandato esplicito:

- macchine virtuali di laboratorio di proprietà dell'autore, su hypervisor locale;
- host per i quali l'autore detiene titolarità diretta o autorizzazione scritta
  esplicita del proprietario.

È fuori perimetro, in modo non negoziabile, qualsiasi sistema, rete o servizio di
terzi non autorizzato. Lo strumento non è progettato per commettere illeciti; l'autore
declina ogni responsabilità per l'uso malevolo da parte di terzi. Quando strumenti
OSINT operano su persone fisiche, l'operatore resta titolare del trattamento ai sensi
del GDPR.

## Struttura del repository

```
hermes-core/
├── mcp_server/        # server MCP: registry tool, risk tier, vault, logging
├── agents/
│   ├── orchestrator/  # orchestratore minimo (invoca un agente, riceve risultato)
│   └── echo_agent/    # agente dummy conforme al contratto (per i test e2e)
├── bin/               # bootstrap, avvio del server, wrapper dei tool, spedizione
├── config/            # *.example.* versionati; copie reali ignorate
├── docs/              # setup della VM, debito di sicurezza, CI, dipendenze
├── logs/              # log d'audit JSONL a runtime (non versionati)
└── tests/             # unit + end-to-end
```

## Requisiti

- Python >= 3.11
- Dipendenze in `pyproject.toml` (`mcp`, `pydantic`)

## I due script del dispiegamento

La sequenza è nell'[installazione](#installazione) qui sopra. Questa sezione
dice **cosa fanno e cosa non fanno**, che è la parte che conta quando qualcosa
non torna.

### `bin/hermes-bootstrap`

Fa il deterministico: utenti, directory, permessi, ACL, gli artefatti che si
installano fuori dall'albero di git, e i file di configurazione quando non ci
sono ancora. Poi chiama il preflight, che è il criterio di accettazione.

Non sovrascrive mai una configurazione esistente, non genera chiavi, non
ricarica `sshd`, non attiva `ufw`, non attiva la spedizione del log. Dove
serve una decisione umana lascia `DA_COMPILARE`, che ogni validatore del
progetto rifiuta: un segnaposto plausibile passerebbe i controlli dando una
configurazione sbagliata, e quello è il guasto peggiore dei due.

Due regole di idempotenza, distinte: gli artefatti la cui fonte è il **repo**
si reinstallano quando differiscono, dichiarandolo; i file che contengono
**decisioni dell'operatore** non si toccano se esistono, qualunque cosa
contengano. Su una macchina già a posto finisce senza cambiare niente.

### `bin/hermes-configura`

Riempie i `DA_COMPILARE` e installa la chiave del servizio. Chiede, valida,
scrive — e `--prova` fa tutto tranne scrivere.

Valida con i validatori veri: il perimetro viene dato al caricatore del
progetto e si installa solo se quello lo accetta; l'utente deve esistere, e
la chiave deve stare su una riga sola, perché una chiave privata incollata
per sbaglio ne ha molte.

Non ricarica `sshd`, non cancella le regole aperte di `ufw`, non applica la
rete. Sono le tre azioni da cui non si torna indietro con un comando: se il
valore è sbagliato, il sintomo è una macchina remota che non si raggiunge
più, e arriva alla prossima connessione invece che adesso.

Entrambi chiudono con **due elenchi distinti**: ciò che hanno verificato e
trovato mancante — che sparisce quando il lavoro è fatto, quindi la sua
assenza è un'informazione — e ciò che non guardano affatto.

### `bin/hermes-collauda-percorsi`

Serve solo se il perimetro dichiara dei `percorsi`, cioè se si registrano
tool che puntano a un file invece che a un host. Prova a uscire dal
perimetro e guarda il kernel dire di no:

```sh
sudo bin/hermes-collauda-percorsi
```

Percorre la catena vera — wrapper installato, file di perimetro, unità
transiente sotto `hermes-tool` — con una sonda che legge un byte al posto di
un tool. Ogni lettura che deve fallire nell'unità ristretta è prima provata
nell'unità normale, dove deve riuscire: un rifiuto che arriva dai permessi
non conta. Dettagli in `docs/setup-vm-hermes.md` §5 e §6.2.

## Setup sviluppo

```sh
python3 -m venv .venv
source .venv/bin/activate      # su zsh/bash
pip install -e ".[dev]"
pytest
```

I test marcati `slow` avviano processi veri e dialogano in MCP su stdio
(~1,5 s l'uno). Durante l'iterazione:

```sh
pytest -m "not slow"
```

## Provare la catena

```sh
cp config/hermes.example.toml config/hermes.toml
python -m mcp_server.doctor config/hermes.toml     # preflight
bin/hermes-core-server                             # resta in attesa su stdio
```

Il **preflight** verifica configurazione, percorsi, permessi del log,
integrità degli script, isolamento dei tool — fino a leggere davvero un byte
di uno script sotto l'identità con cui verrà eseguito — e handshake MCP
reale, e dice cosa fare per ogni problema che trova. Vale la pena eseguirlo
prima di cercare un guasto altrove.

Il server non è pensato per essere usato a mano: parla il protocollo MCP sul
proprio stdin/stdout e si aspetta un client. L'orchestratore in
`agents/orchestrator/` è il client minimo che lo avvia, lo interroga e ne
valida il risultato.

Per il dispiegamento e la registrazione in Hermes desktop:

- [docs/setup-vm-hermes.md](docs/setup-vm-hermes.md) — preparazione della VM
  dedicata: utenti, permessi, chiave SSH vincolata a un comando unico.
- [docs/integrazione-hermes.md](docs/integrazione-hermes.md) — registrazione
  in Hermes e diagnostica.

L'architettura di riferimento tiene il server su una **VM dedicata**, separata
dalle macchine che la toolbox analizza: l'orchestratore custodisce il log
d'audit, il vault e i controlli di scope, e un log che risiede sul bersaglio
vale meno di uno che risiede altrove.

## Stato

**Milestone 0 completa e verificata end-to-end**, integrazione con Hermes
desktop compresa.

Funziona la catena orchestratore → agente → gate di esecuzione → script →
log d'audit, con un unico `correlation_id` dall'invocazione alla riga finale.
L'unico tool registrato è un dummy: **nessun tool di sicurezza reale è ancora
integrato**.

Verificato su dispiegamento reale — Hermes desktop su Windows, server su VM
Ubuntu dedicata raggiunta via SSH con chiave vincolata a un comando unico — su
tre percorsi distinti: l'esecuzione di un tool Verde (`authorized_by: policy`,
nessuna interazione), l'innalzamento di tier con il tier dichiarato che resta
tracciato, e la **sospensione** dello stesso tool dopo l'innalzamento
(`needs_confirmation`, `pending`, script non eseguito). I dettagli e le
condizioni in [docs/integrazione-hermes.md](docs/integrazione-hermes.md).

Le lacune di sicurezza note e consapevolmente non ancora chiuse sono elencate
in [docs/debito-sicurezza.md](docs/debito-sicurezza.md), ciascuna con la
propria condizione di chiusura.

## Licenza

MIT — vedi [LICENSE](LICENSE).
