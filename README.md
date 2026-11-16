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

**4. Le due chiavi**, sulla **postazione**, non sulla VM. Una è **tua**, per
entrare quando il passo 9 avrà spento le password; l'altra è del
**servizio**, per Hermes. Il passo 5 le installa entrambe.

In PowerShell. L'unica cosa da sostituire è `NOME-VM` nella prima riga: il
nome che la VM stampa con `hostname`.

```powershell
$VM = "NOME-VM"
ssh-keygen -t ed25519 -C "admin@$VM"              -f "$env:USERPROFILE\.ssh\id_ed25519_${VM}_admin"
ssh-keygen -t ed25519 -C "hermes-core@postazione" -f "$env:USERPROFILE\.ssh\id_ed25519_hermes_$VM"
type "$env:USERPROFILE\.ssh\id_ed25519_${VM}_admin.pub"
type "$env:USERPROFILE\.ssh\id_ed25519_hermes_$VM.pub"
```

Alla domanda sulla passphrase: per la chiave del **servizio** lascia vuoto,
perché Hermes si collega senza nessuno davanti a digitarla; per la tua,
decidi tu. Lascia aperta la finestra: le due righe stampate servono al passo 5.

Il nome della VM nel nome del file non è decorazione. Con un nome fisso, la
seconda VM servita dalla stessa postazione fa chiedere *«already exists.
Overwrite?»*, e un sì distratto cancella la chiave della prima. E dev'essere
proprio quello di `hostname`, perché il passo 5 lo usa per scriverti il
blocco del passo 7.

**5. I valori di questa macchina:** chi può entrare, le due chiavi, il
perimetro dei bersagli, la regola `ufw`, il file dell'indirizzo fisso.
Chiede, valida, scrive, e per ogni domanda mostra il comando da cui ricavare
la risposta.

```sh
sudo bin/hermes-configura
```

Le chiavi si incollano: copia la riga intera stampata al passo 4. Una chiave
spezzata dall'incollata, o le due chiavi scambiate, vengono rifiutate con il
motivo. Sono gli errori più facili di tutta la procedura, e senza questo
controllo arrivano al passo 8 come un `Permission denied` che non dice
perché.

Non ricarica `sshd` e non applica la rete: sono le due azioni da cui non si
torna indietro, e restano tue. In fondo stampa il blocco del passo 7 già
compilato. `--prova` valida tutto e non scrive niente.

**6. L'indirizzo fisso**, applicato **dalla console della VM** e non da SSH:
cambiando indirizzo la sessione cade, non puoi confermare, e `netplan`
annulla tutto dopo 120 secondi senza dirti perché. Il file l'ha scritto il
passo 5.

```sh
sudo netplan try
```

Poi riconnettiti al nuovo indirizzo: le password funzionano ancora, il passo
9 non è stato fatto. **L'indirizzo va fissato prima che qualcosa lo
registri**, e da qui in avanti lo registrano la configurazione ssh e, più
tardi, Hermes. Se preferisci restare in DHCP, salta questo passo, sapendo che
l'indirizzo cambierà.

**7. Lega la chiave alla VM**, sulla postazione: incolla in PowerShell il
blocco che il passo 5 ha stampato in fondo, già compilato con il nome,
l'indirizzo e l'utente di questa macchina. Se l'hai perso, rilancia
`sudo bin/hermes-configura --prova` e rispondi `N` alle domande: non scrive
niente, e lo ristampa.

Serve perché il nome del file della chiave non è fra quelli che `ssh` prova
da sé: senza questo blocco ogni comando va passato con `-i`, e dimenticarlo
dà `Permission denied (publickey)`. `IdentitiesOnly yes` impedisce a `ssh` di
offrire prima altre chiavi, che su una postazione con più VM possono essere
quelle sbagliate. Su Linux, lo stesso blocco va in `~/.ssh/config`.

**8. Verifica la tua chiave da una finestra nuova**, senza chiudere quella
aperta. Senza le due opzioni `ssh` ricade sulla password senza dirlo, e
concluderesti che funziona.

```sh
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no NOME-VM
```

Qui `NOME-VM` è il nome del blocco `Host` scritto al passo 7, non l'indirizzo:
è quel blocco a dire quale chiave offrire.

Se non entra, la causa si legge sulla VM: `cut -d' ' -f1,3- ~/.ssh/authorized_keys`
stampa tipo e commento di ogni chiave installata, e `sudo journalctl -u ssh`
dice perché `sshd` l'ha rifiutata.

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
