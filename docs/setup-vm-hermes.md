# Setup della VM dedicata a hermes-core

Architettura di riferimento: **la toolbox non abita sulle macchine che
analizza.**

```
Windows (desktop)              VM hermes (dedicata)            VM di laboratorio
┌────────────────┐             ┌──────────────────────┐        ┌──────────────┐
│ Hermes desktop │──ssh:22────▶│ hermes-core          │───────▶│  bersagli    │
│   (client MCP) │   stdio     │  server MCP + gate   │        │  autorizzati │
└────────────────┘             │  log /var/log/hermes │        └──────────────┘
                               │  (futuro: container) │
                               └──────────────────────┘
```

Perché separata: l'orchestratore custodisce il log d'audit, il vault e i
controlli di scope. Se vivessero sulla stessa macchina che la toolbox valuta,
un laboratorio andato male porterebbe via con sé anche la traccia di cosa è
stato fatto. Un log d'audit che risiede sul bersaglio vale meno di uno che
risiede altrove.

Sostituisci lungo il testo: `<IP-VM>` con l'indirizzo della VM e
`<TUO-UTENTE>` con il tuo utente amministrativo sulla VM.

---

## 1. La VM

**Distro:** Ubuntu Server LTS. Senza ambiente grafico: questa macchina non va
usata interattivamente, e ogni pacchetto in meno è superficie in meno.

**Dimensionamento:** 2 vCPU e 2 GB di RAM bastano per ora. Quando arriverà il
container dell'agente di pentest serviranno più margine — conviene creare il
disco già da 40 GB per non doverlo allargare dopo.

**Rete:** sulla stessa rete VMware delle VM di laboratorio, perché dovrà
raggiungerle, e raggiungibile dalla postazione. Con la **NAT** di VMware la
postazione arriva alla VM attraverso l'adattatore VMnet8 e le VM sulla stessa
VMnet sono raggiungibili; **bridged** è l'alternativa più semplice se la VM
deve essere visibile a tutta la rete; **host-only** la isola dalla rete fisica,
quindi va scelta solo se i bersagli stanno tutti lì.

```sh
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv openssh-server
sudo systemctl enable --now ssh
sudo ufw default deny incoming
sudo ufw allow ssh          # prima di 'enable', o ti chiudi fuori
sudo ufw enable
```

`openssh-server` non è dato per scontato: su Ubuntu Server è presente solo se
è stato selezionato durante l'installazione. Se `systemctl status ssh`
risponde `Unit ssh.service could not be found`, è semplicemente assente.

### Indirizzo fisso

La configurazione di Hermes contiene l'indirizzo della VM, quindi con il DHCP
si romperebbe al primo rinnovo.

Raccogli i dati reali della rete:

```sh
ip -br a                                  # interfaccia e indirizzo attuale
ip route                                  # gateway: la riga "default via X"
resolvectl status | grep -i "DNS Servers"
```

Con la NAT di VMware il gateway è tipicamente `.2` e il pool DHCP parte da
`.128`: un indirizzo sotto il pool, come `.10`, è libero. Con una rete
*bridged* dipende dal router, e vale la pena guardare la sua configurazione —
oppure usare una **riserva DHCP**, che ha il vantaggio di sopravvivere a una
reinstallazione della VM.

```sh
sudo tee /etc/netplan/99-hermes-static.yaml >/dev/null <<'NETPLAN'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:                        # il nome della tua interfaccia
      dhcp4: false
      addresses:
        - 192.168.205.10/24       # indirizzo scelto, fuori dal pool DHCP
      routes:
        - to: default
          via: 192.168.205.2      # il tuo gateway
      nameservers:
        addresses: [192.168.205.2, 1.1.1.1]
NETPLAN
sudo chmod 600 /etc/netplan/99-hermes-static.yaml
sudo netplan try
```

Due dettagli che fanno la differenza:

Il prefisso **`99-`** non è estetico: netplan applica i file in ordine e
l'ultimo vince. Con un nome più basso, il `50-cloud-init.yaml` di Ubuntu
Server sovrascriverebbe questa configurazione.

`netplan try` tiene la configurazione per 120 secondi e la annulla da sola se
non confermi — ma **va eseguito dalla console della VM, non via SSH**:
cambiando indirizzo la sessione SSH cade, non puoi confermare, e netplan
annulla tutto senza che tu capisca perché.

Infine, perché cloud-init non rimetta mano alla rete a un aggiornamento:

```sh
echo 'network: {config: disabled}' | \
    sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```

---

## 2. Utenti e permessi

Il disegno: **chi esegue il server non può modificare ciò che esegue.**

| Chi | Cosa può fare |
|---|---|
| `<TUO-UTENTE>` | proprietario del repo: aggiorna il codice, modifica la config |
| `hermes` | esegue il server: **sola lettura** sul repo, scrittura solo sul log |

È la mitigazione reale della finestra TOCTOU fra verifica dello SHA ed
esecuzione: la verifica protegge dall'errore, ma non da chi può riscrivere gli
script. Se l'utente che esegue non può riscriverli, quella strada è chiusa.

```sh
# Utente di servizio. La shell serve: una shell 'nologin' impedirebbe anche
# al comando vincolato della chiave SSH di partire, e la protezione sta
# nel vincolo, non nell'assenza di shell.
sudo useradd --system --create-home --home-dir /var/lib/hermes \
             --shell /bin/sh hermes
sudo passwd -l hermes      # nessun accesso con password
```

---

## 3. Installazione

```sh
sudo git clone https://github.com/gabriele1701/hermes-core.git /opt/hermes-core
sudo chown -R <TUO-UTENTE>:<TUO-UTENTE> /opt/hermes-core
cd /opt/hermes-core

python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q -m "not slow"     # atteso: verde
```

Poi la configurazione, con il log **fuori dal repo**:

```sh
cp config/hermes.example.toml config/hermes.toml
```

Modifica `config/hermes.toml`:

```toml
[server]
agent = "echo_dummy"
repo_root = "/opt/hermes-core"
log_path = "/var/log/hermes/audit.jsonl"
state_dir = "/var/lib/hermes/state"
container_available = false
```

Il resto del file va bene così.

### Permessi: sola lettura per il servizio

```sh
sudo chown -R <TUO-UTENTE>:hermes /opt/hermes-core
sudo chmod -R o-rwx,g-w,g+rX /opt/hermes-core
```

`g+rX` dà al gruppo lettura e attraversamento delle directory, più
l'esecuzione sui file che erano già eseguibili (il wrapper, i binari del
venv), senza renderli scrivibili. `g-w` toglie la scrittura, `o-rwx` esclude
tutti gli altri.

### Le directory scrivibili dal servizio

```sh
sudo install -d -o hermes -g hermes -m 700 /var/log/hermes
sudo install -d -o hermes -g hermes -m 700 /var/lib/hermes/state
```

Sono gli unici due posti in cui il servizio ha bisogno di scrivere, e stanno
fuori dal repo di proposito: il repo è in sola lettura per l'utente che
esegue, ed è la mitigazione del TOCTOU fra verifica dello SHA ed esecuzione.

`/var/lib/hermes/state` tiene due cose.

Lo **store degli innalzamenti di tier** (`overrides.jsonl`). Senza, un tool
alzato a Rosso dopo un incidente torna al tier dichiarato alla connessione
successiva, perché Hermes avvia un processo nuovo ogni volta. Il server parte
lo stesso e lo dichiara nelle risposte, ma la persistenza è il comportamento
che serve.

I **posti di esecuzione** (`slots/<agente>/`), i file di lock con cui il
limite di esecuzioni contemporanee vale fra le connessioni dello stesso agente
invece che dentro un solo processo. Non vanno irrigiditi con `chattr +a` né
ripuliti a mano: sono file il cui unico contenuto informativo è il lock, che
il kernel rilascia alla morte del processo. La directory nasce alla prima
esecuzione; il preflight verifica in anticipo che possa nascere.

**Se la directory dei posti non è utilizzabile il gate rifiuta ogni
invocazione**, e non è un guasto da aspettare che passi: il tetto condiviso
sarebbe dichiarato dalla configurazione e non applicato, e si eseguirebbe
oltre un limite che tutti credono attivo. Il rimedio è lo stesso comando
`install -d` qui sopra; il preflight lo stampa già quando il controllo
fallisce. La differenza con l'assenza di `state_dir` è che lì il limite
condiviso non è mai stato promesso: il catalogo lo dice con
`concurrency_shared_across_connections: false`.

Anche lo store si può irrigidire con `chattr +a`, per la stessa ragione del
log e con la stessa avvertenza: l'attributo va messo sul **file**, quindi dopo
il primo innalzamento, perché su un file che non esiste non si applica. Il
comando sta più avanti, insieme a quello del log.

La protezione che vale sempre, anche senza `+a`, è un'altra: il tier
dichiarato nella configurazione resta un **pavimento**, e nessuna riga di
questo file può abbassarlo. Il peggio che può fare una riga manomessa è
alzare un tier, cioè chiedere più conferme.

---

## 4. Il canale SSH, vincolato e fuori dalla portata del servizio

Qui sta la parte che vale la pena fare bene. La chiave che userà Hermes **non
deve essere un accesso alla macchina**: deve essere il permesso di avviare
quel server e nient'altro. Se un domani quella chiave finisse altrove, non
darebbe una shell.

E c'è una seconda proprietà, meno ovvia della prima: **la restrizione non deve
stare dove il servizio può cambiarla.** Nella versione precedente di questo
documento il comando vincolato viveva in `/var/lib/hermes/.ssh/authorized_keys`,
dentro la home del servizio e di sua proprietà — e i tool girano come il
servizio. Un tool compromesso poteva togliere il `command=`, aggiungere la
propria chiave, e il canale vincolato diventava una shell senza che una riga di
log lo dicesse. La restrizione era custodita da chi dovrebbe subirla.

### 4.1 La chiave del servizio

Su **Windows**, da PowerShell:

```powershell
ssh-keygen -t ed25519 -C "hermes-core@windows" -f $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp
type $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp.pub
```

Sulla **VM**, la chiave pubblica va in una directory di **root**, non nella home
del servizio, preceduta dalle restrizioni e tutto su una riga:

```sh
sudo install -d -m 755 -o root -g root /etc/ssh/authorized_keys.d
sudo tee /etc/ssh/authorized_keys.d/hermes >/dev/null <<'EOF'
command="/opt/hermes-core/bin/hermes-core-server",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...INCOLLA_QUI... hermes-core@windows
EOF
sudo chmod 644 /etc/ssh/authorized_keys.d/hermes
```

Cosa fa ciascun pezzo:

| Restrizione | Effetto |
|---|---|
| `command="…"` | **comando vincolato**: qualunque cosa chieda il client, parte solo il server. Niente shell. |
| `no-pty` | nessun terminale: un TTY farebbe eco e traduzione dei caratteri, corrompendo il JSON-RPC |
| `no-port-forwarding` | la chiave non può aprire tunnel verso la rete di laboratorio |
| `no-agent-forwarding`, `no-X11-forwarding` | nessuna delega di credenziali, nessuna superficie grafica |

Conseguenza pratica: nel comando di Hermes **non serve indicare lo script**,
perché il vincolo lo impone già. Più avanti, un secondo agente avrà una propria
chiave con il proprio comando vincolato — lo schema regge.

File di root e permessi `644`: deve essere **leggibile** da `sshd` (che lo apre
come root) e **non scrivibile** da nessun altro. Il servizio non ha bisogno di
scriverlo mai.

### 4.2 Il drop-in di sshd

Le stesse restrizioni vanno anche nella configurazione di `sshd`, che il
servizio non può modificare. Le opzioni dentro `authorized_keys` restano come
seconda rete, ma non sono più l'unica.

Il file è versionato nel repo: `config/sshd/10-hermes.conf`. Prima di
installarlo, **verifica che `sshd` legga i drop-in**:

```sh
grep -n '^Include' /etc/ssh/sshd_config
sed -n "1,$(grep -n '^Include' /etc/ssh/sshd_config | cut -d: -f1)p" \
    /etc/ssh/sshd_config | grep -vE '^\s*#|^\s*$|^Include'
```

Il primo comando deve trovare `Include /etc/ssh/sshd_config.d/*.conf`; il
secondo deve stampare **niente**. In `sshd` vince il **primo** valore
incontrato, quindi un `Include` in fondo al file, o preceduto da direttive
attive, lascia vincere quelle e il drop-in resta inerte — installato e senza
effetto, che è il falso verde peggiore possibile. Debian 12 e Ubuntu ≥ 22.04 lo
hanno in cima; su distribuzioni più vecchie va aggiunto a mano come prima riga.

```sh
sudo install -m 644 -o root -g root \
    config/sshd/10-hermes.conf /etc/ssh/sshd_config.d/10-hermes.conf
sudo sshd -t
```

`sshd -t` deve stampare niente. Poi guarda **cosa sarà attivo**, non cosa c'è
scritto nel file:

```sh
sudo sshd -T | grep -iE 'passwordauthentication|permitrootlogin|authenticationmethods|allowusers'
sudo sshd -T -C user=hermes | grep -iE 'forcecommand|authorizedkeysfile|permittty'
```

`sshd -T` stampa la configurazione effettiva dopo tutti gli include e i merge:
è la differenza fra leggere un file e sapere cosa farà. Attesi
`passwordauthentication no`, `authenticationmethods publickey`, e per `hermes`
il `forcecommand` e `authorizedkeysfile /etc/ssh/authorized_keys.d/hermes`.

> **Il drop-in disattiva l'accesso con password per tutti.** Prima di
> ricaricare `sshd`, assicurati di avere una chiave funzionante anche per
> l'utente amministrativo, verificata forzando il metodo:
>
> ```
> ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no utente@vm
> ```
>
> Senza `-o`, `ssh` ricade sulla password **senza dirlo**: entreresti,
> concluderesti che la chiave funziona, e dopo il reload ti troveresti fuori.
> Modifica `AllowUsers` nel drop-in se l'utente amministrativo ha un altro
> nome.

```sh
sudo systemctl reload ssh
```

La sessione aperta sopravvive al reload: **non chiuderla** finché una seconda
connessione nuova non ha funzionato. Per tornare indietro basta
`sudo rm /etc/ssh/sshd_config.d/10-hermes.conf && sudo systemctl reload ssh`.

Infine, togli il file che non è più letto:

```sh
sudo rm /var/lib/hermes/.ssh/authorized_keys
```

Lasciarlo significa che la prossima modifica a quelle chiavi verrà fatta nel
file sbagliato, senza effetto e senza errore. Il preflight lo segnala.

### 4.3 Il perimetro di rete

Gli indirizzi **non** stanno nel drop-in: quello è versionato, e un indirizzo è
per-installazione. Il perimetro lo definisce `ufw`, con l'IP della postazione
da cui Hermes si connette — che si legge dal server, invece di dedurlo:

```sh
echo $SSH_CONNECTION        # il primo valore è l'IP del client
sudo ufw allow from <IP-postazione> to any port 22 proto tcp comment 'SSH postazione Hermes'
sudo ufw status numbered
```

Poi cancella le regole `22/tcp ALLOW IN Anywhere` **per numero, partendo dal più
alto** (ce ne sono due, v4 e v6; cancellare rinumera le altre):

```sh
sudo ufw delete <numero più alto>
sudo ufw delete <numero più basso>
sudo ufw status verbose
```

Deve restare una sola regola per la 22, con la sorgente della postazione. In
caso di problemi, `sudo ufw allow 22/tcp` dalla sessione aperta rimette tutto
come prima.

**Un solo indirizzo e non la sottorete**, anche se la sottorete è "solo il
laboratorio": su quella rete finiranno le altre VM del progetto, compresa quella
di pentest, che per definizione esegue codice ostile. Con la sottorete aperta,
quella VM raggiungerebbe la porta 22 del server MCP.

### 4.4 La chiave privata sulla postazione

Lato Windows la chiave privata va protetta con le ACL, perché è l'unica cosa
che sta fra un processo locale e il canale verso la VM:

```powershell
icacls $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp /inheritance:r /grant:r "${env:USERNAME}:(R)"
icacls $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp
```

`/inheritance:r` rompe l'ereditarietà dalla cartella, `/grant:r` sostituisce i
permessi con il solo utente in lettura. Nell'output non devono comparire
`Users`, `Everyone` o altri account utente.

`BUILTIN\Administrators` e `NT AUTHORITY\SYSTEM` restano, e **va bene**: un
amministratore locale può in ogni caso prendere la proprietà del file e
riassegnarsi i permessi, quindi togliere quelle voci dà un output più pulito e
zero sicurezza in più. Se un attaccante ha quei privilegi, la chiave è l'ultimo
dei problemi.

**La chiave del servizio non ha passphrase, ed è una scelta.** Il motivo: per un
uso non interattivo la passphrase deve stare permanentemente nell'`ssh-agent`,
che su Windows persiste le chiavi nel registro cifrate con DPAPI dell'utente —
estraibili da chi ha quel contesto. La passphrase proteggerebbe quindi dalla
*copia del file*, non da un processo locale compromesso, e in cambio
introdurrebbe una dipendenza operativa: con l'agente spento, Hermes chiede una
passphrase a un canale non interattivo e la connessione fallisce con un errore
che non punta alla causa. La protezione a riposo è l'ACL; il perimetro è il
comando vincolato più la regola `ufw`, che rende quella chiave inutile da
qualunque altra macchina.

Se un'installazione preferisce la passphrase, si aggiunge senza rigenerare la
chiave e senza toccare la VM — la parte pubblica non cambia:

```powershell
ssh-keygen -p -f $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp
Get-Service ssh-agent | Set-Service -StartupType Automatic   # altrimenti al riavvio non parte
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519_hermes_mcp
```

L'avvio automatico del servizio è il passaggio che si dimentica, e il guasto
compare solo al riavvio successivo.

---

## 5. Il perimetro dei bersagli

Serve solo se almeno un tool dichiara `target_kind` diverso da `"none"`. Finché
nessuno lo fa — come in Milestone 0 con `echo.ping` — si può saltare, e il
preflight lo dice con un avviso invece di un errore.

Il problema che chiude: l'argomento `target` di un'invocazione è scelto dal
**modello**. Un testo malevolo nel contesto di un agente non deve poter
spostare uno scan su una rete che non è del laboratorio. Finché nessun tool
usava il bersaglio la cosa era inerte; con i tool reali diventa il punto più
direttamente sfruttabile da una prompt injection.

### Dove va il file, e perché non in `state_dir`

```sh
sudo install -d -m 755 -o root -g root /etc/hermes
sudo install -m 644 -o root -g root config/scope.example.toml /etc/hermes/scope.toml
sudo nano /etc/hermes/scope.toml      # mettere le proprie reti e i propri alias
```

Poi in `hermes.toml`, sezione `[server]`:

```toml
scope_file = "/etc/hermes/scope.toml"
```

Di **root**, e non dentro `state_dir`: quella è scrivibile dal servizio, e un
tool compromesso che potesse riscrivere la propria allowlist non avrebbe
un'allowlist. È la stessa forma di HC-04 — una restrizione custodita da chi la
subisce non è una restrizione. Il preflight verifica proprietario e permessi,
non si fida della documentazione.

Leggibile da tutti va bene: il perimetro non è un segreto, è un vincolo.

### Niente DNS, e alias al suo posto

```toml
reti = ["192.168.205.0/24"]

[alias]
lab-web = "192.168.205.20"
```

Il `target` di un'invocazione deve essere un **indirizzo IP** dentro una delle
reti, oppure un **alias dichiarato qui**. Non si risolvono nomi: un nome
risolto al momento del controllo può puntare altrove al momento
dell'esecuzione (DNS rebinding), può risolvere a più indirizzi, e dipende da un
servizio che non è nel perimetro. Un alias si risolve leggendo un file di root:
non si avvelena e non cambia sotto il controllo.

Due regole che il caricamento impone, e che fa fallire l'avvio se violate:

* le reti vanno in **forma canonica** — `192.168.205.0/24` sì,
  `192.168.205.10/24` no. Il secondo verrebbe interpretato come l'intera `/24`,
  cioè un perimetro più largo di quello inteso;
* un alias deve puntare a un indirizzo **dentro** le reti dichiarate, perché
  altrimenti il file direbbe nello stesso momento che quell'indirizzo è
  ammesso e che non lo è.

Nel log restano entrambi: il nome chiesto dal modello e l'indirizzo raggiunto.

### Cosa succede quando manca

Tre casi distinti, e tenerli distinti è il punto:

| Situazione | Comportamento |
|---|---|
| `scope_file` non configurato, nessun tool con bersaglio | Il server funziona. Avviso nel preflight, `scope_configured: false` nel catalogo |
| `scope_file` non configurato, ma un tool dichiara un bersaglio | Quel tool **non è invocabile**: il gate rifiuta, e il preflight dà errore. L'assenza di perimetro non vale come «tutto ammesso» |
| `scope_file` configurato e non caricabile | **Il server non parte.** Un perimetro promesso e non applicabile è peggio di uno assente, perché nessuno sa di averlo perso |

### Come arriva il bersaglio al tool

```
<interprete> -I -S <script> <exec_args...> -- <bersaglio validato>
```

Il separatore `--` non è cosmetico: senza, un bersaglio che inizia per `-`
verrebbe letto come **opzione** dal tool — injection di argomenti, la sola
forma che sopravvive quando non c'è una shell. Il perimetro rifiuta già quei
bersagli; il separatore è il secondo dei due meccanismi, perché un controllo
che dipende da un solo punto non è un controllo.

`exec_args` sono gli argomenti **fissi** del tool, dichiarati
all'integrazione. Fanno parte dell'identità di ciò che viene eseguito —
`(exec_path, exec_sha256, exec_args)` — e servono a distinguere due
sottocomandi dello stesso script a rischio diverso da un alias abusivo: a
identità identica e tier inferiore la registrazione viene **rifiutata**.

### Verificare

```sh
sudo -u hermes /opt/hermes-core/.venv/bin/python \
     -m mcp_server.doctor /opt/hermes-core/config/hermes.toml
```

Il referto deve mostrare le reti e gli alias caricati, e dichiarare che non c'è
risoluzione DNS.

Un controllo visto solo verde non dice molto. Per esercitare il perimetro
serve un tool che dichiari un bersaglio, e nessuno di quelli della Milestone 0
lo fa: in `config/hermes.example.toml` c'è un blocco `[[tool]]` commentato,
`echo.bersaglio`, che riusa lo script del dummy con `target_kind = "host"` e
`exec_args = ["--bersaglio"]`. Scommentarlo (con lo SHA dello script, lo
stesso di `echo.ping`) e ricaricare il server.

Tre invocazioni, che insieme coprono ciò che il perimetro promette:

| Invocazione | Atteso |
|---|---|
| `echo.bersaglio` su un alias dichiarato | `ok`, e nell'output `args` contiene `["--bersaglio", "--", "<indirizzo>"]` — l'alias risolto dal file, non dal DNS |
| `echo.bersaglio` su un indirizzo fuori perimetro (es. `192.0.2.1`, che non è instradabile) | `denied`, con `fuori dal perimetro` nel motivo e il bersaglio tentato nella riga di log |
| `echo.ping` con un bersaglio | `denied`: dichiara `target_kind = "none"`, quindi un bersaglio è un rifiuto e non un valore ignorato |

Vale la pena anche la verifica di controllo — `echo.ping` **senza** bersaglio
deve funzionare — perché conferma che il rifiuto è selettivo sull'argomento di
troppo e non un tool rotto.

Nessuna di queste tocca la rete: lo script stampa `argv` e termina. Il
bersaglio è una stringa che arriva a un eseguibile che non la usa, ed è
esattamente ciò che serve per collaudare il gate senza che nulla venga
contattato.

`echo.bersaglio` conviene tenerlo registrato fino all'ingresso del primo tool
reale: è l'unico modo di riesercitare il perimetro dopo una modifica alla
configurazione o un aggiornamento, e l'alternativa è ricrearlo ogni volta.
Quando arriva un tool con un bersaglio vero, va tolto.

---

## 6. L'identità separata dei tool

Fino a qui i tool giravano con l'identità del **servizio**. Un tool compromesso
— o semplicemente un tool che fa più del previsto — poteva quindi leggere e
scrivere tutto ciò che il server possiede: lo store degli innalzamenti di tier,
i posti di esecuzione, e soprattutto **il log d'audit**, cioè la traccia che
dovrebbe registrarlo. Un presidio la cui prova è alterabile da chi dovrebbe
subirlo non è un presidio.

A1 sposta i tool su un uid dedicato e senza shell, e li racchiude in limiti di
risorsa che il gate da solo non può imporre.

### 6.1 L'utente dei tool

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hermes-tool
```

Nessuna home e nessuna shell: se un giorno quelle credenziali finissero
altrove, non darebbero un accesso. Il nome `hermes-tool` è una convenzione del
progetto — compare nel wrapper e nel preflight, e un test verifica che le due
copie coincidano, perché uno script di shell non può importare una costante
Python.

### 6.2 Il wrapper, e cosa ci sta dentro

```sh
sudo install -m 755 -o root -g root bin/hermes-tool-run /usr/local/sbin/hermes-tool-run
```

**Fuori dall'albero di git, non dentro.** Nel repo il wrapper è un artefatto
versionato; installato è codice privilegiato, e un `git checkout` di un altro
branch cambierebbe ciò che la riga di `sudoers` autorizza — senza che nessuno
lo decida e senza che niente lo dica. Stessa ragione per cui il drop-in di
`sshd` e il file di perimetro si installano invece di essere letti dal repo.

Ne segue anche una conseguenza operativa: **dopo un aggiornamento del repo il
wrapper va reinstallato**, altrimenti la macchina gira con la versione
precedente. `diff` risponde alla domanda:

```sh
diff /usr/local/sbin/hermes-tool-run /opt/hermes-core/bin/hermes-tool-run
```

Di **root**, e il gate rifiuta di eseguire se non lo è. Dentro ci stanno le
cose che il chiamante non deve poter scegliere: l'uid, il gid, i tetti di
memoria e di processi, e il tetto massimo sul tempo. Dal chiamante arrivano
solo il nome dell'unità e il comando.

È la stessa forma del canale SSH (§4) e del perimetro dei bersagli (§5): *una
restrizione custodita da chi la subisce non è una restrizione.*

Il meccanismo è un'unità transiente di **tipo servizio**, non uno scope:

```
systemd-run --pipe --wait --quiet --unit=hermes-tool-<correlation_id> \
    --uid=hermes-tool --gid=hermes-tool \
    -p MemoryMax=1G -p MemorySwapMax=0 -p TasksMax=128 -p RuntimeMaxSec=<n> \
    -- <comando>
```

Con `--scope` il processo sarebbe lanciato da chi chiama, e il cambio di uid lo
dovrebbe fare `systemd-run` stesso — che gira non privilegiato e fallisce con
`Failed to change GID`. Con un'unità di tipo servizio il processo lo lancia
PID 1, che può cambiare identità. `--pipe` ricollega stdin, stdout e stderr al
chiamante; `--wait` attende la fine.

`--quiet` non è pulizia: senza, le righe di stato di systemd («Running as
unit…», «Finished with result…») finiscono sullo **stderr del chiamante**, e il
gate le catturerebbe mescolate all'errore vero del tool.

**`MemorySwapMax=0` è necessario, non ridondante.** `MemoryMax` da solo limita
la memoria *residente*: misurato, un processo che chiede 500 MB con
`MemoryMax=64M` arriva in fondo con esito 0, spingendo 444 MB nello swap. La
macchina non va in OOM ma può essere portata a nuotare nello swap — una
negazione di servizio con un altro nome, mentre il log dice che è andato tutto
bene.

**I tetti sono generosi e non calibrati, di proposito.** Senza un tool reale non
si sa quanto consumi un `nmap -A` su una /24. Un tetto largo e dichiarato è una
misura onesta; un tetto stretto indovinato è il primo scan ucciso a metà, con
un sintomo — un figlio morto con un codice strano — che non punta alla causa.
Si stringono quando c'è qualcosa da misurare: è una voce aperta in
`docs/debito-sicurezza.md`.

### 6.3 Il privilegio concesso

```sh
sudo install -m 440 -o root -g root config/sudoers.example /etc/sudoers.d/hermes-core
sudo visudo -c
```

Una riga sola, sul solo wrapper. I permessi `0440` servono: `sudo` rifiuta di
leggere un file di `/etc/sudoers.d` scrivibile da altri.

La regola permette qualunque argomento, e **va bene**: il wrapper fissa l'uid
al suo interno, quindi `hermes` può far eseguire comandi solo come
`hermes-tool`, che ha *meno* privilegi di `hermes`. Non è un'escalation — il
modello di minaccia di A1 è il tool, non il server.

Cosa invece **non** va fatto: allargare la regola a `systemd-run` o a
`systemctl`. Con `systemd-run` libero si potrebbe avviare un'unità
`--uid=root`; con `systemctl` libero, fermare qualunque servizio della
macchina.

Poi la configurazione, in `[server]`:

```toml
tool_runner = "/usr/local/sbin/hermes-tool-run"
```

### 6.4 Il tempo limite, su due livelli

`RuntimeMaxSec` sta deliberatamente **sotto** il timeout del gate, così systemd
vince sempre per primo. È l'unico che può terminare l'albero dei processi
dentro il cgroup: da quando c'è un'unità in mezzo, uccidere il gruppo di
processi raggiunge `sudo` e `systemd-run`, non il tool.

Il timeout del gate resta la rete di riserva, e scatta solo se systemd ha
fallito: in quel caso il gate chiama `hermes-tool-run --stop <unità>`. Se anche
quello non riesce, la cosa finisce nel log — un residuo invisibile è peggio di
un residuo noto.

### 6.5 La causa nel log, non un «1» generico

`systemd-run --wait` torna 1 sia per un tool che fallisce da sé, sia per uno
ucciso dal tetto di memoria, sia per uno fermato dal tempo limite: tre cause
con rimedi diversi dietro lo stesso numero. Il wrapper legge `ExecMainCode` e
`ExecMainStatus` dall'unità **prima** di rimuoverla, e propaga l'esito con la
convenzione della shell — ucciso da segnale → `128+segnale`. Quindi OOM
diventa `137` e il tempo limite `143`.

Per la causa esatta c'è il **journal**, e il nome dell'unità contiene il
`correlation_id` che si legge nel log d'audit:

```sh
journalctl -u hermes-tool-<correlation_id> --no-pager
```

Deve comparire una riga come `Failed with result 'oom-kill'`, insieme al
consumo di picco.

> **Non usare `systemctl show` o `systemctl status` dopo il fatto.** Il wrapper
> rimuove l'unità con `reset-failed` appena ne ha letto l'esito, e `systemctl
> show` su un'unità **inesistente** non dà errore: restituisce i valori di
> default, cioè `Result=success` e `ExecMainStatus=0`. Su un'esecuzione uccisa
> dal tetto di memoria risponderebbe «successo».
>
> Misurato durante il collaudo del passo 9: `systemctl show` diceva `success`
> mentre il journal, per la stessa unità e lo stesso istante, diceva
> `oom-kill`. Il journal è l'autorità; il wrapper legge l'esito **prima** di
> ripulire, ed è per questo che il `137` arriva corretto al chiamante.

Guadagno collaterale: un processo rimasto in giro si ricollega all'invocazione
che l'ha generato. Prima un orfano era anonimo.

### 6.6 Verificare

```sh
sudo -u hermes /opt/hermes-core/.venv/bin/python \
     -m mcp_server.doctor /opt/hermes-core/config/hermes.toml
```

Quattro controlli distinti, e sono distinti di proposito: il wrapper esiste ed
è di root; l'utente dei tool esiste e non ha shell; `sudo -n` sul wrapper
riesce **senza password**; log e stato restano fuori dalla portata dei tool.

La terza è una sonda vera: il preflight esegue `hermes-tool-run --stop` su
un'unità riservata e inesistente, che non fa nulla ma esercita esattamente il
privilegio. Se `sudo` non è autorizzato si scopre lì, invece che alla prima
invocazione.

Un controllo visto solo verde non dice molto. Vale la pena vederlo dire no:

```sh
sudo chmod 644 /usr/local/sbin/hermes-tool-run   # non più eseguibile
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml | grep -i wrapper
sudo chmod 755 /usr/local/sbin/hermes-tool-run   # ripristino
```

Deve dare `[ERRORE] wrapper di isolamento`, e in quello stato il gate rifiuta
ogni invocazione invece di ricadere sull'identità del servizio.

---

## 7. Verificare dalla VM

Il preflight va eseguito **come l'utente di servizio**, sempre:

```sh
sudo -u hermes /opt/hermes-core/.venv/bin/python \
     -m mcp_server.doctor /opt/hermes-core/config/hermes.toml
```

Non è un dettaglio di comodità. Il preflight risponde alla domanda «il server
funzionerà?», e il server gira come `hermes`: lanciarlo dal proprio account
risponde a una domanda diversa, e le due risposte divergono proprio dove
conta.

Due esempi visti sul campo:

* `/var/log/hermes` è `0700` di `hermes`, quindi dal proprio account il log
  risulta **non scrivibile** e il preflight dà ERRORE su un dispiegamento che
  funziona benissimo;
* il controllo sulla *scrivibilità del codice* — la mitigazione reale del
  TOCTOU — dal proprietario del repo non può rispondere e si dichiara non
  applicabile. Solo eseguito come `hermes` verifica davvero che il servizio
  non possa riscrivere gli script che esegue.

* il controllo sul **canale del servizio** confronta ciò che dichiara il
  drop-in di `sshd` con ciò che risulta sul filesystem, e se divergono vince
  la misura: dice ERRORE se il file che autorizza il canale appartiene al
  servizio o è scrivibile da altri, anche quando la configurazione sembra a
  posto. La verifica autorevole della configurazione effettiva resta
  `sudo sshd -T -C user=hermes`, che richiede root e quindi non è alla
  portata del preflight: il messaggio del controllo lo dice, invece di far
  credere il contrario.

La seconda è la ragione per cui vale la pena fare così anche quando il primo
modo sembra funzionare: un verde ottenuto dall'utente sbagliato è un verde su
meno controlli.

### Rendere log e store non riscrivibili

Da fare **dopo** il primo avvio, perché i file devono esistere. Lo store
nasce al primo innalzamento di tier, quindi il suo `+a` va messo dopo:

```sh
sudo chattr +a /var/log/hermes/audit.jsonl
lsattr /var/log/hermes/audit.jsonl      # deve mostrare 'a'

# dopo il primo raise_tool_tier:
sudo chattr +a /var/lib/hermes/state/overrides.jsonl
lsattr /var/lib/hermes/state/overrides.jsonl
```

Da quel momento quei file si possono solo accrescere: nessun processo non
privilegiato può troncarli o riscriverli, incluso il nostro. Entrambi gli
scrittori lo tollerano per costruzione — scrivono in `O_APPEND` e non
insistono sulla `chmod`, che un file append-only rifiuta anche al
proprietario.

### Annullare un innalzamento di tier

Da sapere **prima** di alzare un tier in produzione: il tier può solo salire,
e con lo store persistente resta salito. Un tool portato a Rosso richiede
conferma, e finché il canale di conferma non è collegato quel tool **non è più
invocabile e non torna da solo**. Prima della persistenza si curava
riconnettendosi; ora no.

Si torna indietro solo da qui, con i privilegi della macchina. È voluto: un
declassamento è un atto deliberato di chi amministra, non una chiamata che il
modello possa fare.

```sh
# 1. togliere l'append-only, se è stato messo
sudo chattr -a /var/lib/hermes/state/overrides.jsonl

# 2. riscrivere il file senza le righe del tool da riportare giù
sudo -u hermes grep -v '"tool_id": "echo.ping"' \
     /var/lib/hermes/state/overrides.jsonl > /tmp/overrides.new
sudo -u hermes cp /tmp/overrides.new /var/lib/hermes/state/overrides.jsonl
rm /tmp/overrides.new

# 3. rimetterlo, se lo si vuole
sudo chattr +a /var/lib/hermes/state/overrides.jsonl
```

Poi `/reload-mcp` in Hermes: il server rilegge lo store all'avvio, quindi
finché il processo è vivo continua ad applicare il tier vecchio.

Per azzerare **tutti** gli override in un colpo — utile in laboratorio, da non
fare a cuor leggero altrove, perché cancella anche innalzamenti decisi
apposta:

```sh
sudo -u hermes truncate -s 0 /var/lib/hermes/state/overrides.jsonl
```

In nessuno dei due casi si può scendere sotto il tier **dichiarato** in
configurazione: quello è un pavimento, e rimuovere righe non lo tocca.

Un `override_tier` scritto in `[[tool]]` non si rimuove da qui: si toglie
dalla configurazione versionata, che è il posto in cui è stato messo.

---

## 8. Verificare da Windows

Prima di configurare Hermes, la prova che conta — da PowerShell:

```powershell
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' | ssh -T -q hermes@<IP-VM>
```

Deve stampare **una riga** che inizia con `{"jsonrpc":"2.0","id":1,"result":`.

Se stampa quello, il canale è pulito: SSH trasporta stdin e stdout in modo
trasparente, il comando vincolato funziona, e Hermes si comporterà allo stesso
modo. Se chiede una password, l'autenticazione a chiave non è a posto; se
stampa testo misto o righe spezzate, è il canale.

---

## 9. Registrare in Hermes

Sull'Hermes di Windows:

```
hermes mcp add hermes_core --command ssh --args -T -q hermes@<IP-VM>
hermes mcp list
hermes mcp test hermes_core
```

Poi `/reload-mcp` in una sessione. I tool compaiono col prefisso del server:

```
mcp__hermes_core__list_available_tools
mcp__hermes_core__describe_tool
mcp__hermes_core__invoke_tool
mcp__hermes_core__raise_tool_tier
```

La prova finale è invocare `echo.ping`: deve restituire `status: "ok"` e, in
`output.stdout`, il JSON dell'agente dummy. Contemporaneamente, sulla VM:

```sh
sudo tail -f /var/log/hermes/audit.jsonl
```

devono comparire le righe della catena sotto un unico `correlation_id`.

---

## 10. Cosa resta per le milestone successive

**Container runtime** (Docker o Podman) sulla VM, per l'agente di pentest: è
la ragione per cui il disco è stato dimensionato con margine. Finché
`container_available = false`, i tool che lo richiedono vengono negati invece
di ricadere sull'host — comportamento voluto.

**Backend reale del vault** (`pass`), al posto dello stub. Dentro ci andranno
solo le credenziali delle VM di laboratorio.

**Spedizione del log** a un collector esterno: è la difesa che conta davvero
contro la manomissione, più dell'append-only locale.

**Un secondo agente**, con la propria configurazione, il proprio utente di
servizio e la propria chiave vincolata.
