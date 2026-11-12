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

### 6.4 L'accesso agli script

I tool ora girano come `hermes-tool`, che **non è nel gruppo `hermes`**: i
permessi del punto 3 (`o-rwx,g-w,g+rX`) non gli danno nulla, nemmeno il
transito sulla radice del repo. Senza una concessione esplicita il primo tool
fallisce con `Permission denied`, e quell'errore arriva dal tool: non nomina
la causa, e manda a cercare un bug dove c'è un'ACL mancante.

La concessione è mirata e va letta come tale: transito sulla radice e nient'altro,
lettura solo di `agents/`.

```sh
sudo setfacl -m u:hermes-tool:--x /opt/hermes-core
sudo setfacl -R -m u:hermes-tool:rX /opt/hermes-core/agents
sudo setfacl -R -d -m u:hermes-tool:rX /opt/hermes-core/agents
```

`--x` sulla radice dà l'attraversamento senza la lettura: `hermes-tool` può
scendere verso `agents/`, non elencare il repo. `rX` dà lettura e
attraversamento delle directory senza aggiungere il bit di esecuzione ai file
che non ce l'hanno. La terza riga imposta l'ACL **di default**, cioè quella
che i file creati dopo erediteranno: senza, il primo tool aggiunto in futuro
ripeterebbe lo stesso guasto.

Restano fuori portata `config/` (che contiene i percorsi e i nomi dei
segreti), `docs/`, `mcp_server/` e il virtualenv. È minimo privilegio
applicato al codice: un tool ha bisogno di leggere *gli script dei tool*, non
il server che decide se può essere eseguito.

Verificare con `getfacl`, oppure — meglio — lasciando che sia il preflight a
leggere davvero un byte (vedi 6.7).

> **`test -r` e `getfacl` rispondono a due domande diverse.** `test -r`
> interroga `access(2)`, che con le ACL POSIX ha già negato una lettura che
> **funzionava**. Un controllo deve riprodurre l'operazione che diagnostica,
> ed è per questo che il preflight apre il file invece di chiedere se
> potrebbe.

#### Due cause, un sintomo solo

Le concessioni sono due — il transito sulla radice e la lettura di `agents/` —
e se ne manca una qualsiasi il preflight dà lo stesso errore, con lo stesso
percorso e lo stesso rimedio:

```
[ERRORE] lettura degli script dai tool: hermes-tool non riesce ad aprire
         1 script su 1 provati: /opt/hermes-core/agents/echo_agent/run.py
         (echo.bersaglio, echo.ping): PermissionError: [Errno 13]
         Permission denied: '/opt/hermes-core/agents/echo_agent/run.py'
```

Non è una sciatteria del messaggio: **il kernel non distingue i due casi**.
`open()` su un percorso di cui un antenato non è attraversabile restituisce
`EACCES` sul percorso intero, identico a quello di un file non leggibile. La
sonda riporta ciò che ha misurato invece di dedurre quale delle due sia — una
causa plausibile ma non verificata, qui, sarebbe peggio del silenzio, perché
verrebbe creduta.

Il rimedio elenca **entrambe** le concessioni, quindi riapplicandolo si ripara
in ogni caso: i tre comandi sono idempotenti e rimetterli tutti e tre non ha
controindicazioni. Chi vuole sapere *quale* mancava lo chiede a `getfacl`,
che qui è lo strumento giusto perché la domanda è «com'è configurato», non
«funziona»:

```sh
getfacl -p /opt/hermes-core        | grep hermes-tool   # atteso: user:hermes-tool:--x
getfacl -p /opt/hermes-core/agents | grep hermes-tool   # atteso: user:hermes-tool:r-x
```

Quello che manca è quello che non compare. Attenzione a leggere la riga
giusta: su `agents/` compaiono sia `user:hermes-tool:r-x` sia
`default:user:hermes-tool:r-x`, e sono due cose diverse — la prima vale per i
file che ci sono, la seconda per quelli che verranno.

Distinguerle nel preflight costerebbe una sonda per ogni componente del
percorso, eseguita solo nel ramo di guasto. Non si fa finché gli script
stanno tutti sotto `agents/`: sostituirebbe un rimedio completo con un rimedio
più corto, al prezzo di codice che si esercita solo quando qualcosa è già
rotto. Se un giorno gli script vivranno in più rami dell'albero, la domanda
torna.

### 6.5 Il tempo limite, su due livelli

`RuntimeMaxSec` sta deliberatamente **sotto** il timeout del gate, così systemd
vince sempre per primo. È l'unico che può terminare l'albero dei processi
dentro il cgroup: da quando c'è un'unità in mezzo, uccidere il gruppo di
processi raggiunge `sudo` e `systemd-run`, non il tool.

Il timeout del gate resta la rete di riserva, e scatta solo se systemd ha
fallito: in quel caso il gate chiama `hermes-tool-run --stop <unità>`. Se anche
quello non riesce, la cosa finisce nel log — un residuo invisibile è peggio di
un residuo noto.

### 6.6 La causa nel log, non un «1» generico

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

### 6.7 Verificare

```sh
sudo -u hermes /opt/hermes-core/.venv/bin/python \
     -m mcp_server.doctor /opt/hermes-core/config/hermes.toml
```

Cinque controlli distinti, e sono distinti di proposito: il wrapper esiste ed
è di root; l'utente dei tool esiste e non ha shell; `sudo -n` sul wrapper
riesce **senza password**; `hermes-tool` riesce ad aprire gli script
registrati; log e stato restano fuori dalla portata dei tool.

Le ultime due del primo gruppo sono sonde vere, non ispezioni.

La terza esegue `hermes-tool-run --stop` su un'unità riservata e inesistente,
che non fa nulla ma esercita esattamente il privilegio. Se `sudo` non è
autorizzato si scopre lì, invece che alla prima invocazione.

La quarta percorre la **stessa catena del gate** — `sudo` → wrapper → unità
transiente → interprete con `-I -S` — cambiando solo l'ultimo anello: legge un
byte dello script invece di eseguirlo. Chiederlo in un altro modo risponderebbe
su un altro utente, perché il servizio legge il repo tramite la propria ACL e
vedrebbe verde su una macchina dove i tool non partono. Si prova solo se la
terza è riuscita: senza autorizzazione fallirebbe per la causa già riportata
sopra, e due errori sulla stessa causa mandano a cercare due guasti.

Un controllo visto solo verde non dice molto. Vale la pena vederli dire no.

Il wrapper:

```sh
sudo chmod 644 /usr/local/sbin/hermes-tool-run   # non più eseguibile
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml | grep -i wrapper
sudo chmod 755 /usr/local/sbin/hermes-tool-run   # ripristino
```

Deve dare `[ERRORE] wrapper di isolamento`, e in quello stato il gate rifiuta
ogni invocazione invece di ricadere sull'identità del servizio.

L'accesso agli script:

```sh
sudo setfacl -R -x u:hermes-tool /opt/hermes-core/agents      # entry di accesso
sudo setfacl -R -d -x u:hermes-tool /opt/hermes-core/agents   # entry di default
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml | grep -iA6 lettura
# ripristino: i tre comandi di 6.4
```

Deve dare `[ERRORE] lettura degli script dai tool`, con i `setfacl` nel
rimedio. È il guasto che il 4 novembre si è visto per la prima volta come
`Permission denied` da un tool, cioè nel momento peggiore e senza la causa.

**Servono due righe, non una.** `setfacl -R -x` toglie le entry di accesso ma
**non** quelle di default: senza la seconda riga si riproduce «ACL applicata e
poi tolta a metà», non «ACL mai applicata», che è lo stato in cui si trova chi
installa da zero. Per i file che già esistono il risultato è lo stesso, ma uno
stato riprodotto a metà è un test che verifica meno di quanto dichiara.

L'altra causa, il transito sulla radice, si esercita a parte — e dà lo stesso
messaggio, per la ragione spiegata in 6.4:

```sh
sudo setfacl -x u:hermes-tool /opt/hermes-core
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml | grep -iA6 lettura
sudo setfacl -m u:hermes-tool:--x /opt/hermes-core   # ripristino
```

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

## 10. Spedizione del log a una seconda macchina (A5)

### Cosa compra, e cosa no

Il log d'audit è `chattr +a`: nessun processo non privilegiato può troncarlo,
nemmeno il nostro. Resta scoperto chi ottiene **root**, che toglie `+a` e
riscrive quello che vuole. Contro di lui l'unica cosa che funziona è una
copia **già uscita** dalla macchina.

| Chi | Cosa può già fare al log | Cosa cambia con A5 |
|---|---|---|
| un tool compromesso (`hermes-tool`) | niente: non lo apre nemmeno | niente |
| il servizio compromesso (`hermes`) | appendere righe false; **non** troncare | niente sulle righe false |
| root su questa macchina | `chattr -a`, riscrivere tutto, disinstallare la spedizione | **tutto**: è l'unico livello che A5 affronta |

Va detto chiaro: **A5 non difende dalle righe false.** Difende dalla
cancellazione a posteriori, e lo fa in due modi — le righe già spedite sono
fuori portata, e una manomissione locale produce un **sintomo**.

### Perché si spinge invece di tirare

Tirando dal collector ogni N minuti, chi entra e ripulisce entro quella
finestra non lascia traccia di sé. Spingendo, le righe sono al sicuro dal
momento in cui partono.

Il costo è una chiave privata sulla macchina esposta. Si accetta perché il
raggio d'azione di quella chiave è quasi nullo: il `ForceCommand` sul
collector permette **solo di appendere byte a un file**. Niente shell,
niente lettura, niente cancellazione. È una differenza di sostanza rispetto
a una credenziale di scrittura su git, che altrove in questo progetto è
stata rifiutata: chi scrive nel repo cambia il codice dei tool *e* il loro
SHA dichiarato nella stessa commit.

### La regola che rende la copia una prova

Il ricevente **rifiuta qualunque offset che non sia la dimensione attuale
della sua copia**. Ne seguono tre proprietà:

- una connessione caduta a metà non duplica né lascia buchi: il mittente
  chiede sempre prima dove siamo arrivati;
- la copia resta **byte-identica** al prefisso dell'originale, quindi un
  `sha256sum` confronta i due file senza interpretarli;
- un troncamento locale diventa **rumoroso**. Riscrivere anche lo stato del
  mittente non aiuta: un offset minore della dimensione remota è rifiutato
  allo stesso modo. L'unico modo di non far scattare il rifiuto è impedire
  al mittente di girare, che è «la spedizione si è fermata» — e si vede.

Il mittente verifica anche l'impronta degli ultimi 4096 byte già spediti: una
riscrittura *a parità di lunghezza*, che il solo confronto delle dimensioni
non vedrebbe, è una divergenza.

---

### 10.0 Due macchine: quale comando va dove

Questa sezione è l'unica del documento che attraversa **due macchine**, e
confonderle fa perdere tempo. Ogni blocco qui sotto comincia con la riga che
dice dove si esegue.

| | Chi è | Cosa ci sta |
|---|---|---|
| **`hermesmcp`** · 192.168.205.10 | la macchina sorvegliata | il repo in `/opt/hermes-core`, il log, il mittente |
| **collector** · 192.168.205.50 | la macchina che conserva | la copia. **Niente repo**, ed è voluto |

**La porta SSH del collector non è per forza la 22.** Un'installazione può
ascoltare altrove, e il mittente lo prevede (`COLLECTOR_PORTA`). Si guarda
una volta, dalla console del collector, e si usa quel numero dappertutto —
`scp`, `ufw`, `ssh-keyscan`, configurazione:

```sh
# sul collector
sudo ss -tlnp | grep sshd
```

I comandi che seguono scrivono la 22, che è il caso solito. Se la tua è
diversa, va cambiata in tutti e quattro i posti: una sola dimenticata dà un
`Connection refused` che non punta alla causa.

Il collector non ha il repo e non deve averlo: conserva prove, non esegue il
progetto. I file che gli servono ci arrivano copiati.

Serve il tuo account sul collector — **non è detto che si chiami come
quello qui**. Si imposta una volta per sessione di shell:

```sh
# su hermesmcp
COLLECTOR=iltuoutente@192.168.205.50
```

Se apri una shell nuova va reimpostato: senza, gli `scp` qui sotto falliscono
subito invece di fare la cosa sbagliata.

### 10.1 Il collector

```sh
# su hermesmcp, dalla radice del repo
scp bin/hermes-log-receive config/sshd/20-hermes-collect.conf "$COLLECTOR":~/
```

Su una porta diversa dalla 22, `scp` vuole `-P` **maiuscola** (`ssh` usa
`-p` minuscola, e scambiarle è un classico):

```sh
# su hermesmcp, se il collector ascolta sulla 2222
scp -P 2222 bin/hermes-log-receive config/sshd/20-hermes-collect.conf "$COLLECTOR":~/
```

I comandi che seguono si eseguono **sul collector**, nella home in cui i due
file sono arrivati — `ls` deve mostrarli. Non da `/tmp`: installare un file
di root da una directory scrivibile da chiunque è una finestra che non serve
aprire.

```sh
# sul collector
# La shell SERVE, ed e' la stessa lezione di 2: sshd esegue il ForceCommand
# ATTRAVERSO la shell di login dell'utente, quindi con 'nologin' non parte
# il ricevente — parte nologin, che stampa «This account is currently not
# available» e chiude. La protezione sta nel vincolo, non nell'assenza di
# shell: qualunque cosa chieda il client, parte solo hermes-log-receive.
#
# La home serve a non lasciare un avviso a ogni connessione: senza, sshd
# scrive «Could not chdir to home directory» prima di ogni giro, e un rumore
# ricorrente su un presidio e' un ottimo modo per smettere di leggerlo.
sudo useradd --system --create-home --home-dir /var/lib/hermes-collect \
             --shell /bin/sh hermes-collect
sudo passwd -l hermes-collect      # nessun accesso con password
sudo install -d -m 755 -o root -g root /var/log/hermes-remoto
sudo install -d -m 700 -o hermes-collect -g hermes-collect \
     /var/log/hermes-remoto/hermesmcp
sudo install -m 755 -o root -g root \
     ~/hermes-log-receive /usr/local/sbin/hermes-log-receive
sudo install -d -m 755 -o root -g root /etc/ssh/authorized_keys.d
sudo install -m 644 -o root -g root \
     ~/20-hermes-collect.conf /etc/ssh/sshd_config.d/
```

La directory per sorgente va creata a mano **di proposito**: il ricevente si
rifiuta di crearla. Una directory che compare da sola è una sorgente che
nessuno ha autorizzato.

Il perimetro di rete, e un tetto sul disco:

```sh
# sul collector
sudo ufw allow from 192.168.205.10 to any port 22 proto tcp
```

> **Attenzione prima di attivare `ufw` qui.** Questa regola apre la 22 al solo
> mittente. Se `ufw` è inattivo la regola non fa niente; ma attivarlo con
> questa sola regola **taglia fuori anche te**, e su una macchina a cui
> arrivi solo via SSH significa restare chiusi fuori. Se amministri il
> collector dalla rete e non dalla sua console, serve anche la regola per la
> postazione da cui ti colleghi, **prima** di `ufw enable`:
>
> ```sh
> # sul collector
> sudo ufw allow from 192.168.205.1 to any port 22 proto tcp
> ```
>
> È lo stesso ragionamento di `hermesmcp`, dove la regola nomina un solo
> indirizzo — ma lì quell'indirizzo è la postazione, e qui no.
>
> E se la porta non è la 22, le regole vanno scritte su quella: una regola
> che apre una porta su cui non ascolta nessuno non protegge e non serve.

Il rischio residuo della scelta di spingere è che un mittente compromesso
riempia il disco del collector. Si confina con una partizione separata o una
quota su `/var/log/hermes-remoto`, non con la configurazione di SSH.

### 10.2 L'identità che spedisce

Su `hermesmcp`. **Non** è l'utente di servizio: `hermes` compromesso non deve
poter fermare la spedizione né prendersi la chiave che la autorizza.

```sh
# su hermesmcp
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hermes-ship
sudo install -d -m 750 -o hermes-ship -g hermes-ship /var/lib/hermes-ship
sudo install -d -m 755 -o hermes-ship -g hermes-ship /var/lib/hermes-ship/stato
sudo -u hermes-ship ssh-keygen -t ed25519 -N "" \
     -f /var/lib/hermes-ship/id_ed25519 -C hermes-ship@hermesmcp
```

Senza passphrase, per la stessa ragione documentata in 4.4: il timer gira
senza nessuno davanti, e la protezione sta nel `ForceCommand`, non nella
passphrase. La directory è `750` e appartiene a `hermes-ship`: l'utente di
servizio non la attraversa.

Lo **stato** è `755` con file `644` di proposito: dentro ci sono dimensioni e
un istante, nessun segreto, e il preflight gira come `hermes` e deve poterlo
leggere. Scriverci può solo `hermes-ship`.

La chiave pubblica va portata sul collector. Sono due macchine, quindi due
comandi: il file nasce di qua e si installa di là.

`/var/lib/hermes-ship` è `750` e appartiene a `hermes-ship`: il tuo utente
non ci entra, quindi lo `scp` diretto fallisce. La chiave **pubblica** si
appoggia un momento in chiaro — è pubblica, non è un segreto:

```sh
# su hermesmcp
sudo install -m 644 -o root -g root \
     /var/lib/hermes-ship/id_ed25519.pub /tmp/hermes-ship.pub
scp /tmp/hermes-ship.pub "$COLLECTOR":~/
sudo rm /tmp/hermes-ship.pub
```

Il `sudo` sulla rimozione serve davvero: `install -o root` intesta il file a
root, e lo sticky bit di `/tmp` lascia cancellare solo al proprietario.

```sh
# sul collector
sudo install -m 644 -o root -g root \
     ~/hermes-ship.pub /etc/ssh/authorized_keys.d/hermes-collect
sudo sshd -t && sudo systemctl reload ssh
```

**Il ricarico va fatto qui e non prima**: `20-hermes-collect.conf` attiva un
`ForceCommand` per `hermes-collect`, e ricaricare `sshd` quando la chiave non
c'è ancora lascerebbe un canale che nessuno può usare, con un sintomo che non
punta alla causa. È la stessa ragione per cui il bootstrap di `hermesmcp` non
ricarica `sshd` da solo.

### 10.3 Conoscere il collector per chiave, non per fiducia

Con la verifica dell'host disattivata, chi riesce a prendere il posto del
collector riceve il log e lo fa sparire — e da `hermesmcp` ogni spedizione
risulterebbe riuscita. Il mittente usa `StrictHostKeyChecking=yes` e un
`known_hosts` che non può riscrivere.

Si prende la chiave dalla rete e **si verifica l'impronta dalla console** del
collector, che è il pezzo che rende l'operazione sicura:

```sh
# sul collector, dalla sua console
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# su hermesmcp
sudo sh -c 'ssh-keyscan -t ed25519 192.168.205.50 > /var/lib/hermes-ship/known_hosts'
ssh-keygen -lf /var/lib/hermes-ship/known_hosts
```

Su una porta diversa dalla 22 serve `-p`, e la voce che ne esce ha una forma
diversa — `[192.168.205.50]:2222` invece del solo indirizzo. È `ssh-keyscan`
a scriverla giusta, purché gli si dica la porta:

```sh
# su hermesmcp, se il collector ascolta sulla 2222
sudo sh -c 'ssh-keyscan -p 2222 -t ed25519 192.168.205.50 > /var/lib/hermes-ship/known_hosts'
```

Le due impronte devono coincidere. **Se non coincidono non si prosegue**: è
esattamente il caso che questo controllo esiste per trovare. Il file resta di
root — `hermes-ship` deve leggerlo, non riscriverlo.

### 10.4 L'accesso ai canali

`hermes-ship` deve leggere i due file da spedire, e un file append-only
**rifiuta anche `setfacl`**, non solo la `chmod`: la concessione va data in
una finestra con `-a` tolto.

```sh
# su hermesmcp
sudo setfacl -m u:hermes-ship:--x /var/log/hermes
sudo chattr -a /var/log/hermes/audit.jsonl
sudo setfacl -m u:hermes-ship:r  /var/log/hermes/audit.jsonl
sudo chattr +a /var/log/hermes/audit.jsonl

sudo setfacl -m u:hermes-ship:--x /var/lib/hermes/state
sudo chattr -a /var/lib/hermes/state/overrides.jsonl
sudo setfacl -m u:hermes-ship:r  /var/lib/hermes/state/overrides.jsonl
sudo chattr +a /var/lib/hermes/state/overrides.jsonl
```

Due cose, per non ripetere errori già fatti:

- **sulle directory serve un'ACL, non un `chmod o+x`.** Gli scrittori
  irrigidiscono anche la directory che li contiene, e un transito dato con
  `chmod` verrebbe tolto al primo avvio. Un'ACL no: dal novembre 2026 una
  concessione nominata non viene più annullata da chi scrive il file;
- **transito mancante e lettura mancante danno lo stesso `EACCES`**, come in
  6.4. Il rimedio qui sopra copre entrambi ed è idempotente.

### 10.5 La configurazione, il mittente, il timer

```sh
# su hermesmcp
sudo install -d -m 755 -o root -g root /etc/hermes
sudo install -m 644 -o root -g root \
     config/log-shipping.example.conf /etc/hermes/log-shipping.conf
sudo editor /etc/hermes/log-shipping.conf
```

Il file è di root perché se `hermes-ship` potesse riscrivere la propria
destinazione, un mittente compromesso spedirebbe le prove a sé stesso e da
qui sembrerebbe tutto a posto. **Gli indirizzi nel modello sono quelli di
questo laboratorio**: su un'altra installazione sono plausibili e sbagliati,
e un valore plausibile passa i controlli dando una destinazione che non è la
tua.

```sh
# su hermesmcp
sudo install -m 755 -o root -g root \
     bin/hermes-log-ship /usr/local/sbin/hermes-log-ship
sudo install -m 644 -o root -g root \
     config/systemd/hermes-log-ship.service \
     config/systemd/hermes-log-ship.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-log-ship.timer
```

Il mittente vive **fuori dall'albero di git** per la stessa ragione del
wrapper dei tool: un `git checkout` cambierebbe il codice che custodisce le
prove. Dopo un aggiornamento che lo tocca va reinstallato, e il preflight fa
il `diff` al posto tuo.

Si abilita il **timer**, non il servizio. La cadenza — cinque minuti — è la
finestra di perdita, ed è scritta nel `.timer` con il suo perché.

Infine, nella configurazione del server:

```toml
log_shipping = "/etc/hermes/log-shipping.conf"
```

### 10.6 Verificare, dai due lati

Un giro a mano, e cosa dice:

```sh
# su hermesmcp
sudo systemctl start hermes-log-ship.service
journalctl -u hermes-log-ship.service -n 20 --no-pager
cat /var/lib/hermes-ship/stato/audit.stato
```

Dal preflight, che è il posto in cui questa verifica vive:

```sh
# su hermesmcp
sudo -u hermes .venv/bin/python -m mcp_server.doctor config/hermes.toml
```

**Il preflight non può dire che la copia remota esista**, e lo dichiara. Può
dire che il mittente è quello del repo, che punta al file su cui il server
scrive davvero, che `hermes-ship` arriva ai canali, e com'è andato l'ultimo
giro. Il resto si guarda **dal collector**, che è l'unica macchina la cui
parola non sia riscrivibile da chi manomette questa:

```sh
# sul collector
ls -l /var/log/hermes-remoto/hermesmcp/
sudo tail -n 3 /var/log/hermes-remoto/hermesmcp/audit.jsonl
```

E il confronto integrale, che è la verifica vera e si fa quando serve — non
ogni cinque minuti:

```sh
# sul collector
wc -c < /var/log/hermes-remoto/hermesmcp/audit.jsonl
sha256sum /var/log/hermes-remoto/hermesmcp/audit.jsonl

# su hermesmcp `read` chiede il numero letto sopra, e lo si incolla.
read -r BYTE
sudo head -c "$BYTE" /var/log/hermes/audit.jsonl | sha256sum
```

Il numero lo si digita invece di metterlo nel comando perché un segnaposto
dentro un blocco da incollare è già costato due errori a questo progetto: qui
`read` lo chiede, e un comando incompleto non parte invece di partire
sbagliato.

Le due impronte devono coincidere: la copia è un prefisso esatto
dell'originale, quindi il confronto non richiede di interpretare niente.

Quando la copia esiste ed è confermata, va resa non riscrivibile anche lì:

```sh
# sul collector, dopo il primo giro riuscito
sudo chattr +a /var/log/hermes-remoto/hermesmcp/audit.jsonl
sudo chattr +a /var/log/hermes-remoto/hermesmcp/overrides.jsonl
```

### 10.7 Quando scatta una divergenza

Il preflight dice `DIVERGENZA` e il servizio esce con 3. Significa che la
copia remota non è più un prefisso del file locale: **il file locale è stato
accorciato o riscritto dopo essere stato spedito.**

Non si «ripara» riallineando. La copia sul collector è la versione da
credere, e la domanda è *cosa manca*:

```sh
# sul collector: fin dove arriva la copia
wc -c < /var/log/hermes-remoto/hermesmcp/audit.jsonl

# su hermesmcp quanto è lungo adesso l'originale
sudo wc -c < /var/log/hermes/audit.jsonl
```

Se l'originale è più corto, le righe che mancano sono nella copia e solo lì.
Il mittente **non spedisce più** finché la divergenza non è risolta, ed è
voluto: scrivere sopra una divergenza costruirebbe una copia che non
corrisponde a niente.

Si riparte solo deliberatamente, da chi amministra: si mette da parte la
copia remota come prova, e si lascia che il mittente ricominci. In
laboratorio, dove una divergenza è quasi sempre un esperimento e non
un'intrusione:

```sh
# sul collector
sudo chattr -a /var/log/hermes-remoto/hermesmcp/audit.jsonl
sudo mv /var/log/hermes-remoto/hermesmcp/audit.jsonl \
        /var/log/hermes-remoto/hermesmcp/audit.jsonl.divergente
```

Al giro successivo la copia riparte da zero e torna allineata. Fuori dal
laboratorio, quel file messo da parte **è la prova**: va conservato prima di
toccare qualunque altra cosa.

### 10.8 La rotazione, che resta a mano

Con la copia remota al sicuro, ruotare il log locale non è più una perdita di
prove: è un'operazione ordinaria. Resta **manuale e deliberata**, e non c'è
nessun rotatore automatico, per una ragione precisa: troncare un log d'audit
in base a un offset sbagliato distrugge prove da solo, e un programma che lo
facesse ogni notte sbaglierebbe senza che nessuno guardi.

La regola, quando la si farà: **si tronca solo fino all'offset confermato dal
collector**, mai oltre. La voce di debito corrispondente resta aperta.

---

## 11. Cosa resta per le milestone successive

**Container runtime** (Docker o Podman) sulla VM, per l'agente di pentest: è
la ragione per cui il disco è stato dimensionato con margine. Finché
`container_available = false`, i tool che lo richiedono vengono negati invece
di ricadere sull'host — comportamento voluto.

**Backend reale del vault** (`pass`), al posto dello stub. Dentro ci andranno
solo le credenziali delle VM di laboratorio.

**Un secondo agente**, con la propria configurazione, il proprio utente di
servizio e la propria chiave vincolata.
