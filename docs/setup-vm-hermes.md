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

### La directory del log

```sh
sudo install -d -o hermes -g hermes -m 700 /var/log/hermes
```

Appartiene al servizio, non al repo: è l'unico posto in cui ha bisogno di
scrivere.

---

## 4. La chiave SSH, vincolata a un comando

Qui sta la parte che vale la pena fare bene. La chiave che userà Hermes **non
deve essere un accesso alla macchina**: deve essere il permesso di avviare
quel server e nient'altro. Se un domani quella chiave finisse altrove, non
darebbe una shell.

Su **Windows**, da PowerShell:

```powershell
ssh-keygen -t ed25519 -C "hermes-desktop@windows"
type $env:USERPROFILE\.ssh\id_ed25519.pub
```

Sulla **VM**, incolla quella chiave pubblica in `authorized_keys` di `hermes`,
**preceduta dalle restrizioni**, tutto su una riga:

```sh
sudo install -d -o hermes -g hermes -m 700 /var/lib/hermes/.ssh
sudo -u hermes tee -a /var/lib/hermes/.ssh/authorized_keys >/dev/null <<'EOF'
command="/opt/hermes-core/bin/hermes-core-server",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA...INCOLLA_QUI... hermes-desktop@windows
EOF
sudo chmod 600 /var/lib/hermes/.ssh/authorized_keys
```

Cosa fa ciascun pezzo:

| Restrizione | Effetto |
|---|---|
| `command="…"` | **comando vincolato**: qualunque cosa chieda il client, parte solo il server. Niente shell. |
| `no-pty` | nessun terminale: un TTY farebbe eco e traduzione dei caratteri, corrompendo il JSON-RPC |
| `no-port-forwarding` | la chiave non può aprire tunnel verso la rete di laboratorio |
| `no-agent-forwarding`, `no-X11-forwarding` | nessuna delega di credenziali, nessuna superficie grafica |

Conseguenza pratica: nel comando di Hermes **non serve indicare lo script**,
perché il vincolo lo impone già. Più avanti, un secondo agente avrà una
propria chiave con il proprio comando vincolato — lo schema regge.

---

## 5. Verificare dalla VM

```sh
cd /opt/hermes-core
.venv/bin/python -m mcp_server.doctor config/hermes.toml
```

Rispetto alla VM di sviluppo, due avvisi dovrebbero essere **scomparsi** se i
permessi sono giusti: la scrivibilità del repo (eseguendolo come `hermes`) e,
dopo il punto seguente, l'append-only del log.

Per vederlo dal punto di vista del servizio:

```sh
sudo -u hermes /opt/hermes-core/.venv/bin/python \
     -m mcp_server.doctor /opt/hermes-core/config/hermes.toml
```

### Rendere il log non riscrivibile

Da fare **dopo** il primo avvio, perché il file deve esistere:

```sh
sudo chattr +a /var/log/hermes/audit.jsonl
lsattr /var/log/hermes/audit.jsonl      # deve mostrare 'a'
```

Da quel momento il log si può solo accrescere: nessun processo non
privilegiato può troncarlo o riscriverlo, incluso il nostro.

---

## 6. Verificare da Windows

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

## 7. Registrare in Hermes

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

## 8. Cosa resta per le milestone successive

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
