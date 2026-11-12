# Politica di sicurezza

## Cos'è questo progetto

`hermes-core` è un server MCP che fa da **gate** fra un agente e l'esecuzione
di tool di sicurezza: decide se una chiamata può essere eseguita, con quale
identità, entro quale perimetro, e ne scrive la traccia in un log d'audit
append-only.

È un progetto didattico e di sicurezza personale, sviluppato da una persona
sola. Non c'è un'azienda dietro, non c'è un reperibile, non c'è un contratto
di servizio. Le righe che seguono dicono cosa aspettarsi davvero, perché una
politica che promette più di quanto può mantenere è peggio di nessuna
politica.

## Versioni supportate

Solo `main`. Non esistono rami di manutenzione né rilasci precedenti da
correggere.

| | |
|---|---|
| Python | 3.11 – 3.14, verificati agli estremi dalla CI |
| Piattaforma | Linux con systemd |

## Come segnalare

**Non aprire una issue pubblica** per una vulnerabilità. Due canali, scegli
quello che preferisci:

1. **Segnalazione privata su GitHub** — la scheda *Security* del repository,
   poi *Report a vulnerability*. Resta nel repo, non espone nessun indirizzo
   e tiene la discussione accanto al codice.
2. **Email** — gabriele.cyber17@gmail.com. Se vuoi cifrare, scrivi prima una
   riga per chiedere la chiave.

### Cosa è utile includere

Più di tutto: **come riprodurlo**. Una vulnerabilità descritta e non
riproducibile costa più tempo a chi la riceve che a chi la segnala.

- la versione o il commit su cui l'hai vista;
- i passi per riprodurla, o un proof-of-concept;
- cosa ottiene chi la sfrutta — in particolare se attraversa uno dei confini
  descritti sotto;
- la configurazione rilevante (`hermes.toml`, `scope.toml`), **senza
  segreti**.

### Cosa aspettarsi

- **Presa in carico**: entro qualche giorno. Se dopo una settimana non hai
  ricevuto risposta, insisti: è molto più probabile che il messaggio sia
  finito nello spam che il contrario.
- **Correzione**: dipende dalla gravità e dal tempo disponibile. Dirò
  onestamente cosa intendo fare e quando, anche quando la risposta è «non
  adesso».
- **Divulgazione**: concordata. Chiedo un tempo ragionevole per correggere
  prima della pubblicazione, e il credito è tuo se lo vuoi.

## I confini che contano

Una segnalazione è tanto più utile quanto più è chiaro **quale** confine
attraversa. Il modello di minaccia è documentato in
[`docs/debito-sicurezza.md`](docs/debito-sicurezza.md) e nel codice; in breve:

| Confine | Cosa dovrebbe impedire |
|---|---|
| Gate | Eseguire un tool che la policy nega, o senza la conferma richiesta |
| Isolamento | Un tool che esce dalla propria identità, dai limiti di risorsa, o che legge log, stato o segreti |
| Integrità | Eseguire uno script il cui contenuto non corrisponde allo SHA dichiarato |
| Perimetro | Un tool che agisce su un bersaglio fuori da `scope.toml` |
| Audit | Una chiamata eseguita e non registrata, o una traccia riscrivibile |
| Segreti | Un segreto che compare in un log, in un messaggio d'errore o in un output |

**Il modello di minaccia è il tool, non il server.** `hermes-core` confina il
codice che esegue; non si difende da un utente di servizio già compromesso.
Un «attacco» che parte dall'avere già i privilegi del server non è una
vulnerabilità di questo progetto — è il presupposto di tutto il resto.

### Fuori ambito

- Difetti nelle dipendenze di terze parti: segnalali a monte. Qui interessano
  solo se il modo in cui le usiamo li rende sfruttabili.
- Configurazioni deliberatamente insicure, quando il preflight le segnala già
  come errore: è il comportamento voluto.
- Ciò che è già scritto in `docs/debito-sicurezza.md` come accettato. Se però
  hai un argomento per cui un rischio accettato è più grave di come è
  descritto, quello **è** una segnalazione utile.
- Scansioni automatiche senza una catena di sfruttamento: un report di tool
  incollato senza analisi non è una segnalazione.

## Uso previsto

Questo strumento esegue tool di sicurezza, alcuni offensivi. È previsto per
**bersagli propri o esplicitamente autorizzati**, in laboratorio, a scopo
didattico e di sicurezza personale. Il perimetro in `scope.toml` è un
presidio tecnico, non un permesso: l'autorizzazione a toccare un bersaglio
viene da chi lo possiede, non da un file di configurazione.
