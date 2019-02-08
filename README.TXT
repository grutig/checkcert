Certbot 1.01
Giorgio L. Rutigliano

This program is used to automatically renew let's encrypt certificates
regardless of the type of application in which they are used.
It is called daily by cron.daily and verifies the expiration of all the certificates
listed in the configuration file checkcert.cfg.
If the expiration is less than the configured value, it calls let'sencrypt certbot
tool to extend certificate validity for another 90 days.
All the configuration values are store in checkcert.cfg file, each element is documented
by comments inside the sample file.
Logging is done via syslog.

Dependencies: python 3.x, certbot

----

Questo programma serve al rinnovo automatico dei certificati let's encrypt
indipendentemente dalla tipologia di applicativo in cui sono utilizzati.
E' richiamato ogni giorno da cron.daily e verifica la scadenza dei certificati
elencati in configurazione. Se la scadenza è inferiore al valore configurato
lancia l'utilita' certbot per estenderne la validità per ultriori 90 giorni.
Le configurazioni sono lette dal file checkcert.cfg, ogni campo è documentato
dai commenti nel file campione.
I logging e' scritto in syslog.

Dipendenze: python 3.x, certbot
