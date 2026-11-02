---
title: Linux L3 / SysSecOps - Engineering Cheat Sheet
---
# LFM — Carnet de terrain Linux L3 / SysSecOps

**Édition V3 — 2 novembre 2026 · enrichie par capitalisation BNP / BP2I**  
Ubuntu / Debian · RHEL / Rocky / AlmaLinux · VMware / vCenter · LVM / NFS · Rudder · OpenSCAP · CIS L1 · Bash / Ansible

> **Légende sécurité** — **[RO]** lecture seule ; **[M]** modifie l'état système ; **[DANGER]** altération potentiellement irréversible. Toute commande impliquant `/dev/...`, des comptes, des ACL, des services, le pare-feu ou des politiques Rudder exige d'identifier le bon hôte et l'objet exact. Les exemples `/dev/sdb`, `vgdata`, `<hôte>` sont **fictifs** et ne doivent jamais être collés tels quels.
>
> **Règle d'or :** mesurer → expliquer → préparer le rollback → tester sur pilote → corriger par vagues → contrôler au niveau OS **et** au niveau métier. Une VM snapshot n'est pas une sauvegarde de données applicatives cohérente.

### Accès rapide

- [01. Triage / systèmes / performance](#1-identification-rapide--premier-diagnostic-lecture-seule) · [Réseau et DNS](#3-réseau-l3--interfaces-routes-dns-ports-filtrage)
- [Stockage / vCenter / SCSI / LVM](#4a-playbook-vcenter--linux--lvm--filesystem) · [NFS / multipath](#4b-stockage-avancé--nfs-san-multipath-quotas)
- [Services / journaux / boot](#5-services-systemd-journaux-boot) · [PAM / SSH / authselect](#6-utilisateurs-sudo-pam-ssh--investigations)
- [Rudder agent / serveur / reporting](#7-rudder--architecture-politique-concepts) · [OpenSCAP / CIS](#8-openscap--cis--audit-analyse-décarts-remédiation)
- [YAML / Foreach / Regex](#9-yaml-rudder--regex--foreach--cours-express-basé-sur-le-tp) · [`grep`/`sed`/`awk`/`find`](#10-grep--sed--awk--find--diff--atelier-dinvestigation)
- [Bash](#11-bash--boucles-tests-exit-codes-lecture-seule) · [Patching APT/DNF](#12-patching-apt--dnf--diagnostic-et-préparation)
- [Ansible](#13-ansible--checklist-sécurité-et-diagnostic) · [Sécurité / SELinux / AppArmor](#14-sécurité-avancée--aide-auditd-permissions-services-sysctl)
- [Runbooks L3](#15-situations-lfm--réponse-immédiate-et-orientation) · [Premier jour](#18-première-journée-lfm--cinq-vérifications-sans-présupposé)
- **[BNP → LFM](#19-capitalisation-bnp--bp2i--acquis-transférables-à-lfm)** · [Satellite](#20-red-hat-satellite-rhsm-et-errata--diagnostic-par-couche) · [Leapp](#21-leapp--rhel-78-et-89--inhibitors-et-retour-arrière) · [Authselect RHEL](#22-pam-et-identité--comparaison-ubuntu--rhel--mécanismes-générateurs) · [Ansible/AAP2](#23-ansible--aap2--build-contrôles-et-remédiation-à-grande-échelle)
- [DNS/NTP](#24-dns--ntp--observabilité--cas-hérités-de-lexpérience-bnp) · [Veritas/SAN](#25-veritas--vxfs--gpfs--san--avant-de-toucher-à-un-cluster) · [Firmware Dell](#26-dell--hpe--firmware-et-console-oob-approche-non-destructive) · [VMware/IBM](#27-vmware--ibm-cloud-vsi--provisioning--crashdump) · [Incidents](#28-bibliothèque-dincidents--preuves-et-scénarios-à-compléter)

**Choisir rapidement l'outil :** `hostnamectl` identité · `journalctl` logs · `ss` sockets · `ip route get` chemin réseau · `df -ih` inodes · `lsscsi` H:C:T:L · `pvs/vgs/lvs` LVM · `rudder agent info` identité Rudder · `oscap info` contenu SCAP · `grep -nHP` regex PCRE.

---

> **NOUVEAU V3 — Capitalisation de l'expérience BNP/BP2I** : enrichissements **Satellite et Content Views, Leapp, Authselect/PAM RHEL, Ansible/AAP2, remédiations DNS/NTP, Veritas/VXFS/GPFS/SAN, Dell/iDRAC/OME, VMware/IBM Cloud, kdump**. Les chapitres §19–31 distinguent expérience rapportée, commandes génériques et cas non documentés. Les sections §0–18 conservent le socle Rudder / OpenSCAP / Linux / stockage de V2.
>
> **Mode d'emploi** — Chercher la catégorie de l'incident, lancer d'abord les commandes **LECTURE SEULE**, comprendre les sorties, vérifier l'impact, puis agir dans le cadre des habilitations et du processus de changement. **Ne pas copier-coller des remédiations sur le parc sans pilote ni rollback.**
>
> **Sources LFM disponibles** : fiche de poste Expert Systèmes Linux, compte rendu transmis par Alain, sujets techniques (Rudder, OpenSCAP, CIS Level 1, patching à industrialiser). Périmètre décrit : deux salles datacenter, environ 250 VM Linux et 80 serveurs physiques *de fonctions variées* ; le parc exact à traiter est à confirmer. Les outils/versions observés sur nos VM de laboratoire ne sont **pas** présumés être les versions de LFM. **Fiche officielle :** environ 250 VM Linux VMware et ~80 serveurs physiques multi-fonctions, deux datacenters, stockage NFS ; ce total ne correspond pas nécessairement au nombre de machines à durcir dans la campagne CIS.

## 0. Les 7 réflexes L3 — avant de toucher une prod

1. **Qualifier** : hôte, OS/version, environnement, rôle applicatif, criticité, symptômes et heure du début.
2. **Comparer** : fonctionne ailleurs ? changement récent ? nouveau noyau ? dernière politique Rudder ? dernier patch ?
3. **Observer** : état réel + logs + indicateurs, en conservant horodatages et preuves.
4. **Isoler la couche** : OS / service / réseau / DNS / stockage / authentification / outil de gestion.
5. **Évaluer** : dépendances, HA/cluster, sauvegarde restaurable, fenêtre de changement, accès console.
6. **Agir minimalement** : pilote, action ciblée, pas de redémarrage ni de changement de sécurité par réflexe.
7. **Valider** : service métier, tests fonctionnels, avant/après, suivi des écarts, rollback possible, ticket.

**Cycle de durcissement CIS** : baseline OpenSCAP → qualification `FAIL` → criticité / applicabilité → exception ou remédiation → pilote Rudder **Audit** → Enforce autorisé → tests métier → nouveau scan OpenSCAP → documentation.

**Cycle patching** : inventorier → classifier → préchecks → sauvegarde/fenêtre → simulation → patch → reboot si requis et validé → postchecks → preuves → reporting.

---

## 1. Identification rapide — premier diagnostic (lecture seule)

**Situation** : un ticket arrive, on ne connaît pas encore la machine.

```bash
hostnamectl                         # hostname, OS, kernel, architecture
cat /etc/os-release                 # VERSION_ID, ID, ID_LIKE
uname -r; uname -m                  # kernel courant, architecture
uptime -p; uptime                   # uptime + charge moyenne
who -b; last -x reboot | head      # dernier boot / historique
ip -br a; ip route                  # interfaces + routes
hostname -f; timedatectl            # FQDN + horloge/NTP
df -hT; df -ih                      # espace et inodes
free -h; swapon --show              # RAM et swap
systemctl --failed                  # unités en échec
journalctl -p err -b --no-pager | tail -60
```

**Interprétation** : `load average` élevé ≠ CPU forcément saturé ; peut refléter attente I/O. `systemctl --failed` donne des indices, pas le diagnostic complet. Horloge non synchronisée = risques TLS/Rudder/SSO/logs.

## 2. CPU, mémoire, processus, performance

**Question : pourquoi la machine est lente ?** D'abord charge, CPU, mémoire, I/O, puis identifier processus et événements.

```bash
uptime                              # load sur 1/5/15 min
nproc; lscpu                        # nombre de CPU et caractéristiques
top -b -n1 | head -35              # vue instantanée non interactive
ps -eo pid,ppid,stat,%cpu,%mem,etime,cmd --sort=-%cpu | head -15
ps -eo pid,ppid,stat,%mem,rss,cmd --sort=-rss | head -15
free -h; cat /proc/meminfo | head -25
vmstat 1 5                          # r,b, si/so, wa, us/sy/id
cat /proc/pressure/{cpu,memory,io}  # PSI (si noyau compatible)
pidstat -u -r -d 1 3                # sysstat, si installé
iostat -xz 1 3                      # sysstat, I/O par device
dmesg -T | grep -Ei 'oom|killed process|out of memory' | tail
journalctl -k -b | grep -Ei 'oom|memory|hung task|blocked for'
```

| Symptôme | Indice | Orientation |
|---|---|---|
| CPU saturé | `top` `%us/%sy` haut, processus gourmand | Identifier processus, workload, quotas, régression |
| Attente I/O | `vmstat wa`, `iostat await` élevés | Storage, NFS, filesystems, saturation backend |
| Pression RAM | `MemAvailable` bas, swap/PSI élevés | Fuite, dimensionnement, OOM, mémoire cache vs disponible |
| OOM Killer | `journalctl -k` « Killed process » | Identifier PID/service, cgroup, limites, cause |
| Processus bloqué | `ps` état `D` | Attente I/O souvent non interruptible, investiguer stockage |

**Précaution** : ne pas `kill -9` ni vider les caches (`drop_caches`) sans analyse ; cela ne corrige pas la cause.

### 2A. Méthode L3 : identifier le véritable goulot

**CPU / load** — le `load average` correspond notamment aux processus exécutables et à certains états d'attente non interruptible ; comparer à `nproc`, au CPU réellement utilisé et aux processus en état `D`.

```bash
ps -eo stat,pid,ppid,ni,pri,wchan:24,comm | awk '$1 ~ /^D/ {print}'  # [RO] processus attente I/O
pidstat -p ALL -u -r -d 1 3               # [RO] consommation CPU/RSS/I/O par PID (sysstat)
sar -u 1 5; sar -r 1 5; sar -q 1 5      # [RO] historique/instantané (sysstat)
cat /proc/loadavg; cat /proc/uptime       # [RO] chiffres bruts
ps -eo pid,comm,ni,pri,psr,%cpu,etime --sort=-%cpu | head -20
```

**RAM** — une RAM `used` élevée peut être normale à cause du page cache ; juger `available`, PSI, swap in/out (`vmstat si/so`), OOM, mémoire cgroup et comportement applicatif.

```bash
free -h; cat /proc/pressure/memory            # [RO]
swapon --show; cat /proc/swaps                 # [RO]
systemctl show <service> -p MemoryCurrent -p MemoryMax -p OOMPolicy
journalctl -k -b | grep -Ei 'oom-killer|out of memory|killed process'
```

**CPU steal / VM** — un `%st` élevé dans `top`/`mpstat` oriente vers une contention de l'hyperviseur ; comparer aux autres VM et métriques vCenter avant d'accuser l'application. **I/O** — `iostat -xz` : observer `await`, `r_await/w_await`, files, `aqu-sz`, `%util` *dans le contexte du type de disque* ; ne pas appliquer de seuil universel.

```bash
mpstat -P ALL 1 3                     # [RO] charge par vCPU (sysstat)
iostat -xz 1 5                       # [RO] latence par device
lsblk -o NAME,TYPE,SIZE,ROTA,MOUNTPOINTS   # [RO] SSD/HDD indicatif
cat /proc/pressure/io                # [RO] attente I/O agrégée
```

**Cause / action** : CPU saturé → PID/threads et changement récent ; mémoire → OOM/cgroup, fuite ou sizing ; I/O → filesystem, latence SAN/NFS ; `D` → attente noyau, pas forcément CPU. Éviter `drop_caches`, `kill -9`, `swapoff -a` sans incident et plan validés.

## 3. Réseau L3 — interfaces, routes, DNS, ports, filtrage

**Question : un serveur n'atteint plus le serveur Rudder ou un dépôt APT/DNF.** Procéder couche par couche.

```bash
ip -br link; ip -br addr           # interface UP ? IP ?
ip route; ip -6 route               # routes par défaut et spécifiques
ip route get 192.0.2.10            # interface, source et next-hop vers la cible
ip neigh show                      # ARP/NDP (voisins)
resolvectl status                  # DNS effectif sur systemd-resolved
cat /etc/resolv.conf               # attention : symlink/généré
getent hosts example.org           # résolution via NSS
getent ahostsv4 example.org        # IPv4
ss -lntup                          # sockets en écoute (root pour PID)
ss -tan state established          # connexions TCP établies
ss -s                              # résumé socket states
nc -zv -w3 192.0.2.10 443          # TCP accessible ?
curl -vkI --connect-timeout 5 https://example.org  # TLS/HTTP (debug seulement)
tracepath example.org              # chemin/MTU si disponible
ip -s link show dev eth0           # erreurs RX/TX, pertes
```

**Sur DNS** (outils selon installation) :

```bash
dig example.org A
dig @192.0.2.53 example.org A +time=2 +tries=1
resolvectl query example.org
getent hosts example.org
```

**Firewall — lecture seule** :

```bash
sudo nft list ruleset              # nftables (si présent)
sudo iptables -S                   # anciens environnements / backend xtables
sudo ufw status verbose            # Ubuntu/UFW si activé
sudo firewall-cmd --state          # RHEL/firewalld si installé
sudo firewall-cmd --list-all
```

**Trame d'analyse** : interface → IP/route → DNS → SYN/port distant → TLS → application → firewall/ACL → logs des deux côtés. `ping` échoué ne prouve pas que TCP est bloqué (ICMP peut être filtré). `curl -k` contourne la validation du certificat **pour diagnostic seulement**.

**Captures réseau sous autorisation, attention données sensibles** :

```bash
sudo tcpdump -ni eth0 'host 192.0.2.10 and port 443' -c 30
sudo tcpdump -ni any 'port 53' -c 30
```

**Codes typiques** : `Connection refused` = destination joignable mais port rejeté/fermé (ou firewall REJECT) ; `Connection timed out` = paquet/retour filtré, chemin interrompu ou service muet ; `Could not resolve host` = DNS ; `SSL certificate problem` = chaîne/nom/date/certificat ; `HTTP 403` = serveur joint mais autorisation refusée.

### 3A. Réseau avancé : comment isoler la couche en panne

```bash
# [RO] identités, VLAN, MTU, pilote, statistiques
ip -d link show dev <iface>              # vlan, mtu, état détaillé
ethtool <iface>                          # vitesse, duplex, link (si installé)
ethtool -i <iface>                       # driver/firmware
ethtool -S <iface> | head -70            # compteurs de drops/erreurs
ip -s link show dev <iface>              # RX/TX errors/dropped
nmcli dev status; nmcli con show --active # NetworkManager si utilisé
networkctl status <iface>                # systemd-networkd si utilisé

# [RO] couche TCP/route/DNS
ip rule show; ip route show table all
ip route get <IP_DEST> from <IP_SOURCE>  # source/route choisies
ss -tnpi dst <IP_DEST>                    # état TCP détaillé
ss -ltnp '( sport = :443 )'              # écoute locale port 443
getent ahostsv4 <FQDN>; dig +short <FQDN>
resolvectl query <FQDN>                  # DNS via resolved
curl -vI --max-time 8 https://<FQDN>     # TLS/HTTP sans -k
openssl s_client -connect <FQDN>:443 -servername <FQDN> </dev/null  # [RO] certificat/SNI
```

| Symptôme observé | Ce que cela suggère | Prochain contrôle |
|---|---|---|
| `No route to host` | Route/filtrage REJECT/ARP ou passerelle | `ip route get`, `ip neigh`, `traceroute -n` |
| `Connection refused` | Service non à l'écoute ou rejet TCP | `ss -ltnp` **sur destination**, firewall |
| `Connection timed out` | Filtrage DROP, retour perdu, service muet | `tcpdump` aux deux extrémités |
| `Could not resolve host` | DNS/NSS | `getent`, `resolvectl`, `dig @serveur` |
| `certificate verify failed` | CA/nom/SNI/date/interception TLS | `timedatectl`, `openssl s_client` |
| SYN sort mais pas de SYN-ACK | Chemin/ACL/destination | capture source **et** cible |
| SYN-ACK reçu mais TLS échoue | Couche TLS/proxy/certificats | `openssl s_client`, proxy, SNI |

**Capture sous autorisation (données sensibles)** :

```bash
sudo tcpdump -ni <iface> -nn 'host <IP_DEST> and (tcp port 443 or tcp port 5309)' -c 40
sudo tcpdump -ni any 'icmp or icmp6' -c 30
# [M] Pas de capture prolongée ni de fichier PCAP contenant des secrets hors cadre validé.
```

**Pare-feu / SELinux** : vérifier les règles **sans les vider** ; `ufw`, `nft`, `firewalld`, iptables ancien backend. Si une connexion reste bloquée malgré ports ouverts, vérifier proxy, ACL réseau, sécurité hyperviseur et routage retour (`rp_filter` selon contexte).

## 4. Stockage, filesystems, LVM, NFS, I/O

**Question : application « no space left on device » alors que df semble correct.** Vérifier blocs **et** inodes, quotas, fichiers supprimés mais ouverts.

```bash
lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS,MODEL
df -hT; df -ih
findmnt -T /var; findmnt -a
mount | grep -E 'nfs|xfs|ext4|overlay'
du -xhd1 /var 2>/dev/null | sort -h   # top dossiers sur même FS
sudo lsof +L1                   # fichiers supprimés mais toujours ouverts
sudo vgs; sudo pvs; sudo lvs -a -o +devices  # LVM
sudo blkid
cat /etc/fstab                    # configurations persistantes
journalctl -k -b | grep -Ei 'ext4|xfs|I/O error|nfs|blk|reset'
iostat -xz 1 3
```

**NFS** :

```bash
findmnt -t nfs,nfs4
nfsstat -m                       # options de montages NFS
rpcinfo -p 192.0.2.20           # seulement pour services RPC exposés, si utile
showmount -e 192.0.2.20         # exports NFSv3 (NFSv4 peut ne rien exposer)
ss -tan | grep ':2049'
```

**Interprétation** : `df -h` plein = blocs ; `df -i` plein = inodes ; `lsof +L1` = espace retenu par PID ; `D state`/`await` élevés = attente stockage ; NFS bloqué = vérifier réseau ET serveur de stockage. **Ne pas supprimer des fichiers aléatoires, étendre LVM ni toucher au stockage partagé sans validation**.

## 4A. PLAYBOOK vCenter → Linux → LVM → filesystem

**Incident / changement :** l'équipe VMware ajoute un VMDK ou agrandit le disque virtuel existant ; il faut augmenter `/data`, `/var` ou `/` **sans toucher à un autre disque**. C'est une opération **[M]** : validation propriétaire applicatif, sauvegarde, plan et fenêtre. Les commandes ci-dessous sont un **modèle**, à adapter au partitionnement réel.

### 4A.1. D'abord identifier le scénario (NE PAS sauter cette étape)

| Cas | Ce qui change côté vCenter | Côté Linux | Chemin LVM |
|---|---|---|---|
| **A — Nouveau VMDK** | Nouveau disque virtuel ajouté | Nouveau `/dev/sdX` à identifier | scan SCSI → `pvcreate` → `vgextend` → `lvextend -r` |
| **B — VMDK agrandi, PV sur disque entier** | Taille d'un disque existant augmentée | `/dev/sdX` grossit, pas de partition | `rescan` ciblé → `pvresize /dev/sdX` → `lvextend -r` |
| **C — VMDK agrandi, PV sur partition** | Taille d'un disque existant augmentée | `/dev/sdX` grossit, `/dev/sdX1` reste ancienne taille | `rescan` → `growpart` → `pvresize /dev/sdX1` → `lvextend -r` |
| **D — Nouveau LV/FS** | Nouveau disque ou `VG` déjà libre | Point de montage nouveau | `pvcreate?` → `vgextend?` → `lvcreate` → `mkfs` → `fstab` |

**Préchecks à noter dans ticket (lecture seule)** :

```bash
hostnamectl; date -Is; uname -r; uptime
findmnt -T /data                          # device/FS/mount réel de /data
lsblk -e7 -o NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,UUID,MODEL,SERIAL,WWN,MOUNTPOINTS
sudo lsscsi -s -g                        # H:C:T:L, device, taille, sg (si installé)
sudo pvs -o pv_name,vg_name,pv_size,pv_free,pv_uuid
sudo vgs -o vg_name,vg_size,vg_free,pv_count,lv_count
sudo lvs -a -o lv_path,lv_size,lv_attr,segtype,devices,data_percent,metadata_percent
findmnt -no SOURCE,FSTYPE,OPTIONS /data
df -hT /data; df -ih /data
sudo blkid; ls -l /dev/disk/by-id/ | head -50
sudo multipath -ll                       # seulement si multipath installé/utilisé
```

`lsscsi` (et non **lsccsi**) donne par exemple :

```text
[2:0:0:0] disk VMware Virtual disk  /dev/sda  60G
[2:0:1:0] disk VMware Virtual disk  /dev/sdb  80G
[2:0:2:0] disk VMware Virtual disk  /dev/sdc 100G  # nouveau candidat
```

`[H:C:T:L]` = **Host : Channel : Target : LUN**. On l'utilise pour identifier le disque SCSI et cibler un rescan ; ce numéro **n'est pas un numéro de partition**. Avant d'exécuter une écriture, croiser la **taille, le contrôleur, l'ID VMDK vCenter, le WWN/serial, le mapping `/dev/disk/by-id/`, les PV existants**. `/dev/sdb` peut changer de nom au reboot : préférer les identifiants stables dans les configurations pérennes.

> ⚠️ Le scanner SCSI ne crée aucun PV. `pvcreate` écrit des métadonnées LVM : sur **un mauvais disque, destruction de données possible**. Pas de `pvcreate -ff`, `wipefs`, `fdisk`, `parted`, `mkfs` « pour tester ».

### 4A.2. Détecter un **nouveau disque** après ajout vCenter (cas A)

**1. Comparer l'avant/après**, puis détecter les contrôleurs :

```bash
lsscsi -s                                    # [RO] demande la liste H:C:T:L
ls -d /sys/class/scsi_host/host*             # [RO] hôtes disponibles
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS   # [RO]
```

**2. Scanner les hôtes SCSI concernés** (intervention approuvée) :

```bash
# [M] scan ciblé si on connaît le host (ex. host2) :
printf '%s\n' '- - -' | sudo tee /sys/class/scsi_host/host2/scan

# [M] scan de tous les contrôleurs SCSI seulement si justifié :
for h in /sys/class/scsi_host/host*; do
    printf '%s\n' '- - -' | sudo tee "$h/scan" >/dev/null
done
sudo udevadm settle
```

`- - -` = rechercher tous les **channels, targets et LUN** du host concerné. Un scan tous hôtes peut être inutilement large dans les environnements SAN : préférer le ciblage et respecter les procédures de stockage.

**3. Vérifier l'identité du NOUVEAU disque** :

```bash
lsscsi -s -g
lsblk -e7 -o NAME,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINTS,MODEL,SERIAL,WWN
sudo udevadm info --query=property --name=/dev/sdc | grep -E 'ID_(SERIAL|WWN|PATH|MODEL)='
sudo wipefs -n /dev/sdc                # [RO] -n = détecter signatures SANS les effacer
sudo pvs; sudo blkid /dev/sdc          # [RO] il ne doit pas appartenir à un PV existant
```

**4. Si disque réellement neuf, validé non utilisé, et politique autorise PV sur disque entier** :

```bash
sudo vgcfgbackup vgdata                   # [M] sauvegarde METADONNÉES LVM, pas données
sudo pvcreate /dev/sdc                    # [M] DANGER mauvais device
sudo vgextend vgdata /dev/sdc             # [M] nouveau PV dans VG existant
sudo pvs -o pv_name,vg_name,pv_size,pv_free
sudo vgs vgdata -o vg_name,vg_size,vg_free
```

**5. Allouer la capacité demandée au LV** (exemple : +20 Gio, pas « tout le VG » par défaut) :

```bash
sudo lvextend --resizefs --size +20G /dev/vgdata/lvdata  # [M] LV + FS en une commande
sudo lvs -o lv_path,lv_size,devices /dev/vgdata/lvdata
findmnt -T /data; df -hT /data                           # [RO] contrôles finaux
```

`-r` = `--resizefs`; `-L +20G` = **ajouter** 20G ; `-L 20G` = définir une **taille totale** de 20G (ne pas confondre). `-l +100%FREE` = **consommer toutes les extents libres du VG** ; n'utiliser que si la demande l'exige :

```bash
sudo lvextend -r -l +100%FREE /dev/vgdata/lvdata  # [M] exemple seulement
```

**Si nouveau PV sur partition exigé** : créer une partition de type LVM via l'outil approuvé, contrôler sa géométrie puis utiliser `/dev/sdc1` pour `pvcreate`; **ne pas** lancer `pvcreate` sur `/dev/sdc` et `/dev/sdc1` en parallèle. En production, un PV sur disque entier peut être une convention ; d'autres environnements standardisent les partitions.

### 4A.3. Étendre un **VMDK EXISTANT** (cas B ou C)

**Cas B : PV directement sur `/dev/sdb`, disque agrandi dans vCenter** :

```bash
lsscsi -s; lsblk -b -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS  # [RO] taille vue
# [M] rescan du périphérique SCSI EXISTANT (pas scan de nouvelle LUN) :
printf '1\n' | sudo tee /sys/class/block/sdb/device/rescan
sudo udevadm settle
lsblk -b -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS       # [RO] nouvelle taille ?
sudo pvs -o pv_name,vg_name,pv_size,pv_free
sudo vgcfgbackup vgdata                            # [M] métadonnées uniquement
sudo pvresize /dev/sdb                             # [M] agrandir PV EXISTANT
sudo vgs vgdata -o vg_size,vg_free
sudo lvextend -r -L +20G /dev/vgdata/lvdata         # [M] selon capacité autorisée
```

**Rescan via ID H:C:T:L**, si sysfs l'expose et après avoir confirmé le mapping du disque :

```bash
ls -l /sys/class/scsi_device/2:0:1:0/device/rescan     # [RO] exemple H:C:T:L
printf '1\n' | sudo tee /sys/class/scsi_device/2:0:1:0/device/rescan  # [M]
```

**Cas C : PV sur partition `/dev/sdb2`** : la nouvelle taille du VMDK n'étend **pas automatiquement la partition**. Vérifier l'emplacement du PV et l'ordre des partitions.

```bash
lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTTYPE,MOUNTPOINTS
sudo pvs -o pv_name,vg_name,pv_size,pv_free
sudo parted -s /dev/sdb unit GiB print free           # [RO] lecture géométrie
# [M] après rescan du disque : agrandir la partition 2 SI l'espace suit cette partition
sudo growpart /dev/sdb 2                       # cloud-guest-utils / cloud-utils-growpart
sudo partprobe /dev/sdb                       # [M] demande reread table (peut échouer si occupé)
sudo udevadm settle
lsblk /dev/sdb
sudo pvresize /dev/sdb2                        # [M] puis extension logique
sudo lvextend -r -L +20G /dev/vgdata/lvdata
```

`growpart` suppose que **l'espace libre est contigu après la partition à agrandir** ; le nom peut varier (`/dev/nvme0n1p2` pour NVMe). Si la table de partitions est occupée, **ne pas forcer** : organiser une procédure de changement et éventuel redémarrage planifié. Dans un VG partagé/multipath/cluster, les étapes diffèrent : **STOP** et procédure spécifique.

### 4A.4. LV ou système de fichiers : comment choisir la commande ?

```bash
findmnt -no SOURCE,FSTYPE,TARGET /data        # [RO] LV + type FS
sudo lvs -o lv_path,lv_size,segtype,devices   # [RO] LV normal, thin, RAID ?
```

| FS | Croissance online (sur FS monté) | Remarque |
|---|---|---|
| **XFS** | `sudo xfs_growfs /data` **[M]** | le LV doit déjà être agrandi ; **XFS ne se réduit pas** |
| **ext4** | `sudo resize2fs /dev/vgdata/lvdata` **[M]** | ext4 peut grandir en ligne si supporté |
| **LV + FS** | `sudo lvextend -r -L +20G /dev/vgdata/lvdata` **[M]** | privilégier quand FS pris en charge |
| **non-LVM** | spécifique partition + filesystem | ne pas exécuter `pvresize` si pas de PV |

`lvextend` sans `-r` augmente **seulement le LV** ; `df` reste à l'ancienne taille tant que le filesystem n'a pas grandi. **Ne jamais utiliser `fsck` sur un XFS monté** ou réduire XFS (non supporté). Sur ext4, `e2fsck` concerne en général un FS non monté et ne doit pas être lancé à l'aveugle.

### 4A.5. Créer un nouveau LV / un nouveau FS (cas D)

```bash
sudo vgs vgdata -o vg_size,vg_free
sudo lvcreate -L 30G -n lvarchive vgdata         # [M] crée LV
sudo mkfs.xfs /dev/vgdata/lvarchive              # [DANGER] formate : LV absolument neuf
sudo mkdir -p /archive                          # [M]
sudo blkid /dev/vgdata/lvarchive                 # [RO] UUID
# [M] éditer /etc/fstab avec l'UUID après validation des options (exemple : defaults,nofail non universel)
sudo mount /archive                             # [M] après édition fstab
findmnt /archive; df -hT /archive                # [RO]
sudo findmnt --verify                           # [RO] cohérence fstab
```

**N'écris jamais le fichier `/etc/fstab` automatiquement à partir de cette fiche.** Vérifier ordre de démarrage et dépendances NFS, services applicatifs, sécurité et politique de montage.

### 4A.6. Résultats possibles / erreurs fréquentes

| Message ou symptôme | Interprétation probable | Action de diagnostic |
|---|---|---|
| `lsscsi: command not found` | Paquet absent | `apt-cache policy lsscsi` / `dnf info lsscsi`, installation autorisée |
| Nouveau disque invisible | Hot-add, contrôleur, scan SCSI, mapping | vCenter + `lsscsi`, `dmesg -T`, host scan ciblé |
| `Device /dev/sdX excluded by a filter` | Filtres LVM / devices file | `lvmdevices --list` si disponible, `/etc/lvm/lvm.conf`, politique LVM |
| `Device has a signature` sur `pvcreate` | Le disque n'est pas forcément vierge | **STOP**, `wipefs -n`, mapping, ne pas forcer |
| `No space left` lors de `lvextend` | `VG Free` insuffisant / extents | `vgs -o vg_free`, `pvs`, taille demandée |
| `PV Size` inchangée après agrandissement | Device, partition ou scan pas agrandi | `lsblk -b`, `parted print`, `pvresize` seulement après correction |
| `device is busy` / kernel can't re-read | Partition active, table occupée | planifier traitement adapté, pas `partprobe` en boucle |
| `df` ancien malgré `lvs` augmenté | FS pas étendu | `findmnt -T`, `xfs_growfs` ou `resize2fs` selon FS |
| `thin pool ... 100%` | pool thin saturé | `lvs -o data_percent,metadata_percent`, stratégie thin à part |

**Postchecks / preuves à garder** : `date -Is`, `lsblk`, `lsscsi`, `pvs/vgs/lvs`, `findmnt`, `df -hT/-ih`, état service, logs noyau, métriques vCenter, numéro du changement. `vgcfgbackup` sauvegarde la configuration LVM : ce **n'est pas** un backup des données ; snapshot VMware **≠** backup applicatif.

---

## 4B. Stockage avancé — NFS / SAN / multipath / quotas

**NFS :** « application figée » / `ls` qui semble bloquer. D'abord déterminer si le processus attend une réponse NFS, si le réseau est stable et si le backend de stockage répond. Les opérations sur un montage NFS `hard` peuvent attendre longtemps : n'exécute pas `umount -f` par réflexe.

```bash
findmnt -t nfs,nfs4 -o SOURCE,TARGET,FSTYPE,OPTIONS
nfsstat -m                                  # options / retrans / version
nfsstat -c                                  # stats client (nfs-common/nfs-utils)
cat /proc/self/mountstats | less            # montages et métriques détaillées
ss -tn dst <IP_NFS>                        # ports/états client ↔ serveur
nc -zvw3 <IP_NFS> 2049                     # TCP NFS v4
journalctl -k -b | grep -Ei 'nfs|server not responding|timed out|stale'
ps -eo pid,stat,wchan:25,cmd | awk '$2 ~ /^D/ {print}'
```

**SAN/multipath** : vérifier d'abord que la VM est réellement attachée à du stockage multi-chemin (pas le cas d'un simple VMDK standard). Ne pas travailler directement sur un chemin `/dev/sdX` lorsqu'un périphérique multipath `/dev/mapper/mpath*` représente la LUN.

```bash
sudo multipath -ll                         # [RO] si multipath présent
lsblk -o NAME,TYPE,SIZE,PKNAME,FSTYPE,MOUNTPOINTS
ls -l /dev/disk/by-id/ | grep -E 'wwn|dm-uuid' | head
sudo dmsetup ls --tree                      # [RO] périphériques device-mapper
sudo pvs -o pv_name,vg_name,pv_size,pv_uuid
```

**Quotas** : `df` peut afficher de la place alors qu'un compte dépasse son quota.

```bash
quota -s -u <user>                         # si quotas installés
sudo repquota -a                            # si système de quotas actif
xfs_quota -x -c 'report -h' /data           # XFS quotas, accès privilégié selon cas
```

**RAID / disques / SMART** :

```bash
cat /proc/mdstat; sudo mdadm --detail /dev/md0  # si md RAID existant
sudo smartctl -a /dev/sdX                   # lecture seulement si matériel exposé
journalctl -k -b | grep -Ei 'I/O error|medium error|reset|timeout|abort|sense key'
```

**Principe datacenter LFM** : stockage partagé, sauvegardes et clusters peuvent modifier les opérations autorisées. Pour une LUN partagée, un FS cluster ou un datastore VMware, **stopper la procédure LVM standard et faire valider les dépendances avec les équipes concernées**.

## 5. Services, systemd, journaux, boot

**Question : service ne démarre plus après un changement.**

```bash
systemctl status <service> --no-pager -l
systemctl show <service> -p ActiveState -p SubState -p ExecMainStatus -p Result
systemctl cat <service>           # unité + drop-ins, source de vérité
systemctl list-dependencies <service>
systemctl --failed
journalctl -u <service> -b --since '30 minutes ago' --no-pager
journalctl -u <service> -b -n 150 -o short-iso
journalctl -p warning..alert -b --no-pager
journalctl -k -b -n 100          # kernel boot courant
journalctl --list-boots
journalctl -b -1 -p err          # boot précédent, si logs persistants
systemd-analyze blame | head    # démarrage lent : pistes
systemd-analyze critical-chain
```

**État `failed`** : lire `ExecMainStatus`, stderr, dépendances et changement récent avant `restart`. `daemon-reload` recharge la description des unités, **pas** le processus applicatif. `reset-failed` efface l'état affiché, **ne corrige pas** l'incident.

**Logs classiques** : Ubuntu `/var/log/syslog`, `/var/log/auth.log` si rsyslog présent ; RHEL `/var/log/messages`, `/var/log/secure` si rsyslog présent ; toujours vérifier `journalctl` et la journalisation effective.

### 5A. Journaux, démarrage et incidents après reboot

```bash
last -x | head -20                         # historique shutdown/reboot
who -b; uptime -s; systemctl is-system-running
journalctl --list-boots                    # boots accessibles
journalctl -b -1 -p err --no-pager        # erreurs précédent boot (si persistance)
journalctl -k -b -n 150                    # noyau boot actuel
systemctl --failed --no-pager
systemctl show <service> -p Restart -p RestartUSec -p NRestarts -p TimeoutStartUSec
systemctl list-timers --all               # tâches timers
systemctl list-sockets                    # sockets systemd
```

**Service en boucle `activating/auto-restart`** : lire la cause (`journalctl -u`), variables de service (`systemctl cat`), utilisateurs/droits, FS, réseau, dépendances, gestionnaire de secrets, ports. Éviter `systemctl restart` en boucle : risque de masquer l'incident.

**Journalctl utile** :

```bash
journalctl -u <service> --since '2026-11-02 13:00:00' --until '2026-11-02 14:00:00' -o short-iso
journalctl _PID=<PID> -b --no-pager -n 60
journalctl -f -u <service>                 # suivi temps réel
journalctl --disk-usage                   # espace journal
journalctl --verify                       # intégrité journaux si utile
```

**Kernel/boot/rootfs** :

```bash
uname -r; uname -a; cat /proc/cmdline
ls -lah /boot | tail -40
findmnt -T /boot; findmnt -T /boot/efi
ls -ld /sys/firmware/efi                 # existe = démarrage UEFI probable
systemd-analyze time; systemd-analyze critical-chain
journalctl -k -b | grep -Ei 'panic|dracut|initramfs|fsck|mount|emergency'
```

**Kernel installé ≠ kernel démarré** : comparer `uname -r` aux paquets. Après incident de reboot, vérifier grub/boot entry/console vCenter, versions, `/etc/fstab`, stockage/multipath et accès OOB. `grub2-mkconfig`, `update-grub`, `dracut -f`, `update-initramfs` sont **[M]** et ne constituent pas des commandes de diagnostic.

## 6. Utilisateurs, sudo, PAM, SSH — investigations

**Question : écart CIS `nullok` ou compte qui ne peut plus se connecter.** Distinguer configuration, état des comptes et chemin d'authentification.

```bash
id <user>; getent passwd <user>
sudo passwd -S <user>            # P = mot de passe défini ; L = verrouillé (varie)
sudo chage -l <user>
sudo awk -F: '$2 == "" {print $1}' /etc/shadow  # comptes locaux à champ vide
sudo grep -nE '^[[:space:]]*auth[[:space:]]' /etc/pam.d/common-auth
sudo grep -nH 'nullok' /etc/pam.d/common-auth /usr/share/pam-configs/unix
sudo sed -n '6l;8l' /usr/share/pam-configs/unix  # montre tabulations/car. invisibles
cat /usr/share/pam-configs/unix   # Ubuntu : profil utilisé par pam-auth-update
sudo sshd -t                     # vérification syntaxique SSHD
sudo sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|passwordauthentication|usepam'
sudo grep -RniE '^(Include|Match|PermitRootLogin|PermitEmptyPasswords|PasswordAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null
sudo -l                          # droits sudo effectifs de l'utilisateur courant
sudo visudo -c                   # validation syntaxique sudoers
```

**PAM (Ubuntu)** : `/usr/share/pam-configs/unix` → `pam-auth-update` → `/etc/pam.d/common-auth` → services `sshd`, `sudo`, `login` selon leurs piles. Un `!` ou `*` dans `/etc/shadow` **n'est pas** un mot de passe vide. `nullok` = option pouvant accepter des mots de passe vides dans le module concerné ; raison de l'écart CIS, même si aucun compte n'a de mot de passe vide.

**RHEL** : vérifier `authselect current`, `authselect check`, profil sélectionné. Ne jamais éditer les fichiers PAM générés par `authselect` ou la pile `pam-auth-update` à l'aveugle.

**Sécurité de manipulation** : snapshot/sauvegarde, accès console hors bande, session SSH conservée, test **nouvelle** session et `sudo -k; sudo -v` depuis compte non-root, rollback testé. Ne pas diffuser `/etc/shadow` ni les empreintes de mots de passe dans les tickets.

### 6A. PAM/authselect/SSH — préchecks et rollback réellement exploitables

**Question : pourquoi `sudo` marche chez un utilisateur et pas chez l'autre ?** Distinguer `sudoers`, PAM, identité AD/LDAP/SSSD, mot de passe expiré, groupe, cache et chemin d'authentification.

```bash
id <user>; getent passwd <user>; getent group <groupe>
command -v sssctl && sudo sssctl domain-list     # SSSD si présent
systemctl status sssd --no-pager                  # AD/LDAP, si utilisé
sudo passwd -S <user>; sudo chage -l <user>
sudo -l; sudo visudo -c
sudo grep -RniH 'pam_unix\|pam_sss\|pam_faillock\|pam_deny\|nullok' /etc/pam.d 2>/dev/null
sudo journalctl -b | grep -Ei 'pam_unix|pam_sss|sudo|authentication failure' | tail -60
```

**RHEL (authselect)** :

```bash
authselect current                           # profil actif, features
authselect check                             # fichiers générés conformes au profil ?
ls -l /etc/pam.d/system-auth /etc/pam.d/password-auth
ls /etc/authselect/custom/ 2>/dev/null
```

**SSH : ne pas oublier les blocs `Match`** — `sshd -T` donne la configuration effective globale par défaut ; pour tester une connexion précise, utiliser `-C` si nécessaire.

```bash
sudo sshd -t
sudo sshd -T -C user=<USER>,addr=<IP_CLIENT>,host=<NOM_CLIENT> | grep -Ei '^(usepam|passwordauthentication|permitrootlogin|permitemptypasswords|pubkeyauthentication) '
sudo grep -RniE '^\s*(Match|Include|PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords|UsePAM)' /etc/ssh/
```

**Incident après Enforce PAM** :

1. Stopper les nouveaux déploiements sur cette Directive/Rule (dans l'outil central) afin d'éviter sa réapplication.
2. Utiliser la **console / accès hors bande** ; garder la session root existante si possible.
3. Comparer sauvegarde et configuration active : `diff -u` ; vérifier `journalctl` et le service affecté.
4. Restaurer **seulement** les fichiers prouvés fautifs depuis sauvegarde fiable (`cp -a`), après contrôle du plan et du périmètre.
5. Tester **nouvelle** session SSH et `sudo -k && sudo -v` sous l'utilisateur approprié ; relancer Audit/Rudder et OpenSCAP.

> ⚠️ `pam-auth-update --force`, `authselect apply-changes`, `systemctl restart sshd`, `passwd -l` sont **[M]** ; ne pas les exécuter pour « vérifier ». Ne pas ouvrir ou copier `/etc/shadow` dans le chat ni dans les tickets ; filtrer seulement le nom des comptes concernés.

## 7. Rudder — architecture, politique, concepts

**Rudder** : Root Server (UI, inventaires, compilation, rapports) → éventuellement Relay → agent Linux → vérification/application des politiques → retour des rapports. **Technique** = logique réutilisable ; **Directive** = instance paramétrée ; **Rule** = associe Directives et groupes de nœuds ; **Audit** = constater ; **Enforce** = appliquer/remédier.

**Flux par défaut Rudder 9.1** (sauf architecture personnalisée) : nœud Linux → policy server `TCP/5309` : téléchargement politiques ; nœud → policy server `TCP/443` : inventaires, rapports, fichiers ; UI/API → serveur `443`. Un `nc` positif prouve seulement le TCP, pas l'authentification de l'agent. Source : docs Rudder 9.1.

### 7.1. Commandes agent (sur nœud géré)

```bash
sudo rudder agent info                 # identité, policy server, version/config
sudo rudder agent status               # état de l'agent
sudo rudder agent update               # télécharger politiques
sudo rudder agent update -i            # information sur le mécanisme de mise à jour
sudo rudder agent inventory            # envoyer inventaire
sudo rudder agent inventory -i         # debug inventaire + commandes sous-jacentes
sudo rudder agent run                  # exécuter politiques (ATTENTION Enforce)
sudo rudder agent run -i               # mode information
sudo rudder agent history              # derniers runs
sudo rudder agent policy-server 192.0.2.10  # MODIFIE le serveur — seulement si nécessaire
sudo rudder agent set-force-audit      # MODIFIE : impose audit local
sudo rudder agent unset-force-audit    # MODIFIE : enlève le verrou local Audit
```

**Important** : `rudder agent run` peut modifier le système. Pour investigation en environnement sensible, vérifier le mode des Directives et avoir une autorisation. `set-force-audit` est un garde-fou local, son emploi doit respecter l'exploitation ; ne pas l'appliquer discrètement en production.

### 7.2. Diagnostic communication agent ↔ server

```bash
sudo rudder agent info
cat /opt/rudder/etc/policy_server.dat  # si présent sur cette version
getent hosts <rudder-server>
ip route get <IP-SERVEUR-RUDDER>
nc -zvw3 <IP-SERVEUR-RUDDER> 5309
nc -zvw3 <IP-SERVEUR-RUDDER> 443
curl -vkI https://<IP-SERVEUR-RUDDER>  # diagnostic TLS/HTTP
sudo rudder agent update -i
sudo rudder agent inventory -i
sudo rudder agent run -i               # uniquement si exécution approuvée
systemctl status rudder-agent --no-pager -l
journalctl -u rudder-agent -b -n 100 --no-pager
```

**Cas lab** : IP Policy Server passée de `192.168.1.234` à `.233`. Symptômes `Could not retrieve the UUID` + `curl (7) Failed to connect ...443`. Démarche : `rudder agent info` → `nc` 443/5309 → changer l'IP si validé avec `rudder agent policy-server <IP>` → `update` → `inventory` → `run` après vérification du mode des politiques. **Ne pas** `factory-reset` pour une simple IP changée.

### 7.3. Rudder Root Server — santé et logs

```bash
sudo rudder server health              # santé Rudder (si disponible sur version)
systemctl status rudder-server --no-pager -l
systemctl status rudder-jetty rudder-slapd postgresql --no-pager -l
systemctl status apache2 --no-pager -l   # Ubuntu, httpd sur RHEL
systemctl list-units --all | grep -Ei 'rudder|jetty|postgres|apache|httpd|slapd'
ss -lntup | grep -E ':(443|5309|5432)\b'
df -hT; df -ih; free -h; uptime
journalctl -u rudder-server -b -n 100 --no-pager
sudo tail -n 100 /var/log/rudder/webapp/webapp.log
sudo tail -n 100 /var/log/rudder/compliance/non-compliant-reports.log
sudo find /var/log/rudder -maxdepth 2 -type f | head -60
```

**À vérifier côté UI** : `Settings → General → Allowed Networks` (IP client incluse), Node accepté, première génération terminée, groupe statique du pilote vs groupe dynamique, dernières policies et date de l'inventaire, conformité et messages du nœud, `Utilities → Event Logs`.

**Ne jamais redémarrer tous les services Rudder « pour voir » en production** ; identifier le composant fautif et l'impact avant `systemctl restart`.

### 7.4. Rudder — lecture des sorties

| Sortie | Sens pratique | Vérification suivante |
|---|---|---|
| `E\| compliant` | Enforce : état déjà conforme | Le contrôle couvre-t-il bien l'exigence CIS ? |
| `E\| repaired` | Enforce : correction effectuée | Diff, test métier, persistance, nouveau scan |
| `A\| compliant` | Audit : contrôle jugé conforme | Attention aux regex qui ne matchent rien ! |
| `A\| non-compliant` | Audit : écart signalé, pas de correction | Cause, portée, ligne exacte, risque |
| `E/A\| error` | Erreur d'évaluation/exécution | Détails agent, logs serveur, permission, syntaxe |
| `not-applicable` | Contrôle ignoré/non pertinent selon conditions | Condition et OS corrects ? |
| `Reports sent.` | Envoi lancé/réussi côté agent | Confirmer réception et statut en UI |
| `Could not retrieve UUID` | Inventaire ne connaît pas serveur/root UUID | 443, allowed networks, policy server, root/relay |
| `Cannot find suitable server` (`update -i`) | Problème récupération policy | 5309, ACL, serveur/relai, agent accepté |
| `Invalid signature` | Inventaire signé invalide/mauvais nœud | NodeID, clé agent, clones, logs webapp |
| `curl (7)` | Échec connexion TCP | IP, route, port, firewall/service |
| `curl (60)` / `curl (90)` | Problème TLS/certificat/pinning | Chaîne, date, clé épinglée, proxy/EDR |

**Attention reporting Foreach** : deux itérations avec même `Component` et même `Key` peuvent être ambiguës. Nommer les méthodes, vérifier les identifiants de composant et comparer les résultats à un contrôle Linux indépendant.

### 7.5. Runbooks Rudder — erreur → couche → commande

**Architecture à vérifier** : Root Server / relais éventuels / inventaire et acceptation du nœud / génération de policies / téléchargement / agent run / rapports / vue conformité. **TCP/5309** : policy distribution aux agents Linux ; **TCP/443** : inventaires, rapports, fichiers. Les ports peuvent être personnalisés.

| Symptôme | Première hypothèse | Vérifier |
|---|---|---|
| `Could not retrieve UUID` à l'inventaire | HTTPS/Allowed Networks/Policy Server | `rudder agent info`, `nc -zv .. 443`, `inventory -i` |
| `curl (7)` | Pas de connexion TCP | IP/route/firewall/port/service destination |
| `curl (60)` | Trust TLS | chaîne CA, date et noms, proxy |
| `curl (90)` | Clé publique épinglée inattendue | certificat/agent/policy server/proxy sécurité |
| `Cannot find suitable server` | 5309 ou ACL de distribution | `update -i`, `nc ... 5309` |
| `Unspecified server refusal` | agent non accepté/first policies | UI nœuds, regeneration, logs policy server |
| Agent `Reports sent` mais UI grise | collecte/temps/UUID/relays | `agent history`, UI, horloges, webapp logs |
| `Invalid parameter 'replacement'` | Valeur whitespace ou type invalide | Technique YAML, validation, paramètres méthodes |
| `A| compliant` et `FAIL` OpenSCAP | portée/règle/regex ou version de profil | valider OS + regex, comparer Rule ID CIS |
| `E| repaired` récurrent | dérive/daemon/outil concurrent | `diff`, package hooks, réexécutions, ownership |

**Sur agent (ordonnancement)** :

```bash
sudo rudder agent info                   # [RO]
sudo rudder agent status                 # [RO]
sudo rudder agent history                # [RO]
cat /opt/rudder/etc/policy_server.dat  # [RO] si fichier/version présent
sudo rudder agent update -i              # [M] refresh policies si réseau ok
sudo rudder agent inventory -i           # [M] transmet inventaire
sudo rudder agent run -i                 # [M] exécute ENFORCE si défini
```

**Sur serveur (triage)** :

```bash
sudo rudder server health                 # Rudder 9.x si présent
hostnamectl; timedatectl; ip -br a; ip route
ss -lntup | grep -E ':(443|5309|5432)\b'
free -h; df -hT; df -ih; uptime
systemctl list-units --all | grep -Ei 'rudder|jetty|postgres|httpd|apache|slapd'
sudo journalctl -p err -b -n 100 --no-pager
sudo tail -n 100 /var/log/rudder/webapp/webapp.log
sudo find /var/log/rudder -type f | head -40
```

**Agents offline multiples** : comparer le point commun (`Root`, relai, site, plage réseau, certificat, DNS, règle firewall, génération de politiques, saturation stockage/PostgreSQL). Un seul nœud offline : vérifier le host (policy_server, ACL, TLS, clés, version, agent service) avant de soupçonner Rudder globalement.

**Runbook IP Policy Server changée (comme dans notre TP)** :

```bash
sudo rudder agent info
ip route get <NEW_SERVER_IP>
nc -zvw3 <NEW_SERVER_IP> 443
nc -zvw3 <NEW_SERVER_IP> 5309
sudo rudder agent policy-server <NEW_SERVER_IP>  # [M] seulement si changement validé
sudo rudder agent update                         # [M] récupération politiques
sudo rudder agent inventory                      # [M] envoi inventaire
# run uniquement après vérification des policies Enforce :
sudo rudder agent run                            # [M]
```

**Ne pas `factory-reset`** un nœud simplement parce que l'IP a changé ; cela modifie son identité et peut compliquer acceptation/clés.

### 7.6. Audit / Enforce / reporting : pièges de production

- `A| non-compliant` : observation d'une configuration à corriger, aucun changement prévu par cette méthode.
- `E| repaired` : une action a été exécutée ; vérifier qu'elle est **correcte et persistante**, plus des tests applicatifs.
- `A| compliant` **n'est pas un verdict CIS** : une regex qui n'a rien trouvé peut conduire à un résultat trompeur selon la méthode.
- Dans un `Foreach`, même **path** et même identifiant de reporting peuvent rendre des itérations difficiles à distinguer ; noms des méthodes, clés de reporting et contrôles indépendants.
- `Rule` = cible groupes/noeuds + Directives ; attention groupes dynamiques (blast radius). Dans les tests, préférer **un groupe pilote statique**.
- Audit de système réel et outils d'état peuvent diverger : un `FAIL` XCCDF est distinct d'un `non-compliant` de la politique Rudder.

## 8. OpenSCAP / CIS — audit, analyse d'écarts, remédiation

**Rôle** : OpenSCAP = **mesure de conformité** selon profils XCCDF et contrôles OVAL ; Rudder = **contrôle/application des configurations** ; Ansible = **orchestration** possible. Un score Rudder « 100 % » n'implique pas CIS « 100 % » : les ensembles de contrôles peuvent être très différents.

### 8.1. Préparer le scan et trouver le bon contenu

```bash
oscap --version
oscap info /chemin/vers/ssg-<os>-ds.xml
# RHEL 9 (paquets openscap-scanner + scap-security-guide) :
ls /usr/share/xml/scap/ssg/content/ssg-rhel*-ds.xml
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
# Ubuntu : utiliser un datastream qualifié pour cette version et référentiel CIS validé.
# En TP : ComplianceAsCode ssg-ubuntu2404-ds.xml et profil ci-dessous.
```

### 8.2. Audit en lecture seule (exemple lab Ubuntu 24.04)

```bash
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results ./cis-l1-results.xml \
  --results-arf ./cis-l1-arf.xml \
  --report ./cis-l1-report.html \
  ./ssg-ubuntu2404-ds.xml
```

**Attention aux permissions** : exécuter depuis un répertoire accessible au compte effectif (sinon les fichiers peuvent se retrouver sous `/root`). Ne jamais ajouter `--remediate` pendant un audit. `oscap xccdf eval` peut retourner un code non nul lorsque des règles sont en échec : distinguer le résultat de conformité d'une erreur d'exécution avec `--verbose` et le rapport.

### 8.3. Analyser un FAIL — démarche en 6 étapes

1. Relever **Rule ID, titre, sévérité, profil et version du datastream**.
2. Lire la preuve OVAL/XCCDF : fichier/paquet/paramètre demandé, critère exact.
3. Vérifier la configuration **effective** (pas seulement une ligne du fichier).
4. Identifier applicabilité, dépendances, exception/risque métier, faux positif éventuel.
5. Planifier action pilote, rollback, tests fonctionnels, valeur attendue.
6. Corriger via canal validé et relancer **le même profil/version**, comparer `avant/après`.

```bash
# Diagnostic d'un exemple de non-conformité PAM :
sudo grep -nH 'nullok' /etc/pam.d/common-auth /usr/share/pam-configs/unix
sudo awk -F: '$2 == "" {print $1}' /etc/shadow
sudo sshd -T | grep '^permitemptypasswords '
# Voir les fichiers de résultats (l'outil xmllint doit être installé) :
command -v xmllint && xmllint --format ./cis-l1-results.xml | less
# Rapport HTML à partir de résultats existants :
oscap xccdf generate report ./cis-l1-arf.xml > ./rapport-regénéré.html
```

**Rappels XCCDF** : `pass` = contrôle satisfait ; `fail` = non satisfait ; `notapplicable` = contrôle hors périmètre ; `notchecked` = non évalué ; `error` = évaluation échouée ; `notselected` = règle non retenue dans le profil. **Ne jamais assimiler `notchecked` à PASS**.

**Lab réel** : score initial ~68,57 % sur Ubuntu 24.04, 112 FAIL (rapport du lab, pas LFM). Règle `no_empty_passwords_unix` détectait `nullok` dans `/etc/pam.d/common-auth` même sans entrée de mot de passe réellement vide ; `sshd -T` affichait `permitemptypasswords no`, démontrant que les couches de contrôle ne sont pas identiques.

**RHEL 9** : même logique, autre datastream :

```bash
sudo oscap xccdf eval \
  --profile <ID_REEL_DU_PROFIL> \
  --results-arf /var/tmp/rhel9-cis-arf.xml \
  --report /var/tmp/rhel9-cis-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Ne pas présumer que `cis`/le benchmark et son niveau existent sous le même ID sur toutes les distributions. `oscap info` d'abord. Les profils CIS fournis par Ubuntu Security Guide et les profils ComplianceAsCode peuvent avoir des couvertures et versions différentes : **ne pas comparer leurs scores sans normaliser le référentiel**.

### 8.4. Un FAIL OpenSCAP : remonter de la règle à la preuve

```bash
oscap info <DATSTREAM>.xml                  # [RO] profil, datastream, version
oscap xccdf eval --help | less              # [RO] options installées
# [RO] parcourir uniquement le rapport déjà produit :
less -S ./cis-l1-results.xml
grep -nF 'xccdf_org.ssgproject.content_rule_' ./cis-l1-results.xml | head
# XML structuré, si xmllint installé :
xmllint --format ./cis-l1-results.xml | less
# Regénérer HTML à partir d'un résultat XML au format attendu :
oscap xccdf generate report ./cis-l1-results.xml > ./rapport.html
```

**Lecture des statuses** : `pass` conforme, `fail` échec, `notapplicable` hors plateforme/périmètre, `notchecked` non évalué, `error` erreur moteur, `notselected` non inclus. `oscap xccdf eval` retourne typiquement `0` si tout réussit, `2` si des échecs de conformité existent, `1` pour une erreur d'exécution ; valider avec la version en place et les rapports, et ne pas traiter `2` comme échec du processus automatisé.

**Ne pas modifier sur simple présomption :**

```text
Exemple PAM : `nullok` présent → règle XCCDF fail
Mais `/etc/shadow` ne contient aucun mot de passe vide → risque latent
Et `sshd -T` peut confirmer `PermitEmptyPasswords no` → couche SSH différente
Décision : remédiation de la politique PAM à étudier et valider, pas « SSH déjà KO ».
```

**Rapports à archiver par hôte** : horodatage, hostname/UUID, OS, version du datastream, profil et tailoring, niveau CIS, hash du contenu, baseline avant/après, liste des Rule IDs écartés, exceptions approuvées, preuve de test applicatif.

**Automatisation OpenSCAP en production** : prévoir charge CPU/IO (notamment AIDE et inspections fichiers), droits root, déploiement sécurisé du datastream, retention/reporting, limitation de concurrence, planification et processus de traitement des erreurs. Un scan ne doit pas devenir une opération de remédiation ; **jamais `--remediate` pendant la mesure**.

## 9. YAML Rudder + regex + Foreach — cours express basé sur le TP

### 9.1. Lire du YAML sans paniquer

```yaml
id: lfm___cis___pam_disable_nullok  # chaîne de caractères
name: LFM - CIS - PAM Disable Nullok
version: '1.0'                      # guillemets pour éviter l'interprétation numérique
items:                              # liste
  - id: methode-1                   # 1er élément (tiret)
    method: file_replace_lines      # méthode Rudder
    params:                         # dictionnaire de paramètres
      path: /etc/pam.d/common-auth
      line: '^auth\s+...nullok\s*$' # quote simple : antislashs préservés
      replacement: 'auth...'
```

**Règles** : indentation par **espaces**, pas des tabulations ; `clé: valeur` = dictionnaire ; `-` = élément de liste ; quotes simples conservent littéralement `\` et `${...}` ; quotes doubles interprètent certains échappements YAML (`\t` devient tabulation). Une expression régulière qui matche mal peut provoquer **faux `compliant`**.

### 9.2. Foreach (principe de notre Technique)

```yaml
- id: <id-stable-de-la-methode>
  name: 'PAM - ${pam.name}'
  method: file_replace_lines
  params:
    path: /usr/share/pam-configs/unix
    line: '${pam.pattern}'
    replacement: '${pam.replacement}'
  foreach_name: pam
  foreach:
    - name: Auth
      pattern: '^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok(\s+try_first_pass)\s*$'
      replacement: '${match.1}${match.2}'
    - name: Auth-Initial
      pattern: '^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok\s*$'
      replacement: '${match.1}'
```

**Lecture** : `${pam.pattern}` = regex de l'itération en cours ; `${match.1}` = premier groupe capturé par la regex ; les deux entrées `Auth` et `Auth-Initial` deviennent deux traitements. Limite de l'éditeur Rudder observée : le paramètre `replacement` ne peut pas démarrer ou finir par des blancs ; les captures conservent l'indentation sans en mettre directement dans le paramètre. **Ce fragment est pédagogique, il doit être inséré dans la structure d'une Technique valide et être testé en Audit.**

### 9.3. Regex PCRE/GNU grep — pense-bête

| Regex | Signification | Exemple |
|---|---|---|
| `^` et `$` | Début / fin de ligne | `^auth.*$` |
| `.` / `.*` / `.+` | N'importe quel caractère / 0+ / 1+ | `pam_.*` |
| `\s*` / `\s+` | Espaces/tabulations 0+ / 1+ (PCRE) | `^\s*auth` |
| `[[:space:]]+` | Espaces POSIX | GNU grep `-E` |
| `\.` / `\[` | Point ou `[` littéral | `pam_unix\.so` |
| `(...)` | Groupe de capture | `(pam_unix\.so)` |
| `a\|b` | Alternative PCRE/ERE | `fail\|error` |
| `\b` | Frontière de mot en PCRE | `\bnullok\b` |
| `${match.1}` | Réutilise groupe 1 dans remplacement **Rudder** | garde indentation |

**Tester d'abord avec GNU grep `-P`** :

```bash
grep -nHP '^\s*\[success=end default=ignore\]\s+pam_unix\.so\s+nullok' /usr/share/pam-configs/unix
# -n numéros ; -H filename ; -P PCRE. 
# -i = ignore casse ; -R = récursif ; -E = regex étendue POSIX ; -F = texte littéral.
```

`grep -E` et `grep -P` sont des **moteurs de regex différents** ; ne pas les additionner par réflexe. `grep -P` n'est pas disponible sur toutes les plates-formes Unix.

### 9.4. Notre Technique PAM — YAML **expliqué**, ligne par ligne

```yaml
id: lfm___cis___pam_disable_nullok            # identifiant stable Rudder
name: LFM - CIS - PAM Disable Nullok          # nom lisible
version: '1.0'                                # version (chaîne)
category: ncf_techniques
items:                                        # liste de méthodes
  - id: 14463291-1d81-4a76-b316-d28ce8b87462
    name: 'PAM - common-auth'
    method: file_replace_lines               # méthode générique Rudder
    params:                                   # paramètres de cette méthode
      path: /etc/pam.d/common-auth
      line: '^auth\s+\[success=1 default=ignore\]\s+pam_unix\.so\s+nullok\s*$'
      replacement: "auth\t[success=1 default=ignore]\tpam_unix.so"
  - id: 1820a6a0-ce78-4609-a8a3-ee22f1d3f367
    name: 'PAM - ${pam.name}'                 # nom dépend de l'itération
    method: file_replace_lines
    params:
      path: /usr/share/pam-configs/unix
      line: '${pam.pattern}'                 # prend la regex de chaque itération
      replacement: '${pam.replacement}'       # remplace avec les captures
    foreach_name: pam                        # nom de la variable itératrice
    foreach:                                 # deux cas dans un fichier
      - name: Auth
        pattern: '^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok(\s+try_first_pass)\s*$'
        replacement: '${match.1}${match.2}'
      - name: Auth-Initial
        pattern: '^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok\s*$'
        replacement: '${match.1}'
```

**YAML essentiel** : deux espaces d'indentation cohérents ; un tiret `-` ouvre un élément de liste ; `params:` ouvre un mapping ; **simple quote** conserve les `\` des regex ; **double quote** accepte `\t` (tabulation). Dans l'éditeur Rudder, `replacement` ne doit pas commencer/finir par du whitespace : le message observé était `value must not have leading or trailing whitespaces`. Les captures `${match.1}` permettent de préserver l'indentation **sans la mettre au début du paramètre**.

**Attention à la vérification** : ne pas confondre *trois instances de méthode* et *trois règles CIS indépendantes*. Dans notre TP, trois lignes `non-compliant` correspondaient aux différentes occurrences/contrôles de la Technique. Ne jamais affirmer que `compliant` prouve l'absence de `nullok` : contrôler l'OS avec `grep` et le rapport OpenSCAP.

**Lire une regex sans peur** :

```text
^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok(\s+try_first_pass)\s*$
│   │                                  │           │             │               │
│   └ groupe 1 = indentation + début   │           └ groupe 2   │               └ fin
└ début                                └ espaces + 'nullok'      └ espaces fin

${match.1}${match.2} = recomposer l'ancienne ligne SANS l'option nullok
```

### 9.5. Regex : mini-laboratoire sûr sur chaîne, sans fichier système

```bash
# `printf` + grep = on valide la regex AVANT Rudder.
printf '%s\n' '  [success=end default=ignore] pam_unix.so nullok try_first_pass' |
  grep -nP '^(\s*\[success=end default=ignore\]\s+pam_unix\.so)\s+nullok(\s+try_first_pass)\s*$'

# Identifier les 2 lignes de la source Ubuntu :
grep -nHP '^\s*\[success=end default=ignore\]\s+pam_unix\.so\s+nullok(\s+try_first_pass)?\s*$' \
  /usr/share/pam-configs/unix
```

**Regex pro (PCRE `grep -P`, Rudder dépend de sa méthode)** :

| Expression | Sens | Exemple |
|---|---|---|
| `^` / `$` | début / fin ligne | `^auth...$` |
| `\s*` / `\s+` | 0+ / 1+ blancs | `^\s*auth` |
| `\d+` / `[0-9]+` | chiffres | `uid=[0-9]+` |
| `\w+` | caractère de mot | `[A-Za-z0-9_]` approximatif |
| `[^#]*` | n'importe quoi sauf `#` | éviter commentaires |
| `(foo|bar)` | alternative + capture | `pass|fail` |
| `(?:foo|bar)` | groupe sans capture | utile si index de captures stable |
| `(?=foo)` / `(?!foo)` | lookahead positif/négatif | exclure config déjà correcte |
| `\b` | frontière de mot PCRE | `\bnullok\b` |
| `?` / `+` / `{n,m}` | 0/1 ; 1+ ; répétition | `try_first_pass?` **ne veut pas dire** option facultative complète |
| `\.` / `\[` | caractère littéral | `pam_unix\.so`, `\[` |

**Pièges :** `grep -E` ≠ `grep -P` ; `.` ≠ `\.` ; `*` se rapporte au caractère/groupe **précédent** ; les regex peuvent faire du « faux vert » si aucun objet n'est trouvé ; une capture Rudder `${match.1}` ne correspond **pas** à la variable shell `$1`.

## 10. grep / sed / awk / find / diff — atelier d'investigation

```bash
# GREP : retrouver un paramètre sans bruit
sudo grep -RniE 'nullok|PermitEmptyPasswords|PasswordAuthentication' /etc/pam.d /etc/ssh 2>/dev/null
grep -nH -P '^\s*auth\s+.*pam_unix\.so' /etc/pam.d/common-auth
grep -nF 'literal.string[abc]' fichier   # recherche littérale

# SED : affichage et caractères invisibles, AUCUNE modification
sed -n '10,30p' /etc/pam.d/common-auth  # lignes 10-30
sed -n '6l;8l' /usr/share/pam-configs/unix  # tabulations, fins de lignes
sed -n '/pam_unix/p' /etc/pam.d/common-auth
sed -n 's/nullok/[NULL_OK]/p' /etc/pam.d/common-auth  # prévisualise transformation
# NE PAS utiliser sed -i en prod sans sauvegarde + validation.

# AWK : colonnes et filtres
awk -F: '{print $1, $3, $7}' /etc/passwd  # login UID shell
sudo awk -F: '$2 == "" {print $1}' /etc/shadow
awk '$1 == "nameserver" {print $2}' /etc/resolv.conf
awk 'NR>=10 && NR<=20 {print NR ":" $0}' /etc/pam.d/common-auth

# FIND / STAT / DIFF : contexte
find /etc -type f -mtime -2 2>/dev/null | head
stat -c '%n %a %U:%G %y' /etc/pam.d/common-auth
sudo diff -u /root/backup-pam/common-auth.bak /etc/pam.d/common-auth
sha256sum fichier_avant fichier_apres
findmnt -T /etc/pam.d/common-auth
```

**Astuce** : `sed -n 'l'` montre `\t`, les retours de ligne et certains caractères invisibles ; très utile pour diagnostiquer une regex Rudder qui ne trouve aucune ligne.

### 10A. `grep`, `sed`, `awk` — options qui font gagner du temps

| Outil | Option / expression | Effet |
|---|---|---|
| `grep` | `-nH` | numéros + noms de fichiers |
| `grep` | `-Rni` | récursif, ligne, insensible casse |
| `grep` | `-P` | PCRE si GNU grep compilé avec PCRE |
| `grep` | `-E` | ERE POSIX ; pas mêmes fonctionnalités |
| `grep` | `-F` | recherche fixe, plus sûre pour chaînes littérales |
| `grep` | `-v`, `-m1`, `-C3` | inverser ; 1er match ; contexte ±3 |
| `grep` | `-l`, `-L`, `-q` | fichiers matches ; fichiers sans match ; silencieux |
| `grep` | `-o`, `--color=always` | extraire match ; surligner dans terminal |
| `sed` | `-n '5,12p'` | seulement lignes 5 à 12 |
| `sed` | `-n '6l;8l'` | montrer TAB (`\t`), CR (`\r`), fin (`$`) |
| `sed` | `-n '/regexp/p'` | lignes correspondant à regex |
| `sed` | `'s/old/new/g'` | substituer **sur stdout** (sans `-i`) |
| `awk` | `-F:` / `-v x=...` | séparateur / variable shell injectée |
| `awk` | `NR`, `NF`, `$0`, `$1` | no ligne, nb champs, ligne, champ 1 |
| `awk` | `BEGIN`, `END` | début / fin de traitement |
| `find` | `-print0` | noms sécurisés avec espaces/newlines |
| `xargs` | `-0`, `-r`, `-n1` | lit NUL, pas de commande à vide, un arg/lot |

**Extractions prêtes à l'emploi :**

```bash
# Colonnes et filtres de comptes :
awk -F: '$3 >= 1000 && $3 < 60000 {printf "%-22s uid=%-8s shell=%s\n",$1,$3,$7}' /etc/passwd
# Sortie processus par RAM, puis top 10 :
ps -eo pid,%mem,rss,comm --sort=-rss | head -11
# Lignes contenant 'pam_unix' mais pas commentaires (PCRE, lecture seule) :
grep -nP '^\s*auth\s+.*pam_unix\.so' /etc/pam.d/common-auth
# TAB, CRLF et espaces de fin :
sed -n '1,30l' /etc/pam.d/common-auth
# Comparer sauvegarde ↔ actif :
diff -u /root/backup-pam/common-auth.bak /etc/pam.d/common-auth || true
# Résumer journaux d'un service par codes d'erreur (exemple) :
journalctl -u <service> -b --no-pager | grep -Ei 'error|failed|timeout|denied' | tail -60
```

**Exemples de `awk` décisionnel :**

```bash
# FS >= 85% (colonne Use% de df -P, hors pseudo-FS) :
df -P /var /home | awk 'NR>1 {gsub(/%/,"",$5); if ($5 >= 85) print $6, $5"%"}'
# Montrer le champ 2 d'un fichier "clé:valeur" :
awk -F: '$1 == "admin-user" {print $1, $3, $7}' /etc/passwd
# Compter les états d'un fichier texte Rudder (exemple, si log sauvegardé) :
awk '/^A\|/ {audit++} /^E\|/ {enforce++} END {print "Audit="audit+0,"Enforce="enforce+0}' run.log
```

**Éviter le `sed -i` en production sans revue.** Pour une prévisualisation sûre : `sed 's/nullok/[RETIRER nullok]/' fichier | diff -u fichier -` et vérifier attentivement le résultat ; ceci ne modifie aucun fichier.

## 11. Bash — boucles, tests, exit codes, lecture seule

```bash
# Variables protégées, boucle sur plusieurs hôtes/ports
HOST=192.0.2.10  # EXEMPLE : renseigner le vrai serveur
for port in 443 5309; do
    if nc -z -w3 "$HOST" "$port"; then
        echo "$HOST:$port OK"
    else
        echo "$HOST:$port KO"
    fi
done

# Test existence fichier / dossier
if [[ -f /etc/pam.d/common-auth ]]; then echo 'PAM présent'; fi
if [[ -d /sys/firmware/efi ]]; then echo 'UEFI'; else echo 'BIOS/Legacy'; fi

# While : lecture de noms de machine (pas d'action distante ici)
while IFS= read -r host; do
    [[ -z "$host" || "$host" == \#* ]] && continue
    printf 'Cible à auditer : %s\n' "$host"
done < hosts.txt

# Case : distribution
. /etc/os-release
case "$ID" in
  ubuntu|debian) echo 'Famille APT' ;;
  rhel|rocky|almalinux) echo 'Famille DNF' ;;
  *) echo "À vérifier : $ID" ;;
esac

# Retour d'exécution
commande
rc=$?
if (( rc != 0 )); then printf 'Commande échouée : code %d\n' "$rc"; fi
```

**Important** : `&&` exécute la suite seulement si code `0`; `||` si code non nul; `$?` code de la commande précédente; `set -e` n'est **pas** une stratégie universelle de gestion d'erreurs ; tester chaque appel important. Pour des boucles de remédiation, ajouter timeouts, logs, mode `dry-run`, idempotence et limite de concurrence.

### 11A. Bash L3 — robustesse, scripts d'audit et erreurs

```bash
#!/usr/bin/env bash
set -u                              # variable non définie = erreur
# set -e et pipefail : à utiliser si comportement maîtrisé, pas comme recette magique
HOST="${1:-}"
if [[ -z "$HOST" ]]; then echo "Usage: $0 <IP/FQDN>" >&2; exit 64; fi
for PORT in 443 5309; do
    if timeout 4 nc -z "$HOST" "$PORT" >/dev/null 2>&1; then
        printf 'OK %s:%d\n' "$HOST" "$PORT"
    else
        printf 'KO %s:%d\n' "$HOST" "$PORT" >&2
    fi
done
```

**Tests Bash fréquents :**

```bash
[[ -f "$f" ]] && echo 'fichier existe'
[[ -d "$d" ]] && echo 'répertoire existe'
[[ -r "$f" ]] && echo 'lisible'
[[ -x "$f" ]] && echo 'exécutable'
[[ -L "$f" ]] && readlink -f "$f"
[[ -s "$f" ]] && echo 'non vide'
[[ "$s" == 'ubuntu' ]] && echo 'OS connu'
(( count > 5 )) && echo 'seuil dépassé'
command -v lsscsi >/dev/null || echo 'outil non installé'
```

**Boucles :**

```bash
# Boucle sur services (lecture seule) :
for service in ssh cron systemd-resolved; do
  systemctl is-active "$service" || true
done

# Tableau, sans parsing de `ls` :
services=(ssh cron)
for service in "${services[@]}"; do printf '%s\n' "$service"; done

# Plusieurs fichiers, jamais "for file in $(ls ...)" :
for f in /etc/pam.d/common-*; do
  [[ -f "$f" ]] || continue
  grep -nH 'nullok' "$f" || true
done
```

**Exit codes / pipeline :**

```bash
# capturer le code DIRECTEMENT après la commande :
command_example
rc=$?
printf 'rc=%s\n' "$rc"
# `grep`: 0 = match, 1 = aucun match, 2 = erreur (selon GNU grep)
# `dnf check-update`: 0 = rien à mettre à jour, 100 = MAJ disponibles, 1 = erreur
# `oscap eval`: 2 peut signifier non-conformité, pas panne moteur
```

**Ancrage de bonne pratique** : scripts d'audit = lecture seule, timeout, journalisation datée, sortie par host, noms quotés, tri des codes de retour, pas de secrets. Remédiations : idempotence, `--check` quand possible, rollback, approbation et limites de parallélisme.

## 12. Patching APT / DNF — diagnostic et préparation

### Ubuntu / Debian

```bash
apt-cache policy <package>           # version installée/candidate, dépôts
dpkg -l | grep <package>
apt list --upgradable 2>/dev/null    # aperçu interactif
sudo apt-get -s upgrade              # simulation ; ne modifie pas packages
grep -RiE '^deb |^URIs:' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
sudo tail -n 80 /var/log/apt/history.log
sudo tail -n 80 /var/log/dpkg.log
uname -r
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required
```

`apt-get update` actualise les index et n'installe pas de paquet, mais effectue des accès dépôts et peut modifier les caches ; sur l'infrastructure LFM, respecter proxy et fenêtre opérationnelle.

### RHEL 8/9

```bash
rpm -q <package>
rpm -qi <package>
dnf repolist --enabled
dnf check-update                 # code 100 = updates disponibles, pas erreur fatale
dnf updateinfo list --security  # dépend des métadonnées dépôts
dnf history list | head -30
dnf history info <ID>
dnf repoquery --upgrades         # plugin/dnf selon version
uname -r
command -v needs-restarting && needs-restarting -r  # version/paquet nécessaire
```

**Sécurité** : distinguer package *installé*, kernel *installé* et kernel *actuellement booté*. Reboot à planifier après validations services/cluster. RHEL : vérifier Satellite/repos/Content Views/errata selon architecture réellement en place ; ne pas supposer Satellite chez LFM.

### Préchecks/postchecks minimum autour d'un patch

```bash
date -Is; hostnamectl; uname -r; uptime
systemctl --failed; df -hT; df -ih; free -h
ip -br a; ip route; ss -lntup
findmnt -a; journalctl -p err -b -n 80 --no-pager
# Ajouter contrôles applicatifs validés (URL health, port métier, cluster, NFS, DB...).
```

**Ne pas automatiser un `reboot` global** sans matrice des dépendances, supervision, HA et fenêtre autorisée. Patch ≠ upgrade majeur ; définir critère d'éligibilité et exceptions.

### 12A. Patching : préchecks, correctif, reboot, postchecks

**APT** (la simulation `apt-get -s` ne garantit pas l'impact applicatif réel) :

```bash
apt-cache policy <pkg>; dpkg-query -W <pkg>
apt-mark showhold                         # paquets bloqués
sudo apt-get -s upgrade                   # [RO*] simulation, accès aux métadonnées
sudo apt-get -s dist-upgrade              # [RO*] simulation avec dépendances/removals
cat /var/run/reboot-required 2>/dev/null  # si présent
ls /var/run/reboot-required.pkgs 2>/dev/null
```

**DNF/RHEL** (tenir compte proxy, Satellite et sources de dépôt) :

```bash
dnf repolist -v | head -80                # sources dépôts/cache
rpm -q <pkg>; rpm -q --changelog <pkg> | head -25
dnf updateinfo list --security            # métadonnées advisories si accessibles
dnf check-update                          # 100=MAJ disponibles
sudo dnf history info <ID>                # lecture historique transaction
rpm -qa --last | head -20                 # derniers packages (date install RPM)
```

**Reboot :** distinguer noyau installé et noyau chargé ; examiner HA, drains/clusters, sessions, services, backups, astreinte. La décision de redémarrer dépend des modifications réellement appliquées et du processus interne. Sur Debian et RHEL, les outils/conventions indiquant reboot nécessaire peuvent différer : ne pas imposer une logique commune universelle.

**Exemple de journal de validation :**

```bash
# [RO] AVANT et APRÈS, sorties datées dans un répertoire autorisé :
date -Is; uname -r; uptime
systemctl --failed; findmnt -a; df -hT; df -ih
ss -lntup; ip -br a; ip route
journalctl -p err -b -n 70 --no-pager
# Ajouter healthcheck applicatif et validation du propriétaire.
```

## 13. Ansible — checklist sécurité et diagnostic

```bash
ansible --version
ansible-inventory -i inventory.ini --graph
ansible-inventory -i inventory.ini --list
ansible -i inventory.ini <groupe_pilote> -m ping       # connexion + Python, pas ICMP
ansible -i inventory.ini <groupe_pilote> -m setup -a 'filter=ansible_distribution*'
ansible-playbook -i inventory.ini patch.yml --syntax-check
ansible-playbook -i inventory.ini patch.yml --list-hosts
ansible-playbook -i inventory.ini patch.yml --check --diff --limit pilote
ansible-playbook -i inventory.ini patch.yml --limit pilote --step
ansible-lint patch.yml    # si installé
```

**À savoir** : `--check` (simulation) dépend des modules et ne détecte pas tous les effets ; `--diff` peut exposer des secrets ; `--step` impose confirmation de tâches, pas de garantie d'absence de risque ; `serial: 1`/vagues pour limiter le blast radius ; `become` maîtrisé. `UNREACHABLE` = transport/auth/SSH ; `FAILED` = action exécutée et en échec ; `CHANGED` = modification déclarée ; `OK` = état déclaré conforme ; `SKIPPED` = condition non remplie. Confronter au système réel.

### 13A. Ansible : modèles d'automatisation L3 sécurisée

**Vérifier le périmètre avant de lancer** :

```bash
ansible-inventory -i inventory.ini --graph
ansible-playbook -i inventory.ini remediation.yml --syntax-check
ansible-playbook -i inventory.ini remediation.yml --list-hosts --limit pilote
ansible-playbook -i inventory.ini remediation.yml --check --diff --limit pilote
ansible-playbook -i inventory.ini remediation.yml --limit pilote --step
```

**Exemple minimal de contrôle de service (lecture seule, sans modification)** :

```yaml
---
- name: Préchecks Linux LFM (exemple)
  hosts: pilote
  gather_facts: true
  serial: 1
  tasks:
    - name: Vérifier le kernel actif
      ansible.builtin.command: uname -r
      register: kernel
      changed_when: false
    - name: Afficher le kernel
      ansible.builtin.debug:
        var: kernel.stdout
    - name: Vérifier l'espace libre
      ansible.builtin.command: df -hT
      register: storage
      changed_when: false
    - name: Afficher les disques
      ansible.builtin.debug:
        var: storage.stdout_lines
```

**Retour Ansible :** `ok` vérifié, `changed` modifié selon module, `unreachable` cible non contactée (SSH/DNS/credentials), `failed` erreur pendant tâche, `skipped` condition non satisfaite. Sur l'infra LFM, *Rudder pour configuration/hardening* et *Ansible éventuellement pour orchestration patching* est une **orientation technique**, pas une architecture officiellement validée.

**Points durs** : `check_mode` non universel, secrets et `no_log: true`, `serial`/canary/limite, gestion packages reboot asynchrone (prévoir reconnect), rescue/block, métriques de validation, tags et inventaires propres.

## 14. Sécurité avancée : AIDE, auditd, permissions, services, sysctl

```bash
# Fichiers / permissions / SUID
namei -l /chemin/fichier
stat -c '%n %a %U:%G' /etc/ssh/sshd_config
getfacl /chemin/fichier
find /usr/bin -xdev -perm /4000 -type f 2>/dev/null | head
getcap -r /usr/bin 2>/dev/null | head

# AIDE si installé : peut être coûteux en I/O, et baseline à gouverner
command -v aide && aide --version
# auditd si installé
systemctl status auditd --no-pager
sudo auditctl -s
sudo ausearch -m USER_AUTH,USER_LOGIN -ts recent | tail -40

# Noyau et sysctl : d'abord lecture seule
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl --system                # MODIFIE : NE PAS lancer comme simple contrôle
systemd-analyze security <service>  # score indicatif, pas verdict CIS
```

**GRUB/boot** : vérifier `test -d /sys/firmware/efi` avant de conclure à une recommandation UEFI. Durcissement bootloader, réseau, PAM, SSH, pare-feu = modifications à fort risque opérationnel.

### 14A. SELinux, AppArmor, SSH, pare-feu : vérifier la protection effective

```bash
# RHEL — SELinux (lecture seule) :
getenforce; sestatus
ls -Z /chemin/ ; ps -eZ | head
sudo ausearch -m AVC,USER_AVC -ts recent | tail -50     # si auditd présent
# Ubuntu — AppArmor (lecture seule) :
sudo aa-status                                         # si AppArmor installé
journalctl -k -b | grep -Ei 'apparmor=.*DENIED|audit.*denied'
# Firewalls (lecture seule) :
sudo nft list ruleset
sudo ufw status numbered
sudo firewall-cmd --state; sudo firewall-cmd --list-all-zones
```

**Ne pas utiliser `setenforce 0`, `aa-complain`, `ufw disable` ou `systemctl stop firewalld` comme « diagnostic rapide » en production.** Analyser le refus exact et ses contrôles : contexte de fichier/port/domaines SELinux, profil AppArmor, zone firewalld et source/destination.

**CIS + ACL/permissions** :

```bash
stat -c '%a %U %G %n' /etc/shadow /etc/ssh/sshd_config
namei -l /etc/ssh/sshd_config
getfacl /chemin/fichier
find /etc -type f -perm /002 -print 2>/dev/null | head     # world-writable
sudo sshd -t; sudo visudo -c
sysctl -a 2>/dev/null | grep -E '(^net.ipv4.ip_forward|net.ipv4.conf.all.rp_filter)'
```

**AIDE / auditd / kernel hardening** : contrôler état du paquet, génération de baseline (si autorisée), intégrité et charge I/O. `aide --init` **[M]** peut être long et produit une base à protéger ; un scan de règles couvrant toute l'arborescence peut créer de la charge. `auditctl -l` = contrôle audit rules ; ajout/suppression de règles et modification de `sysctl` = [M].

### 14B. Matériel x86 et virtualisation — serveurs physiques

```bash
sudo dmidecode -t system -t bios -t memory       # [RO] asset, firmware, RAM
lscpu; lsblk -o NAME,SIZE,TYPE,MODEL,TRAN
lspci -nn | head -40                        # bus PCI/contrôleurs
sudo ethtool -i <iface>                      # driver NIC + firmware
sudo ipmitool sensor list                    # BMC/IPMI si installé/autorisations
sudo smartctl -H /dev/sdX                    # santé disque exposé si supporté
hostnamectl; systemd-detect-virt             # VM ou bare metal ?
```

**Dell/iDRAC/OME** : outils spécifiques et accès BMC à valider sur place, sans supposer qu'ils sont déployés chez LFM. Après changement firmware/driver : vérifier modèle exact, matrice compatibilité OS-hyperviseur, plan de reboot, rollback et état du matériel. `dmidecode` peut être limité en VM ; iDRAC n'est pas un substitut au diagnostic OS.

## 15. Situations LFM — réponse immédiate et orientation

| Situation | Démarche prioritaire | Commandes d'entrée | Correction envisagée seulement après analyse |
|---|---|---|---|
| Agent Rudder offline | IP, route, DNS, 443/5309, politique acceptée | `rudder agent info`, `nc`, `update -i`, logs | Réseau/ACL, policy server, service ciblé |
| Inventaire non reçu | Pipeline HTTPS, UUID, signature, allowed network | `inventory -i`, `webapp.log`, UI | Corriger flux, identité, acceptation |
| `A\| compliant` mais CIS FAIL | Comparer périmètre de contrôle et regex | `grep -nHP`, test sur fichier, rapport HTML | Réécrire contrôle, pas forcer Enforce |
| SSH bloqué après hardening | Accès console, configuration effective, PAM | `sshd -t`, `sshd -T`, `journalctl`, `diff` | Désactiver politique + restauration validée |
| `sudo` cassé | Console root/OOB, sudoers/PAM, diff | `visudo -c`, `journalctl`, `diff` | Restaurer fichier et empêcher re-remédiation |
| Service HS après patch | Dépendances, kernel, librairies, logs | `systemctl status/cat`, `journalctl -u`, `uname -r` | Rollback paquet/kernel selon plan |
| Host CPU 100 % | Trouver PID, cause, impacts | `top`, `ps`, `pidstat`, `journalctl` | Limiter workload/corriger applicatif |
| FS plein | Bloc/inode/open-unlinked | `df -hT`, `df -i`, `lsof +L1`, `du -x` | Nettoyage approuvé / extension préparée |
| NFS lent | Réseau, mount, serveur, IO | `findmnt`, `nfsstat -m`, `iostat`, `ss` | Corriger source, pas de démontage aveugle |
| OpenSCAP 112 FAIL | Qualifier par criticité et applicabilité | rapport, rule ID, preuve, contrôle OS | Pilote par lots, pas `--remediate` global |
| CVE critique | Identifier exposition, version patchée, redémarrage | `rpm -q`, `apt-cache policy`, errata | Changement piloté, mesure compensatoire si blocage |
| RHEL authselect écrasé | Inspecter profil source et état authselect | `authselect current/check` | Profil personnalisé et processus approuvé |

### 15A. Cinq mini-runbooks **symptôme → première action**

**1. « `/var` plein »** : `df -hT /var` → `df -ih /var` → `du -xhd1 /var` → `lsof +L1` → logs/dossiers responsables → nettoyage autorisé OU extension LVM/vCenter (voir §4A). **Ne pas vider `/var/log` au hasard**.

**2. « SSH ne fonctionne plus après CIS »** : accès OOB → `sshd -t`, `sshd -T -C user=...,addr=...,host=...` → `journalctl -u ssh/sshd` → `grep` PAM/authselect → `diff` politique → stop Rule Rudder/rollback ciblé → tests nouvelle session.

**3. « 80 agents Rudder en erreur »** : déterminer point commun relais/site/horodatage ; Root health, cert/443/5309, génération de policies, db/disk/time. Ne pas dépanner 80 machines individuellement avant d'isoler le facteur commun.

**4. « OpenSCAP PASS chez hôte A et FAIL chez hôte B »** : comparer version OS, datastream/profil, paramètres adaptés, applicabilité de la règle, configuration effective, overrides, exceptions documentées. Éviter de comparer des scores de référentiels différents.

**5. « Nouveau disque VMware non visible »** : vérifier ajout VMDK à la bonne VM et contrôleur → `lsscsi -s`, `lsblk` → scan SCSI ciblé → identité by-id/serial/WWN → PV neuf seulement si disque vierge et changement autorisé → `vgextend`/`lvextend -r` → postchecks FS. **Ne jamais `pvcreate` avant mapping certain.**

### 15B. Matrice de décision — agir ou escalader ?

| Risque | Exemples | Approche |
|---|---|---|
| **Faible** | commandes RO, `grep`, `journalctl`, `lsblk`, `oscap info` | diagnostic immédiat dans les habilitations |
| **Moyen** | audit OpenSCAP complet, capture réseau, `rudder agent inventory`, scan SCSI ciblé | évaluer charge, données et périmètre |
| **Fort** | `lvextend`, `vgextend`, patch packages, modifications PAM/SSH, reload firewall | ticket/changement, pilote, rollback, validation métier |
| **Critique** | `pvcreate` mauvais device, `mkfs`, `wipefs`, FS shrink, `authselect --force`, reboot prod | opération destructrice : double vérification / autorisation renforcée |

## 16. Lecture des commandes — aide-mémoire compacte

| Commande | Option | Signification |
|---|---|---|
| `grep` | `-n` / `-H` | Numéro de ligne / afficher nom du fichier |
| `grep` | `-R` / `-i` | Récursif / ignorer la casse |
| `grep` | `-E` / `-P` / `-F` | Regex étendue POSIX / PCRE / texte fixe |
| `grep` | `-v` / `-C3` | Inverser / montrer 3 lignes autour |
| `sed` | `-n '10,20p'` | Montrer uniquement lignes 10 à 20 |
| `sed` | `-n 'l'` | Afficher les caractères invisibles |
| `awk` | `-F:` | Séparateur de champs = `:` |
| `find` | `-mtime -1` | Modifié il y a moins de 24 h (arrondi jours) |
| `find` | `-xdev` | Rester sur le filesystem courant |
| `ps` | `--sort=-%cpu` | Trier CPU décroissant |
| `journalctl` | `-u`, `-b`, `-p` | Unité, boot, priorité |
| `ss` | `-lntup` | Listen, Numeric, TCP, UDP, Processes |
| `curl` | `-v`, `-I`, `-k` | Verbeux, HEAD, ignorer vérif TLS (diagnostic) |
| `df` | `-hT`, `-i` | Humain + type FS, inodes |
| `du` | `-x`, `-h`, `-d1` | Même FS, humain, profondeur 1 |
| `diff` | `-u` | Diff unifié avant/après |
| `stat` | `-c` | Format personnalisé (droits, horodatage) |
| `systemctl` | `--failed`, `cat` | Unités échouées, unité + overrides |

## 17. Modèle de note d'incident / écart CIS

```text
Serveur / environnement / rôle / propriétaire applicatif :
OS / version / kernel / groupe Rudder :
Heure début / heure constat / fuseau :
Symptôme / impact métier / gravité :
État avant : services, réseau, ressources, sécurité :
Outil d'alerte : Rudder | OpenSCAP | supervision | ticket :
Rule ID CIS / score / profil / datastream / version :
Commandes de diagnostic (et sorties utiles) :
Cause avérée vs hypothèses :
Changement récent / dépendances / exceptions :
Plan correctif + tests pilote + sauvegarde/rollback :
Validation post-action (services + scan + Rudder) :
Ticket / acteur / date / résultat / suivi :
```

## 18. Première journée LFM — cinq vérifications sans présupposé

1. Qui est propriétaire des serveurs, des changements, des politiques CIS et des exceptions ? Quel est le **périmètre réel** (OS/EOL/criticité) ?
2. Rudder : version, Root/Relays, groupes pilotes, droits, modes Audit/Enforce, sauvegarde des Techniques, Git ?
3. OpenSCAP : source du datastream, version du CIS Benchmark, profils, fréquence, stockage et nomenclature des rapports ; score cible et mode de comptage ?
4. Patching : outils existants, dépôts internes/proxy, RHSA et canaux RHEL, fenêtres, reboot, VMware/snapshot, HA/NFS, contrôle applicatif.
5. Processus : accès bastion/console, tickets, supervision, backup/restauration testée, responsables métier, processus d'urgence et d'exception.

---

## Références techniques et limites

- Broadcom/VMware (03/2026) — nouveau VMDK puis `pvcreate/vgextend/lvextend` : https://knowledge.broadcom.com/external/article/431753/online-lvm-capacity-expansion-on-running.html
- Red Hat RHEL 9 — LVM et redimensionnement : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/configuring_and_managing_logical_volumes/configuring_and_managing_logical_volumes
- Ubuntu Server — volumes logiques / LVM : https://ubuntu.com/server/docs/how-to/storage/manage-logical-volumes/
- Debian — `lsscsi` et H:C:T:L : https://manpages.debian.org/bullseye/lsscsi/lsscsi.8.en.html
- Rudder 9.1 — Troubleshooting : https://docs.rudder.io/reference/9.1/administration/troubleshooting.html
- Rudder 9.1 — Flux réseau : https://docs.rudder.io/reference/9.1/installation/requirements.html
- Rudder 9.1 — Administration serveur : https://docs.rudder.io/reference/9.1/administration/server.html
- Rudder — Logs : https://docs.rudder.io/reference/9.0/reference/logs.html
- Rudder — `file_replace_lines` et captures : https://docs.rudder.io/techniques/8.1/file_replace_lines.html
- Rudder 9.1 — Architecture et inventaires : https://docs.rudder.io/reference/9.1/reference/architecture.html
- OpenSCAP — Manuel : https://static.open-scap.org/openscap-1.4.1/oscap_user_manual.html
- Red Hat RHEL 9 — Compliance/OpenSCAP : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/scanning-the-system-for-configuration-compliance-and-vulnerabilities_security-hardening
- Canonical — Ubuntu Security Guide : https://documentation.ubuntu.com/security/compliance/usg/

**Mise en garde** : ce document est un aide-mémoire de préparation, pas un runbook LFM validé. Les chemins, versions, droits et commandes doivent être adaptés au serveur et à la politique interne. Les exemples du lab (Rudder 9.1.5, Ubuntu 24.04, comptes/IP) restent des exemples ; ne pas partager de secrets, empreintes privées ou informations de production non autorisées.
---

## 19. Capitalisation BNP / BP2I — acquis transférables à LFM

> **Provenance** — Cette section intègre `BNP Paribas — Capitalisation technique Linux L3 / SysOps`, transmis le 2 novembre 2026. L'extraction se fonde principalement sur des résumés d'échanges et des CV : elle **ne donne pas accès aux tickets complets ni aux scripts d'origine**. Indicateurs : **[H]** élément retrouvé dans cette extraction ; **[C]** complément technique vérifiable, non attribué comme opération exécutée chez BNP ; **[?]** information non suffisamment documentée. Les noms internes de collections et les identifiants d'infrastructure ont été anonymisés.
>
> **À retenir** : l'expérience historique confirme des activités Linux de production, pas une certitude sur l'outil, la version ou la procédure réellement déployée chez LFM. Vérifier le SI LFM avant toute action.

| Sujet retrouvé dans l'historique | Transférable à LFM | Ce qu'il ne faut pas présumer |
|---|---|---|
| [H] RHEL 7/8/9, BUILD, RUN, MCO, N2/N3 | Triage d'incidents, patching, hardening, revue kernel | Niveau de support et versions LFM |
| [H] Satellite : Content Views / environnements / Capsules | Dépôts maîtrisés, traçabilité des mises à jour, classification des errata | Satellite présent chez LFM |
| [H] LCM : Patch Light / Kernel, Upgrade / Post-Upgrade | Préchecks, vagues de déploiement, reboot, postchecks | Noms exacts des jobs et pipelines |
| [H] Leapp : migrations RHEL 7→8→9 mentionnées | Gestion des prérequis, inhibitors et transitions majeures | Chemin de migration supporté pour un hôte donné |
| [H] PAM/Authselect, packaging RPM, rôle Ansible | Conception de règles CIS, risque d'accès SSH/sudo | Même générateur de PAM sur Ubuntu |
| [H] Ansible/AAP2, Jinja2, GitLab, CI/lint | Remédiation idempotente et industrialisation | Détail des inventaires/workflows, à confirmer |
| [H] DNS, NTP/Chrony, décommissionnement qualifié par ELK | Analyse de flux, configuration effective, test avant/après | Détails des serveurs ou données internes |
| [H] Dell/HPE, iDRAC/OME, mises à jour BIOS/firmware | Incident matériel, compatibilité kernel/driver, console OOB | Modèle, contrôleur et CLI HPE exacts |
| [H] Veritas Cluster, VXFS, GPFS, SAN | Détection de dépendances avant reboot, storage, patching | Aucun détail précis de cluster ni script historique |
| [H] VMware, IBM Cloud VSI, crashdump | Build, capacité, diagnostics post-reboot | CLI IBM Cloud et processus de restauration inconnus |
| [H] ELK/Kibana, Dynatrace, ServiceNow/Jira | Preuves de changement et suivi des écarts | Organisation de l'observabilité LFM |

**Éléments à confirmer, non à promouvoir en expérience prouvée** : taille de parc déclarée dans d'anciens CV, réalisations détaillées d'inventaires dynamiques AAP2, usage opérationnel RHEL 10, détails Kubernetes/Terraform/OpenShift, incidents unitaires dont les tickets ne sont pas disponibles. Une ancienne correction de CV demande de ne pas surestimer la responsabilité sur les inventaires/workflows AAP2 : **ne pas transformer cette mention en réalisation personnelle certaine**.

### 19.1. Trois chaînes d'exploitation à garder en tête

**Chaîne LCM** — [H] éléments de workflow, séquence exacte à confirmer par organisation :

```text
Périmètre → versions/dépôts → préchecks → ticket/fenêtre → patch
      → reboot autorisé si requis → postchecks → correction des échecs
      → état RHSM/Satellite → reporting / traçabilité
```

**Chaîne migration RHEL majeure Leapp** — [H] étapes citées ; [C] leurs contrôles :

```text
Pré-requis → snapshot/sauvegarde → leapp preupgrade → inhibitors/answerfile
       → décision GO/NO-GO → leapp upgrade (CHG) → reboot
       → kernel/paquets/réseau/stockage/SSSD/services → recette métier
```

**Chaîne hardening** — [H] expérience Authselect/CIS et automatisation ; [C] adaptation Rudder :

```text
Benchmark adapté → preuve d'écart → applicabilité → exception éventuelle
      → Technique / groupe pilote → Audit → Enforce autorisé
      → contrôle de l'authentification et de la disponibilité → OpenSCAP
```

## 20. Red Hat Satellite, RHSM et errata — diagnostic par couche

**Situation** : « le serveur ne reçoit pas le correctif attendu », « erreur de dépôt après patch », « enregistrement Satellite perdu ». L'extraction confirme l'utilisation de Satellite et d'automatisations post-upgrade, mais **ne fournit pas de ticket réel entièrement résolu**.

### 20.1. Côté client RHEL : lecture seule d'abord

```bash
cat /etc/redhat-release                        # [RO] version RHEL
subscription-manager identity                  # [RO] enregistrement connu localement
subscription-manager status                    # [RO] interpréter selon SCA/architecture
subscription-manager repos --list-enabled      # [RO] dépôts RHSM déclarés
sudo dnf repolist -v                           # [RO] dépôts effectivement visibles
sudo dnf repolist --all                        # [RO] actifs + désactivés
sudo dnf module list --enabled                 # [RO] RHEL8 / modularité si utilisée
rpm -q katello-ca-consumer                     # [RO] si ce paquet est présent
ls -l /etc/yum.repos.d/                        # [RO] sources des fichiers .repo
sudo dnf history | head -25                    # [RO] transactions récentes
sudo dnf updateinfo summary                    # [RO] synthèse errata exposés par dépôt
sudo dnf updateinfo list security              # [RO] avis de sécurité disponibles
sudo dnf updateinfo info RHSA-YYYY:NNNN       # [RO] remplacer par vrai identifiant
```

**Ne pas interpréter `subscription-manager status` seul** : dans certains déploiements avec Simple Content Access (SCA), le message peut ne pas correspondre à l'attente d'un ancien mode de souscription. Corréler identité, dépôts, certificats, accès réseau et politique Satellite.

| Résultat observé | Piste d'investigation | Action sûre |
|---|---|---|
| Identité absente | Machine non enregistrée ou état RHSM perdu | Identifier la procédure d'enregistrement validée ; **pas** de `register --force` improvisé |
| Dépôt absent | Content View / Lifecycle / activation key / filtre | Comparer hôte et machine saine du même groupe |
| `403` / `401` | Accès, certificat, entitlement / proxy | Vérifier état Satellite, heure, certificats, jetons ; ne rien publier dans le ticket |
| Erreur TLS/certificat | CA locale, DNS, proxy, NTP | `timedatectl`, `getent`, `curl -v` sans désactiver TLS en production |
| `No match for argument` | Nom, stream, dépôt ou version non disponible | `dnf list --showduplicates <paquet>`, `dnf repoquery` si installé |
| Erratum absent | Métadonnées/updateinfo filtrées | Comparer CV, package installé, version disponible et erratum exact |
| `dnf check-update` rc=100 | Mise à jour disponible, **pas** échec | Traiter 0 = aucune, 100 = présente, autre = erreur |

### 20.2. Sur serveur Satellite autorisé : Hammer (read-only)

```bash
hammer --version
hammer organization list
hammer lifecycle-environment list --organization '<ORG>'
hammer content-view list --organization '<ORG>'
hammer content-view version list --content-view '<CV>' --organization '<ORG>'
hammer content-view-environment list --organization '<ORG>'
hammer host list --search '<HOSTNAME>'
```

**Selon version et droits**, des noms/options varient : consulter `hammer <sous-commande> --help`. Le triptyque à vérifier est **produit/dépôt → Content View et version publiée → Lifecycle Environment affecté à l'hôte**. Ne jamais lancer `hammer ... publish`, `promote`, `host update`, `subscription-manager unregister/register` ou `dnf update` pour « regarder ».

### 20.3. Patching RHEL : suivre le changement, pas seulement l'orchestrateur

```bash
uname -r; rpm -q kernel-core                       # [RO] noyau actif / installés
rpm -qa --last | head -25                        # [RO] paquets récemment installés
sudo dnf history info <TRANSACTION_ID>            # [RO] contenu transaction
sudo dnf history list                            # [RO] transactions
systemctl --failed --no-pager                    # [RO] services en échec
journalctl -b -p err --no-pager | tail -70        # [RO] erreurs du boot
findmnt -t nfs,nfs4                              # [RO] montages NFS
sudo pvs; sudo vgs; sudo lvs                      # [RO] cohérence LVM
```

**Après reboot** : `uname -r` doit refléter le noyau **effectivement démarré**, pas simplement un RPM installé. Un job `SUCCESS` signifie que l'orchestrateur a terminé, **pas** que le serveur et son application sont sains.

**[H] Ancrage historique** : campagnes Patch Light/Kernel, étapes Upgrade/Post-Upgrade et réenregistrement Satellite automatisé. Les commandes ci-dessus sont [C], sauf mention contraire dans l'extraction.

## 21. Leapp / RHEL 7→8 et 8→9 — inhibitors et retour arrière

**Situation** : « Leapp preupgrade termine avec un inhibitor » ou « un serveur RHEL redémarre mal après upgrade ». Les chemins d'upgrade pris en charge **dépendent des versions mineures, éditions, dépôts et matrice Red Hat** : ne pas supposer qu'un saut direct de RHEL 7 à RHEL 9 est supporté.

```bash
cat /etc/redhat-release                          # [RO] version source
uname -r; lsblk -f; df -hT                      # [RO] noyau/stockage
rpm -qa | grep -Ei '^leapp|leapp-'              # [RO] composants disponibles
ls -lh /var/log/leapp/                          # [RO] rapports présents
less /var/log/leapp/leapp-report.txt             # [RO] rapport lisible
grep -nEi 'inhibitor|high|medium|missing|required|answer' \
  /var/log/leapp/leapp-report.txt               # [RO] repérer blocages
less /var/log/leapp/leapp-preupgrade.log         # [RO] log préparation
sudo cat /var/log/leapp/answerfile               # [RO] questions nécessitant réponse
```

`leapp preupgrade` est **[SCAN/M]** : évaluation qui écrit rapports et consomme de l'espace (jusqu'à plusieurs Go selon configuration). Ce n'est pas une simple commande de consultation ; la programmer après les préchecks et le feu vert opérationnel.

| Diagnostic | Sens | Approche |
|---|---|---|
| `inhibitor` | **NO-GO** pour l'upgrade tant qu'il subsiste | Lire contexte précis et traiter chaque cause |
| `Missing required answers` | Question dans `answerfile` non résolue | Étudier réponse et risque, `leapp answer ...` **[M]** après validation |
| Rapport sans inhibitor | Ne prouve **pas** que l'upgrade réussira | Lire aussi les risques High/Medium et la compatibilité applicative |
| Espace `/var/lib/leapp` bas | Analyse incomplète / échec possible | Capacity planning, ne pas déplacer sans analyse |
| Post-reboot sans réseau | NM, device/driver, nommage, route, DNS | Console OOB, `ip -br a`, `ip route`, `nmcli`, journal |
| Service non démarré | Application, bibliothèque/ABI, SELinux, mounts | `systemctl --failed`, `journalctl`, tests métier |

**Ne pas exécuter `leapp upgrade`, reboot, `dracut -f`, nettoyage de packages ou réponse automatique `True` à tous les prompts hors procédure approuvée.** Le rollback d'un upgrade majeur exige un plan adapté (backup/snapshot vérifié et dépendances externes).

## 22. PAM et identité — comparaison Ubuntu / RHEL / mécanismes générateurs

**[H]** Le profil Authselect spécifique RHEL/CIS, son packaging RPM et son déploiement Ansible apparaissent dans l'extraction. **[LAB CONFIRMÉ]** Notre TP Ubuntu Rudder a identifié 3 occurrences de `nullok`, validé YAML/Foreach en Audit, sans remédiation de production.

| Ubuntu/Debian (selon génération) | RHEL 8/9 avec Authselect |
|---|---|
| `/etc/pam.d/common-auth` | `/etc/pam.d/system-auth`, `password-auth` |
| `/usr/share/pam-configs/unix` | `/usr/share/authselect/default/...` ou `/etc/authselect/custom/...` |
| `pam-auth-update` | `authselect` et profils `sssd`/`winbind`/custom |
| `@include common-auth` | inclusion/stacks spécifiques au service |
| Vérifier `pam-auth-update` et le fichier **effectif** | Vérifier `authselect current`, `authselect check`, profil actif |

### 22.1. Commandes d'audit sans toucher à l'authentification

```bash
# Ubuntu/Debian :
grep -nH 'nullok' /etc/pam.d/common-auth /usr/share/pam-configs/unix
sed -n '6l;8l' /usr/share/pam-configs/unix     # révèle les tabs/espaces
head -18 /etc/pam.d/common-auth
grep -n 'common-auth' /etc/pam.d/sshd /etc/pam.d/sudo /etc/pam.d/login

# RHEL 8/9 :
authselect current                                # [RO] profil / features
authselect check                                  # [RO] cohérence fichiers gérés
authselect list                                   # [RO] profils disponibles
grep -RniE 'pam_unix|pam_sss|pam_faillock|nullok' /etc/pam.d/ /etc/authselect/ 2>/dev/null
sssctl domain-list                               # [RO] si SSSD installé

# Tous :
sshd -t                                          # [RO] syntaxe (root souvent requis)
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|permitemptypasswords'
visudo -c                                        # [RO] syntaxe sudoers
id <USER>; getent passwd <USER>; passwd -S <USER>
```

**Piège redoutable** : modifier une sortie générée (`common-auth` ou `system-auth`) sans corriger son mécanisme de génération provoque une dérive ou un retour de l'écart au prochain changement. Pour un profil Authselect personnalisé nécessitant des modifications PAM persistantes, **ne pas utiliser `--symlink-pam`** lors de la création d'un profil qui doit contenir des copies éditables des modèles PAM ; suivre les instructions Red Hat de la version cible.

**PAM → plan de changement** : snapshot/backup validé, utilisateur test et console OOB, session existante maintenue, Rule Rudder pilote en Audit, correction ciblée en fenêtre, nouvelle session SSH, `sudo -k; sudo -v`, logs d'authentification, rollback si KO. **Éviter `pam-auth-update --force` et `authselect select --force`** comme solutions réflexes.

### 22.2. Le piège `nullok` rencontré ensemble

```text
Ubuntu :  /etc/pam.d/common-auth → pam_unix.so nullok
          /usr/share/pam-configs/unix → Auth:         nullok try_first_pass
          /usr/share/pam-configs/unix → Auth-Initial: nullok

Rudder : 3 composants non-compliant en Audit ≠ 3 règles CIS distinctes.
```

```bash
grep -nHP '^\s*\[success=end default=ignore\]\s+pam_unix\.so\s+nullok' \
  /usr/share/pam-configs/unix                 # [RO] matcher indentation
awk -F: '$2 == "" {print $1}' /etc/shadow     # [RO, ROOT] détecter champ shadow vide
```

**Protection des identifiants** : ne jamais copier des hash `/etc/shadow` ou des tokens dans une conversation, un rapport, un ticket ou Git. La présence de `nullok` est un défaut de politique possible **même si aucun compte local n'a de mot de passe vide**.

## 23. Ansible / AAP2 — build, contrôles et remédiation à grande échelle

**[H]** Les sources mentionnent GitLab/Jenkins, collection Ansible interne, roles de build, configurations DNS/NTP, packaging et déploiement Authselect, Upgrade/Post-Upgrade, et Python préparant des données d'automatisation. Les détails d'inventaires dynamiques attribués personnellement au profil restent **[?]**.

### 23.1. Remettre les contrôles dans le bon ordre

```bash
ansible --version
ansible-config dump --only-changed                # [RO] overrides actifs
ansible-galaxy collection list                    # [RO] collections disponibles
ansible-inventory -i inventory.yml --graph         # [RO] périmètre
ansible-playbook -i inventory.yml site.yml --syntax-check
ansible-playbook -i inventory.yml site.yml --list-hosts
ansible-playbook -i inventory.yml site.yml --list-tasks
ansible-lint site.yml                              # [RO] qualité, si installé
ansible-playbook -i inventory.yml site.yml --check --diff --limit pilote
```

`--check` n'est **pas** une simulation fiable pour tous les modules, et `--diff` peut révéler des secrets. Éviter `--diff` sur les fichiers sensibles ; utiliser `diff: false` et `no_log: true` là où c'est approprié.

### 23.2. Lecture des échecs AAP2 / Ansible

| Sortie | Interprétation | Investigation |
|---|---|---|
| `ok` | Déjà dans l'état voulu / tâche exécutée sans changement | Confirmer la donnée métier attendue |
| `changed` | Modification déclarée | Diff, handler et postcheck |
| `failed` | Tâche exécutée mais erreur | `msg`, `rc`, `stderr`, variables, privilèges, paquet/service |
| `unreachable` | Transport/connexion vers cible impossible | Inventaire, DNS, route, SSH, bastion, clé, Win? non pertinent Linux |
| `skipped` | Condition/tag ou check mode | `when`, facts, tags |
| `rescued` | Gestion d'échec de bloc | Contrôler rétablissement réel, pas juste statut du bloc |

### 23.3. Playbook **audit uniquement** pour rafraîchir YAML / boucles / condition

```yaml
---
- name: Diagnostic Linux minimal et non destructif
  hosts: linux_pilot
  gather_facts: true
  serial: 1
  tasks:
    - name: Collecter le noyau actif
      ansible.builtin.command: uname -r
      register: kernel_info
      changed_when: false

    - name: Vérifier les composants attendus selon distribution
      ansible.builtin.command: "{{ item }}"
      loop:
        - /usr/bin/uptime
        - /usr/bin/df -hT
      register: check_results
      changed_when: false

    - name: Afficher le noyau
      ansible.builtin.debug:
        var: kernel_info.stdout

    - name: Afficher l'identifiant Red Hat seulement si RHEL
      ansible.builtin.debug:
        msg: "Famille Red Hat : {{ ansible_facts['distribution'] }}"
      when: ansible_facts['os_family'] == 'RedHat'
```

**Attention** : dans le `loop` de `ansible.builtin.command`, chaque item doit rester une commande valide avec ses arguments, et un chemin absolu comme `/usr/bin/df` peut varier selon OS. Pour une production hétérogène, préférer les modules natifs et contrôles homogènes ; cet exemple est pédagogique.

### 23.4. Precheck avant mutation par vagues

```bash
# [RO] en lecture de périmètre ; exécution réelle modifiante uniquement après validation
ansible-playbook -i inventory.yml site.yml --list-hosts --limit pilote
ansible-playbook -i inventory.yml site.yml --check --limit pilote
# En production, si validé : utiliser --limit pilote + serial + suivi du rollout
```

**Idempotence** : un état « compliant » après une première modification doit rester stable lors des passages suivants, et un job ne doit pas faire « changed » sans raison à chaque exécution.

## 24. DNS / NTP / observabilité — cas hérités de l'expérience BNP

**[H]** Les remédiations DNS `resolv.conf`/Jinja2, NTP au BUILD/RUN et les analyses ELK avant décommissionnement ont été rapportées. Aucune adresse interne ni requête ELK propriétaire n'a été importée.

### 24.1. Quelle configuration DNS est réellement active ?

```bash
readlink -f /etc/resolv.conf
ls -l /etc/resolv.conf
cat /etc/resolv.conf
cat /etc/nsswitch.conf | grep '^hosts:'
getent ahosts <NOM>
dig +time=2 +tries=1 <NOM>
dig @<IP_DNS> <NOM>
resolvectl status                 # si systemd-resolved utilisé
nmcli -f GENERAL,IP4 device show # si NetworkManager gère la connexion
```

**Diagnostic** : une modification manuelle de `/etc/resolv.conf` peut être écrasée par NetworkManager, DHCP, Netplan ou systemd-resolved. **Modifier la source autoritative** après avoir identifié le gestionnaire et le périmètre, pas uniquement le fichier généré.

### 24.2. NTP / Chrony : ne pas confondre service actif et synchronisation réelle

```bash
timedatectl status
systemctl status chronyd --no-pager       # RHEL, si chrony utilisé
systemctl status chrony --no-pager        # Ubuntu, si chrony utilisé
chronyc tracking
chronyc sources -v
chronyc sourcestats -v
ss -ulpn | grep ':123'                  # NTP UDP, si serveur local
```

**Interprétation rapide** : `Leap status : Normal` et une source sélectionnée `^*` indiquent typiquement une synchronisation ; source non joignable ou très fort décalage = vérifier UDP/123, DNS, service, politique NTP, accès. Une horloge incorrecte perturbe TLS, journaux, authentification et certains agents de conformité.

### 24.3. Décommissionnement contrôlé : l'enseignement historique

```text
Recenser les dépendances → analyser les requêtes/logs → distinguer préprod/prod
→ notifier les propriétaires → tester le remplacement → retirer par vagues
→ suivre erreurs DNS et retours applicatifs → préparer le rollback.
```

**Ne pas confondre absence de trafic observé et absence de dépendance** : rétention des logs, applications intermittentes, clients non vus, caches DNS et exigences de continuité peuvent masquer des usages.

## 25. Veritas / VXFS / GPFS / SAN — avant de toucher à un cluster

**[H]** Build/MCO Veritas Cluster, intégration SAN, upgrade kernel, VXFS et GPFS font partie du périmètre historique. **[?]** Aucun ticket, capture de `hastatus` ni commande Veritas exécutée n'a été récupéré. Les commandes ci-dessous sont des pistes de lecture pour environnement équipé et compatible ; **vérifier l'aide/version locale**.

### 25.1. Avant reboot, patch ou extension de stockage

```bash
uname -r; lsmod | grep -Ei 'vx|gpfs|dm_multipath'
findmnt -o SOURCE,TARGET,FSTYPE,OPTIONS | grep -Ei 'vxfs|gpfs|nfs'
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
multipath -ll                       # si Device Mapper Multipath déployé
pvs -o pv_name,pv_size,vg_name,pv_uuid
```

Sur un hôte avec Veritas InfoScale, commandes **à confirmer selon version et habilitations** :

```bash
hastatus -sum                       # [RO] résumé cluster VCS si outil présent
hagrp -state                        # [RO] groupes de service
vxprint -ht                         # [RO] topologie volumes VxVM (peut être volumineuse)
vxdisk list                         # [RO] état et identifiants des disques VxVM
vxdg list                           # [RO] disk groups visibles
```

**Précautions** : distinguer VG LVM vs disk group VxVM ; **ne pas lancer `pvcreate`, `vgextend`, `lvextend` sur une LUN VxVM/cluster ou partagée sans vérification**. Identifier HA, failover, ordre des ressources, filesystem cluster et propriétaire applicatif. Ne pas modifier des ressources VCS en production hors protocole d'exploitation.

### 25.2. Diagnostic de panne : méthode

1. **Cluster** : quorums, nœuds, service groups, master, état des ressources.
2. **Stockage** : chemins SAN, WWID, multipath, baie, erreurs SCSI, réseau inter-nœud.
3. **Kernel/modules** : module Veritas ou GPFS compatible avec nouveau kernel ?
4. **Applications** : montages et dépendances, services et portage des ressources.
5. **Risques** : un `systemctl reboot`, `umount`, rescan ou `multipath -F` non contrôlé peut faire tomber un service.

## 26. Dell / HPE — firmware et console OOB, approche non destructive

**[H]** Gestion Dell/HPE, BIOS/firmware/driver, iDRAC et OpenManage Enterprise. **[?]** Pas de commandes RACADM exécutées ni de modèle HPE précis dans l'extraction.

```bash
sudo dmidecode -t system -t bios          # [RO] modèle, firmware
lscpu; lspci -nn                          # [RO] CPU et bus/contrôleurs
sudo ethtool -i <INTERFACE>              # [RO] pilote et version firmware NIC
sudo lshw -class network -class storage   # [RO] si lshw installé
journalctl -k -b | grep -Ei 'firmware|microcode|raid|pci|link down'
```

Sur un équipement Dell/iDRAC pour lequel RACADM est disponible et autorisé :

```bash
racadm getversion                         # [RO] firmware BIOS/iDRAC/LC selon version
racadm getsysinfo                         # [RO] informations système
racadm getsensorinfo                      # [RO] températures, ventilation, alimentation
racadm getsel                             # [RO] journal matériel, si supporté
racadm hwinventory                        # [RO] inventaire hardware, si supporté
```

**Méthode firmware** : vérifier la cible exacte, l'état matériel initial, les versions BIOS/iDRAC/NIC/RAID, la matrice constructeur, la dépendance kernel/driver, la redondance, la fenêtre de reboot, l'alimentation et l'accès OOB. Sur HPE, utiliser les outils réellement validés (iLO / outils constructeur si déployés), pas une commande Dell transposée à l'identique.

**Console clavier iDRAC** : `localectl status` et `loadkeys fr` se rapportent à la console Linux, alors que le client iDRAC peut appliquer son propre mapping. `loadkeys fr` change l'état console ; à exécuter uniquement si nécessaire, pas comme commande d'information.

## 27. VMware / IBM Cloud VSI / provisioning / crashdump

**[H]** Environnements VMware vSphere et IBM Cloud VSI, gestion de disques/snapshots/crashdump, automatisation du build. **[?]** L'extraction ne contient pas les commandes IBM Cloud CLI, les templates de VM ou une analyse de vmcore précise.

### 27.1. Contrôle d'une VM fraîchement provisionnée

```bash
hostnamectl; cat /etc/os-release; uname -r
systemd-detect-virt                          # vmware/kvm/none, si détectable
lscpu; free -h; lsblk -f; df -hT
ip -br a; ip route; getent ahosts <NOM_CIBLE>
timedatectl; chronyc tracking               # si chrony installé
systemctl --failed
journalctl -b -p err --no-pager | tail -60
```

Compléter selon LFM : agents de supervision, EDR, backup, Rudder, dépôts, IAM/SSSD, montages NFS, `fstab`, règles applicatives et rattachement aux groupes de configuration.

### 27.2. Capture kernel / Kdump : triage non destructif

```bash
systemctl status kdump --no-pager            # RHEL avec kdump
kdumpctl status                              # RHEL si kdumpctl installé
cat /proc/cmdline | tr ' ' '\n' | grep '^crashkernel='
ls -lh /var/crash/                         # contenu selon configuration
journalctl -k -b -1 --no-pager | tail -120  # si boot précédent accessible
```

**Danger** : provoquer un crash volontaire (`echo c > /proc/sysrq-trigger`) est une opération **destructrice** ; ne jamais l'utiliser comme test improvisé.

## 28. Bibliothèque d'incidents — preuves et scénarios à compléter

Le deuxième assistant n'a pas retrouvé de tickets complets avec symptôme, cause et correction. Gardons cette distinction plutôt que de fabriquer des « incidents BNP résolus ».

| Sujet cité / scénario | Ce qui est documenté | Ce qui reste inconnu | Première commande |
|---|---|---|---|
| [H partiel] Diagnostic initial RHEL | Accès distant, `uptime`, `top` cités | Incident et cause racine | `uptime; top -b -n1 | head` |
| [C] `/var` saturé | Séquence de dépannage suggérée par ancien assistant | Exécution/résultat non confirmés | `df -hT /var; df -i /var; lsof +L1` |
| [C] Test port TCP 443 | Commandes proposées dans échange | Service, résultat inconnus | `ip route get <IP>; nc -zvw3 <IP> 443` |
| [H partiel] Clavier console iDRAC | Sujet et commandes de keymap mentionnés | Résolution finale | `localectl status` |
| [H mention] Xstart / package / flux | Sujet seulement | OS, erreur, fix | Collecter erreur et contexte, ne pas inventer |
| [H activité] DNS / NTP via Ansible | Automatisations documentées | Diff et logs d'exécution | `getent`, `dig`, `resolvectl`/`nmcli` |
| [H activité] Leapp / LCM | Processus documenté | Inhibitor et état exact des hôtes | rapports dans `/var/log/leapp` |
| [H activité] Veritas / SAN | BUILD et MCO mentionnés | État cluster / commandes originales | `hastatus -sum` si outil présent |

**Modèle à renseigner en situation réelle chez LFM** : `symptôme exact → hôte / heure / périmètre → sortie RO → hypothèse → preuve → correctif approuvé → résultat → rollback si applicable → ticket`. Les nouveaux cas viendront enrichir une **V4** expurgée des données internes.

## 29. Bash / commandes transverses — quatre recettes de production

### 29.1. Comparer deux fichiers de configuration (avant/après)

```bash
sudo install -d -m 700 /root/backup                       # [M] dossier restreint
sudo cp -a /etc/ssh/sshd_config /root/backup/sshd_config.pre  # [M] sauvegarde
sudo diff -u /root/backup/sshd_config.pre /etc/ssh/sshd_config # [RO] après changement
sudo sshd -t                                               # [RO] valide syntaxe
sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords) '
```

**Ne pas ouvrir/écraser un fichier PAM/SSH sans console de secours et politique de changement.** `sshd -T` présente la config générale ; les `Match` peuvent nécessiter `sshd -T -C user=...,addr=...,host=...`.

### 29.2. Extraire des erreurs de journaux avec horodatage

```bash
journalctl -u <SERVICE> --since '1 hour ago' -o short-iso --no-pager \
  | grep -nEi 'failed|error|denied|timeout|oom'
```

Le grep ne remplace pas la lecture du contexte. Avec `journalctl`, filtrer d'abord une fenêtre temporelle et le service pertinent.

### 29.3. `awk` : repérer les filesystem au-dessus d'un seuil

```bash
df -P | awk 'NR>1 { sub(/%/, "", $5); if ($5+0 >= 85) print $5 "%", $6 }'
# [RO] parsing best-effort de df ; utiliser des APIs/outils dédiés pour scripts robustes.
```

### 29.4. Boucle Bash pour faire plusieurs contrôles en lecture seule

```bash
#!/usr/bin/env bash
set -u
for svc in sshd chronyd rudder-agent; do
  if systemctl list-unit-files --type=service | grep -qE "^${svc}\.service"; then
    printf '%-20s %s\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null)"
  else
    printf '%-20s %s\n' "$svc" 'non présent dans systemd'
  fi
done
```

**Attention** : `sshd` s'appelle souvent `ssh` sur Ubuntu et `chronyd` peut s'appeler `chrony` : ce script démontre volontairement pourquoi un script multi-distribution doit **détecter la plateforme** et ne pas présumer les unités.

## 30. Priorités LFM : utiliser le référentiel sans se disperser

| Quand ? | Priorité | Lecture du carnet |
|---|---|---|
| Premier accès | Identité OS, périmètre, sécurité, accès secours | §0–2, §18 |
| Rudder KO | Agent→serveur, ports, policy server, génération | §7 |
| Audit CIS | Profil/cible/FAIL/preuve/exception | §8 et §22 |
| Nouvelle remédiation | YAML/regex/foreach, Audit → pilote → test OS | §9, §14, §22 |
| Incident DNS/NTP | Source effective, flux et chrony | §3, §24 |
| Incident stockage | VMDK nouveau ou agrandi ? PV entier/partition ? SAN ? | §4A, §4B, §25 |
| Patching RHEL | Content View, errata, LCM, postchecks | §12, §20, §21 |
| Automation | Périmètre, syntax-check, check/diff, secrets | §13, §23 |
| Problème firmware | Drivers/BIOS/console OOB, dépendances | §14B, §26 |
| Incident cluster | HA, ressources, multipath, validation applicative | §25 |

## 31. Sources et traçabilité de l'enrichissement V3

- **Source historique fournie** : `BNP Paribas — Capitalisation technique Linux L3 / SysOps`, fichier transmis le 2 novembre 2026. Sources sous-jacentes rapportées : CV et mémoires du deuxième ChatGPT ; historique complet et tickets non accessibles ici. **Ces affirmations ne constituent pas une validation indépendante des activités personnelles.**
- Red Hat, **RHEL 9 / LVM** : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_logical_volumes/basic-logical-volume-management_configuring-and-managing-logical-volumes
- Red Hat, **RHEL 9 / XFS** : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_file_systems/increasing-the-size-of-an-xfs-file-system_managing-file-systems
- Red Hat, **RHEL 8→9 / Leapp inhibitors** : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/upgrading_from_rhel_8_to_rhel_9/troubleshooting_upgrading-from-rhel-8-to-rhel-9
- Red Hat, **RHEL / Authselect custom** : https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect_configuring-authentication-and-authorization-in-rhel
- Red Hat, **Satellite / Content Views et Lifecycle** : https://docs.redhat.com/en/documentation/red_hat_satellite/6.19/html/managing_content/managing-content-views-and-content-view-environments
- Red Hat, **Satellite / Hammer CLI** : https://docs.redhat.com/en/documentation/red_hat_satellite/6.19/html/hammer_reference/hammer-content-view
- Ansible Core, **Check / Diff** : https://docs.ansible.com/projects/ansible-core/2.22/playbook_guide/playbooks_checkmode.html
- Dell, **RACADM iDRAC9 CLI** : https://downloads.dell.com/topicspdf/idrac_v4-22_cliguide_en-us.pdf

**Périmètre** : support de préparation Linux L3/SysSecOps, **pas** une procédure d'exploitation LFM validée. Aucune IP, URL interne, donnée client, secret, nom de serveur BNP ni nom de collection propriétaire n'est nécessaire à ce référentiel.
