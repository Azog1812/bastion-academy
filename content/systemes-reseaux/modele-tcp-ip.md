# Le modèle TCP/IP, vu par un attaquant

Au niveau 1, tu as lu des requêtes HTTP. Mais HTTP voyage **dans** d'autres
protocoles, empilés comme des enveloppes. Chaque couche a ses propres attaques,
et un défenseur doit savoir à quelle couche il se place.

## Les quatre couches

| Couche TCP/IP | Rôle | Exemples | Attaques typiques |
|---|---|---|---|
| **Application** | Ce que les programmes se disent | HTTP, DNS, SSH, SMB, LDAP | Injection, vol de session, mauvaise configuration |
| **Transport** | Relier deux *programmes* (ports) | TCP, UDP | Scan de ports, SYN flood |
| **Internet** | Acheminer entre *machines* (adresses IP) | IPv4, IPv6, ICMP | Usurpation d'adresse, routage détourné |
| **Accès réseau** | Transmettre sur le support local | Ethernet, Wi-Fi, ARP | Empoisonnement ARP, faux point d'accès Wi-Fi |

On parle aussi du modèle **OSI** à 7 couches : retiens surtout que « couche 7 »
désigne l'application et « couche 3 » IP. Ce vocabulaire revient dans tous les
pare-feu et toutes les certifications.

## Adresse IP et port : qui, et quel programme

Une adresse IP désigne une **machine** (ou plutôt une interface réseau). Un
**port** (0 à 65535) désigne un **programme** sur cette machine. Le couple
`IP:port` est une *socket*.

Deux adresses à connaître par cœur :

- `127.0.0.1` (*loopback*) : la machine elle-même. Un service qui écoute
  **uniquement** sur cette adresse est injoignable depuis le réseau.
- `0.0.0.0` : « toutes les interfaces ». Un service qui écoute ici est
  joignable par **toute machine qui peut atteindre la tienne**.

C'est pour cela que le `docker-compose.yml` de Bastion publie le port ainsi :

```yaml
ports:
  - "127.0.0.1:3000:3000" # loopback only: not exposed to the LAN
```

Sans le `127.0.0.1:`, Docker publierait le port sur toutes les interfaces, et
le café dans lequel tu travailles pourrait joindre ton instance.

## TCP : la poignée de main

TCP garantit que les données arrivent, dans l'ordre. Avant tout échange, les
deux machines se synchronisent en trois paquets :

```text
client                        serveur
  | --- SYN ------------------->  |   « je veux parler, voici mon numéro de séquence »
  | <-- SYN-ACK ----------------  |   « d'accord, voici le mien »
  | --- ACK ------------------->  |   « c'est parti »
```

Si le port est fermé, le serveur répond `RST` (reset). Si un pare-feu filtre le
port, il n'y a souvent **aucune réponse**. Ces trois comportements (ouvert,
fermé, filtré) sont exactement ce qu'un scanner de ports observe.

**UDP**, lui, n'a ni poignée de main ni garantie : c'est plus rapide (DNS,
streaming, jeux), mais un paquet UDP est trivial à envoyer avec une adresse
source falsifiée. C'est la base des attaques par **amplification** : une petite
requête DNS falsifiée provoque une grosse réponse envoyée à la victime.

## À toi de jouer : qui écoute sur ta machine ?

Lance Bastion en local, puis liste les sockets en écoute :

```bash
# Linux
ss -tlnp
# macOS
lsof -iTCP -sTCP:LISTEN -n -P
# Windows (PowerShell)
Get-NetTCPConnection -State Listen | Sort-Object LocalPort
```

Repère la ligne du port 3000. L'adresse locale est-elle `127.0.0.1` ou
`0.0.0.0` ? Dans le second cas, ta machine expose Bastion à ton réseau local.
Relance avec `HOST=127.0.0.1` et vérifie que la ligne change.

Fais le même exercice pour tout le reste de la liste : chaque ligne en
`0.0.0.0` est une porte d'entrée. La **réduction de la surface d'attaque**
commence ici, par la question « ce service doit-il vraiment être joignable ? ».

## À retenir

- IP désigne la machine, le port désigne le programme.
- `127.0.0.1` reste local, `0.0.0.0` s'ouvre à tout le réseau.
- Un port répond ouvert (SYN-ACK), fermé (RST) ou filtré (silence).
- Chaque couche a ses attaques : savoir où l'on se place, c'est savoir quelle
  défense choisir.
