# Linux : l'élévation de privilèges

Un attaquant obtient rarement `root` du premier coup. Le scénario classique :
une faille web lui donne un shell sous `www-data`, puis il cherche **comment
passer root** sur la machine. C'est l'élévation de privilèges (*privilege
escalation*, ou *privesc*), une épreuve centrale de toutes les certifications
offensives.

## La méthode : énumérer avant d'attaquer

Un attaquant méthodique fait d'abord l'inventaire de ce que son utilisateur
peut faire :

```bash
id; hostname; uname -a                  # qui, où, quel noyau
sudo -l                                  # que puis-je lancer avec sudo ?
find / -perm -4000 -type f 2>/dev/null   # binaires SUID
getcap -r / 2>/dev/null                  # binaires avec des capabilities
ls -la /etc/cron* ; cat /etc/crontab     # tâches planifiées
ps aux                                   # processus, surtout ceux de root
```

## Les quatre vecteurs les plus fréquents

### 1. `sudo` trop généreux

```text
$ sudo -l
User www-data may run the following commands:
    (root) NOPASSWD: /usr/bin/find
```

`find` sait exécuter des commandes (`-exec`). L'autoriser en root, c'est donner
un shell root. Le projet **GTFOBins** recense des centaines de programmes
ordinaires (`find`, `vim`, `less`, `tar`, `python`…) qui permettent de sortir
de leur rôle. Règle : **jamais** d'éditeur, d'interpréteur ou d'outil
généraliste dans `sudoers`.

### 2. Un binaire SUID détourné

Même logique : un binaire SUID root qui peut lancer une commande ou écrire un
fichier arbitraire donne root. La liste de la leçon précédente se compare à ce
qu'une installation standard contient ; tout binaire inhabituel est suspect.

### 3. Une tâche planifiée modifiable

```text
* * * * * root /opt/scripts/backup.sh
-rwxrwxrwx 1 root root  120 /opt/scripts/backup.sh
```

Le script tourne en root chaque minute **et** tout le monde peut le modifier.
L'attaquant y ajoute une ligne : une minute plus tard, elle s'exécute en root.
Même problème si le script appelle un programme sans chemin absolu dans un
`PATH` modifiable.

### 4. Les capabilities

Linux découpe les pouvoirs de root en *capabilities* (`CAP_NET_BIND_SERVICE`
pour écouter sous le port 1024, `CAP_SYS_ADMIN` pour… presque tout). Un
`python3` doté de `cap_setuid` peut changer son UID en 0. `getcap -r /` les
révèle.

### Et le noyau ?

Un noyau non mis à jour peut avoir une faille locale connue (Dirty COW, Dirty
Pipe). C'est le vecteur le plus brutal, et la raison pour laquelle on **patche**
même les machines « internes ».

## Le point de vue du défenseur

| Vecteur | Défense |
|---|---|
| `sudo` | Liste blanche minimale de commandes précises, jamais d'interpréteur ; journaliser `sudo` |
| SUID | Inventaire régulier, retirer le bit des binaires inutiles (`chmod u-s`), monter les partitions de données en `nosuid` |
| Cron | Scripts appartenant à root et non modifiables par d'autres (`755` au plus), chemins absolus |
| Capabilities | N'en accorder aucune par défaut |
| Noyau | Mises à jour automatiques de sécurité |

Et surtout : **réduire ce que l'attaquant trouve en arrivant**. Le conteneur de
Bastion part de l'image *distroless* : pas de shell, pas de `sudo`, pas de
`find`, pas de cron, aucun binaire SUID. Le premier réflexe de l'attaquant,
`/bin/sh`, échoue. La CI le vérifie à chaque build (`container.yml`) :

```bash
if docker run --rm --entrypoint /bin/sh "$LOCAL_IMAGE" -c true 2>/dev/null; then
  echo "::error::a shell exists in the runtime image"; exit 1
fi
```

## À retenir

- L'élévation de privilèges commence par une énumération méthodique.
- `sudo`, SUID, cron modifiable, capabilities : quatre portes à vérifier.
- GTFOBins montre que des outils banals deviennent des armes avec trop de droits.
- La meilleure défense est un système qui ne contient que le strict nécessaire.
