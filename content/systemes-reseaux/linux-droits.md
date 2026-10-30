# Linux : utilisateurs, groupes et permissions

La quasi-totalité des serveurs web, des conteneurs et des équipements réseau
tournent sous Linux. Son modèle de sécurité tient en une idée : **chaque
processus agit au nom d'un utilisateur**, et le noyau vérifie ses droits à
chaque accès à un fichier.

## Qui suis-je ?

```bash
id              # mon UID, mon GID principal et mes groupes
whoami
cat /etc/passwd | head -5    # comptes : nom:x:UID:GID:description:home:shell
```

- L'**UID 0**, c'est `root` : le noyau ne lui applique presque aucune
  vérification de permissions. Compromettre un processus root, c'est
  compromettre la machine.
- Les comptes de service (`www-data`, `postgres`, `nobody`…) ont un UID non
  nul et souvent un shell `/usr/sbin/nologin`.
- Les empreintes des mots de passe sont dans `/etc/shadow`, lisible par root
  seulement.

## Lire une permission

```bash
ls -l /etc/passwd /etc/shadow
# -rw-r--r-- 1 root root   2734 ... /etc/passwd
# -rw-r----- 1 root shadow 1460 ... /etc/shadow
```

| Bloc | Pour qui | Lettres |
|---|---|---|
| `rw-` | le **propriétaire** (`root`) | lire, écrire |
| `r--` | le **groupe** (`shadow`) | lire |
| `---` | **tous les autres** | rien |

Sur un fichier, `r` = lire, `w` = modifier, `x` = exécuter. Sur un
**répertoire**, `x` permet de le traverser et `w` permet de créer ou supprimer
des fichiers dedans, **même ceux qui ne t'appartiennent pas**. C'est un piège
classique.

En octal, `r`=4, `w`=2, `x`=1 : `rw-r-----` s'écrit `640`, et `chmod 600 cle.pem`
rend une clé privée lisible par son seul propriétaire.

## Les bits spéciaux

| Bit | Effet | Exemple légitime | Risque |
|---|---|---|---|
| **SUID** (`s` chez le propriétaire) | Le programme s'exécute avec les droits de son **propriétaire**, pas de l'appelant | `/usr/bin/passwd` (doit écrire dans `/etc/shadow`) | Un binaire SUID root mal choisi = élévation de privilèges |
| **SGID** | Idem avec le groupe | Répertoires partagés | Moins grave, même logique |
| **Sticky** (`t`) | Dans un répertoire, seul le propriétaire d'un fichier peut le supprimer | `/tmp` (`drwxrwxrwt`) | Sans lui, n'importe qui pourrait effacer les fichiers des autres |

```bash
ls -l /usr/bin/passwd       # -rwsr-xr-x : le « s » est le bit SUID
ls -ld /tmp                 # drwxrwxrwt : le « t » est le sticky bit
```

## Le principe du moindre privilège, appliqué

Un service web n'a besoin ni de lire `/etc/shadow`, ni d'écrire dans son propre
code. Voici comment l'image Docker de Bastion s'organise (`Dockerfile`) :

```dockerfile
COPY --from=build --chown=0:0 --chmod=0555 /out/dist ./dist
COPY --chown=0:0 --chmod=0555 content ./content
USER 65532:65532
```

- Le code et le contenu appartiennent à **root** et sont en `0555` (lecture et
  exécution pour tous, écriture pour personne).
- Le processus tourne sous l'UID **65532**, qui n'est pas propriétaire de ces
  fichiers.

Conséquence : même si un attaquant prenait le contrôle du processus Node, il ne
pourrait **pas modifier le code** pour y installer une porte dérobée. Seul
`/data`, la base de données, appartient à l'utilisateur 65532.

## À toi de jouer

Sur ta machine Linux (ou WSL), trouve les fichiers que **tout le monde** peut
modifier en dehors de `/proc` et `/tmp` :

```bash
find / -xdev -type f -perm -o+w 2>/dev/null | grep -v -e ^/proc -e ^/tmp | head
```

Puis liste les binaires SUID :

```bash
find / -xdev -perm -4000 -type f 2>/dev/null
```

Garde cette seconde liste : la prochaine leçon explique pourquoi c'est la
première commande d'un attaquant qui vient d'obtenir un accès limité.

## À retenir

- Le noyau vérifie l'UID du processus à chaque accès : tout part de là.
- `w` sur un répertoire permet de supprimer les fichiers des autres.
- SUID exécute avec les droits du propriétaire : à surveiller de près.
- Un service ne doit pas pouvoir modifier son propre code.
