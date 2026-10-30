# Forensique : les premiers gestes

La **forensique** (ou investigation numérique) cherche à établir ce qui s'est
passé, de façon assez rigoureuse pour que les conclusions tiennent face à une
contestation, parfois devant un juge. Les premiers gestes décident de ce qu'il
restera à analyser.

## L'ordre de volatilité

Certaines preuves disparaissent en quelques secondes, d'autres durent des
années. La RFC 3227 recommande de collecter **du plus volatil au moins volatil** :

1. registres et cache du processeur ;
2. table de routage, cache ARP, liste des processus, **mémoire vive** ;
3. systèmes de fichiers temporaires ;
4. disque ;
5. journaux distants et données de supervision ;
6. configuration physique, topologie du réseau ;
7. archives.

Concrètement : une copie de la mémoire vive **avant** d'éteindre quoi que ce soit.

## Préserver la preuve

- **Travailler sur une copie**, jamais sur l'original.
- **Calculer une empreinte** (SHA-256) de chaque copie au moment de la collecte :
  elle prouvera plus tard que rien n'a changé.
- Tenir une **chaîne de traçabilité** (*chain of custody*) : qui a collecté
  quoi, quand, comment, et entre quelles mains la preuve est passée.
- Noter les heures **en UTC**, et le décalage de l'horloge de chaque machine.

## Reconstituer la chronologie

L'essentiel du travail est une **chronologie** : fusionner les journaux du
serveur web, de l'application, du système, du pare-feu, et les dates des
fichiers, sur un même axe de temps. C'est là que la journalisation de la
première leçon (UTC, identifiants de corrélation, centralisation) rend la
mission possible, ou non.

## Et dans un conteneur ?

Les conteneurs changent la donne :

- un conteneur supprimé emporte son système de fichiers : avant de le
  supprimer, `docker inspect`, `docker logs`, et `docker export` pour en
  garder une copie ;
- `docker diff` liste les fichiers modifiés depuis le démarrage. Sur un
  conteneur **en lecture seule**, comme ceux de Bastion et de ses labs, elle
  est **vide** : l'attaquant n'a pu modifier ni le code ni le système.
- Les seules zones inscriptibles sont alors les volumes et les `tmpfs` (comme
  `/tmp`). Un `tmpfs` vit **en mémoire** : il n'apparaît ni dans `docker diff`,
  ni dans `docker export`, ni même dans `docker cp`, et il disparaît à l'arrêt
  du conteneur. C'est l'ordre de volatilité appliqué aux conteneurs : son
  contenu se collecte **en premier**, depuis l'intérieur du conteneur en
  marche (`docker exec … tar`), avant tout arrêt.

Côté Bastion, `node dist/cli.js verify-audit` vérifie la chaîne HMAC du journal
d'audit : si un attaquant a modifié ou supprimé des entrées, la commande
indique la première entrée invalide. Un journal dont on peut **prouver**
l'intégrité vaut beaucoup plus qu'un journal qu'on espère intact.

## À retenir

- Du plus volatil au moins volatil : la mémoire avant le disque.
- Copier, hacher, tracer la chaîne de traçabilité.
- La chronologie est le cœur de l'enquête ; elle dépend de la qualité des journaux.
- Conteneurs : exporter avant de supprimer ; lecture seule = enquête simplifiée.
