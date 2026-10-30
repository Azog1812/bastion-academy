# Enchaîner les failles

Les défis des niveaux précédents isolaient une faille à la fois. Les vraies
intrusions se font rarement avec une seule faille critique : elles
**enchaînent** des faiblesses que chacun, pris seul, jugeait mineures.

## Un exemple de chaîne

1. Un message d'erreur indique où sont rangés les fichiers sur le serveur.
   *Seul : faible gravité, une simple fuite d'information.*
2. Un paramètre de téléchargement permet une traversée de répertoires, mais
   seulement en lecture. *Seul : gravité moyenne, « on ne lit que des fichiers ».*
3. Un fichier de configuration lisible contient le secret qui signe les jetons
   de session. *Seul : invisible depuis l'extérieur.*
4. Avec ce secret, on fabrique un jeton administrateur valide.

Résultat : **prise de contrôle complète**, à partir de trois constats qu'un
rapport superficiel aurait classés « faible » ou « moyen ». Le lab de ce module
reproduit exactement cette chaîne.

## Penser en graphe

L'auditeur ne se demande pas seulement « cette faille est-elle grave ? », mais
« **qu'est-ce qu'elle me donne, et à quoi ça me donne accès ensuite ?** ».
Chaque découverte ouvre des portes :

| J'obtiens… | …ce qui me permet de |
|---|---|
| Un chemin interne | Viser précisément une traversée de répertoires |
| Un fichier de configuration | Lire des secrets : base de données, signature, API |
| Un secret de signature | Forger des jetons, donc des identités |
| Un compte de service | Me déplacer vers d'autres machines (niveau 3, Active Directory) |

C'est aussi ainsi que pensent les outils comme BloodHound pour Active
Directory : un graphe de chemins vers « administrateur du domaine ».

## Ce que la défense en retient

Une chaîne se casse à **n'importe quel maillon**. Bastion en coupe plusieurs
par conception :

- les erreurs ne révèlent rien (invariant 7) ;
- les fichiers ne sont servis qu'avec une racine fixe, sans fichiers cachés ;
- les secrets ne sont **pas** dans des fichiers que l'application sert : ils
  viennent de fichiers montés en lecture seule (`*_FILE`), hors de toute
  arborescence web, et le code est en lecture seule pour le processus ;
- l'algorithme des jetons est imposé par le serveur, et le secret fait 256 bits.

C'est la défense en profondeur vue du côté de l'attaquant : il suffit d'une
seule barrière solide sur le chemin pour que la chaîne entière tombe.

## À retenir

- Des faiblesses « mineures » enchaînées font une compromission totale.
- Pour chaque découverte : qu'est-ce que ça me donne, et ensuite ?
- Un rapport doit présenter la chaîne, pas seulement les maillons.
- Côté défense, casser un seul maillon suffit : d'où la défense en profondeur.
