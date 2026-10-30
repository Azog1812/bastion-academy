# Réussir un examen pratique

Les candidats qui échouent à un examen pratique ne manquent pas toujours de
connaissances. Le plus souvent, ils manquent de **méthode** : ils restent six
heures bloqués sur une machine, oublient de capturer une preuve, ou rendent un
rapport bâclé à 4 heures du matin. Cette dernière leçon traite de ce qui se
passe *autour* de la technique.

## Avant : préparer son terrain

- **Un environnement prêt** : machine d'attaque à jour, outils testés,
  dictionnaires présents, captures d'écran faciles.
- **Des notes réutilisables** : pour chaque technique, la commande qui marche,
  les pièges, ce qu'il faut vérifier. Pendant l'examen, on ne cherche pas, on
  relit ses notes.
- **Un modèle de rapport** déjà rempli : page de garde, méthodologie, une
  section par machine avec les cases « preuve » vides.
- **Des entraînements chronométrés** : des machines que tu ne connais pas, en
  temps limité, sans solution.

## Pendant : la boucle d'énumération

Quand on bloque, la réponse est presque toujours : **on n'a pas assez énuméré**.

1. Tous les ports, TCP **et** UDP, pas seulement les mille premiers.
2. Pour chaque service : version, contenu, identifiants par défaut, failles connues.
3. Chaque information trouvée (un nom d'utilisateur, un chemin, un mot de passe)
   **relance** la boucle sur tous les autres services : la réutilisation des
   identifiants est la faille la plus fréquente.
4. Après l'accès initial, on recommence en local : utilisateurs, droits `sudo`,
   SUID, tâches planifiées, services, fichiers de configuration, privilèges
   Windows (niveau 3).

## Gérer le temps

- Fixe une **limite par machine** (par exemple deux heures sans progrès) et passe
  à la suivante : un regard neuf débloque souvent.
- Sur un examen de 24 heures, **dors** quelques heures. La fatigue fait rater
  l'évidence.
- Fais le calcul des points dès le début : quelles machines te donnent les 70
  points, et dans quel ordre ?

## Les preuves, au fil de l'eau

Chaque étape se documente **au moment où elle se produit** : la commande
exacte, sa sortie, une capture d'écran qui montre le fichier preuve **et**
l'adresse de la machine. Une étape qu'on ne peut pas reproduire dans le rapport
ne compte pas. C'est la même exigence qu'un vrai rapport de test d'intrusion
(niveau 4) : un développeur doit pouvoir rejouer le constat.

## Le règlement d'examen est un périmètre

Chaque examen a ses règles : outils interdits (certains outils d'exploitation
automatique, souvent l'IA générative), surveillance par webcam, interdiction de
partager. Les enfreindre, c'est l'échec et parfois l'exclusion définitive. C'est
le même réflexe qu'en mission : **on reste dans le cadre écrit**.

## Après : le rapport

Relis-le à tête reposée : chaque machine, chaque étape, chaque preuve. Un
rapport clair qui reconstitue l'attaque compte autant que l'attaque.

## Et après la certification

Une certification est un point de départ. Ce qui fait un expert, c'est la
pratique continue (CTF, labs, programmes de *bug bounty* dans leur périmètre),
la veille (CVE, techniques nouvelles, règles de détection), et la capacité
à **expliquer** : à un développeur comment corriger, à une direction pourquoi
c'est urgent. C'est exactement ce que Bastion Academy t'a fait faire à chaque
niveau : casser, puis corriger, puis expliquer pourquoi.

## À retenir

- Préparer : environnement, notes, modèle de rapport, entraînements chronométrés.
- Bloqué ? Énumérer encore ; chaque information relance la boucle.
- Limiter le temps par machine, dormir, viser les points nécessaires.
- Documenter chaque preuve sur le moment ; respecter le règlement d'examen comme un périmètre.
