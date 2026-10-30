# SIEM, corrélation et faux positifs

Une entreprise de taille moyenne produit des millions d'événements par jour.
Personne ne les lit. Un **SIEM** (*Security Information and Event Management*)
les collecte, les normalise, et lève des **alertes** quand une règle de
détection correspond. Ce sont ces alertes que traite un analyste du **SOC**.

## Les étapes

1. **Collecte** : agents sur les postes, syslog, API des services cloud.
2. **Normalisation** : chaque source nomme ses champs à sa façon. Le SIEM les
   ramène à un schéma commun : `src_ip` doit vouloir dire la même chose pour le
   pare-feu et pour le serveur web.
3. **Détection** : des règles s'exécutent sur le flux.
4. **Corrélation** : relier des événements de sources différentes. Une
   connexion VPN depuis un pays inhabituel, puis une création de compte, puis
   un accès à la base de données : chacun est banal, la suite ne l'est pas.

## Deux familles de règles

| Famille | Exemple | Force | Faiblesse |
|---|---|---|---|
| **Signature** | « la requête contient `UNION SELECT` » | Précise, explicable | Contournable (encodage, casse, synonymes) |
| **Comportement** | « plus de 10 comptes différents en échec depuis la même adresse en 10 minutes » | Résiste aux variantes | Demande de bien choisir les seuils |

La pulvérisation de mots de passe que tu as analysée au niveau 3 ne se voit
qu'avec une règle de comportement : chaque échec, pris seul, est banal.

## Faux positifs, faux négatifs

| | Il y a une attaque | Il n'y en a pas |
|---|---|---|
| **Alerte** | Vrai positif | **Faux positif** : du temps d'analyste perdu |
| **Pas d'alerte** | **Faux négatif** : l'attaque passe | Vrai négatif |

Les deux erreurs coûtent cher. Trop de faux positifs, et les analystes
finissent par ignorer les alertes : c'est la **fatigue d'alerte**, qui a joué un
rôle dans de nombreuses intrusions pourtant « détectées ». Trop de faux
négatifs, et le SOC ne sert à rien. On parle de **précision** (la part des
alertes qui sont de vraies attaques) et de **rappel** (la part des attaques qui
déclenchent une alerte).

Les défis de ce parcours exigent les deux à 100 % : **toutes** les attaques
détectées, **aucune** fausse alerte.

## Cartographier avec MITRE ATT&CK

**MITRE ATT&CK** est la référence commune pour nommer les techniques des
attaquants : *T1110.003 Password Spraying*, *T1190 Exploit Public-Facing
Application*, *T1059.001 PowerShell*, *T1218 System Binary Proxy Execution*.
Rattacher chaque règle à une technique permet de mesurer sa **couverture** :
quelles techniques sait-on détecter, et lesquelles passent inaperçues ?

## À retenir

- Le SIEM collecte, normalise, détecte et corrèle ; l'analyste décide.
- Signature : précise mais contournable. Comportement : robuste mais à calibrer.
- Faux positifs et faux négatifs coûtent tous les deux : viser précision **et** rappel.
- ATT&CK donne un vocabulaire commun et une mesure de la couverture.
