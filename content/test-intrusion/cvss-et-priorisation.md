# Évaluer la gravité : CVSS et priorisation

Un rapport qui liste quarante failles sans dire lesquelles corriger d'abord est
inutilisable. Il faut une échelle commune : le **CVSS** (*Common Vulnerability
Scoring System*), maintenu par le FIRST. Sa version 4.0 est publiée depuis
novembre 2023.

## Les métriques de base

Le score de base décrit la faille elle-même, indépendamment de l'environnement :

| Métrique | Question | Valeurs |
|---|---|---|
| **AV**, vecteur d'attaque | D'où peut-on attaquer ? | Réseau, adjacent, local, physique |
| **AC**, complexité | Faut-il contourner une protection, réussir une course ? | Faible, élevée |
| **AT**, prérequis d'attaque | La faille dépend-elle d'une condition de déploiement ? | Aucun, présents |
| **PR**, privilèges requis | Faut-il un compte ? | Aucun, faibles, élevés |
| **UI**, interaction | Une victime doit-elle agir ? | Aucune, passive, active |
| **VC / VI / VA** | Impact sur la confidentialité, l'intégrité, la disponibilité du système vulnérable | Élevé, faible, aucun |
| **SC / SI / SA** | Même chose pour les **systèmes suivants** | Élevé, faible, aucun |

La séparation entre le système vulnérable et les systèmes suivants est une
nouveauté de la v4 : une XSS touche peu le serveur, mais beaucoup le navigateur
des victimes.

Le résultat s'écrit sous forme de **vecteur**, lisible et vérifiable :

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

Et le score, de 0 à 10, donne une gravité : **faible** de 0,1 à 3,9,
**moyenne** de 4,0 à 6,9, **élevée** de 7,0 à 8,9, **critique** de 9,0 à 10.

## Au-delà du score de base

- Les métriques de **menace** tiennent compte de l'exploitation réelle : un
  code d'exploitation public augmente l'urgence.
- Les métriques **environnementales** adaptent le score au contexte du client :
  une faille sur un serveur sans données sensibles et isolé pèse moins.

## Le score ne fait pas la priorité

Le CVSS évalue une faille **isolée**. Deux corrections s'imposent en pratique :

- une **chaîne** (leçon précédente) peut transformer trois failles « moyennes »
  en compromission totale : le rapport doit le dire et prioriser le maillon le
  moins coûteux à casser ;
- le **coût de correction** compte : une ligne de configuration qui supprime
  un risque élevé passe avant une refonte qui supprime un risque moyen.

## À retenir

- CVSS 4.0 : un vecteur lisible, un score de 0 à 10, quatre niveaux de gravité.
- Vecteur d'attaque, complexité, privilèges, interaction, impacts sur le système et au-delà.
- Menace et environnement ajustent le score de base au monde réel.
- Prioriser selon la chaîne et le coût de correction, pas seulement le score.
