# Détecter les attaques contre Active Directory

Un expert ne sait pas seulement mener une attaque : il sait aussi quelles traces
elle laisse, et comment la repérer. Les attaques AD les plus discrètes passent
par des opérations **normales** (demander un ticket, répliquer l'annuaire) : la
détection repose donc sur le **contexte**, pas sur une signature.

## Où regarder

Tout commence par l'audit des contrôleurs de domaine. Sans la bonne stratégie
d'audit, ces événements n'existent tout simplement pas :

| Événement | Signification | Sous-catégorie d'audit à activer |
|---|---|---|
| **4768** | Demande de TGT | Service d'authentification Kerberos |
| **4769** | Demande de ticket de service | Opérations de ticket du service Kerberos |
| **4662** | Opération sur un objet de l'annuaire | Accès au service d'annuaire |
| **4886 / 4887** | Demande et émission de certificat (AD CS) | Services de certificats |

## Kerberoasting : l'événement 4769

Chaque demande de ticket de service produit un 4769 sur le contrôleur de
domaine, avec le compte demandeur, le service visé et le **type de chiffrement**
du ticket. Les outils de Kerberoasting demandent souvent un ticket **RC4**
(`0x17`) : il se casse bien plus vite qu'un ticket AES (`0x11`, `0x12`).

Mais une règle « RC4 = alerte » noie le SOC :

- de vieilles applications ne parlent que RC4, et tous leurs utilisateurs
  déclenchent l'alerte, chaque jour ;
- les comptes **machine** (dont le nom finit par `$`) ont des mots de passe
  aléatoires de 120 caractères, impossibles à casser : leurs tickets RC4 ne sont
  pas une cible de Kerberoasting.

Le vrai signal est **comportemental** : un même compte qui demande des tickets
RC4 pour **plusieurs comptes de service différents** en peu de temps. Un
utilisateur normal parle à une poignée de services ; un attaquant les veut tous.
Et un attaquant patient espace ses demandes : la fenêtre de temps compte autant
que le seuil.

## Le leurre : un compte de service qui n'existe pour rien

Crée un compte de service avec un SPN, un nom alléchant (`svc_sauvegarde_sql`),
un mot de passe immense, et **aucun usage réel**. Personne n'a jamais besoin de
ticket pour lui. Un seul 4769 qui le vise est donc, par construction, une alerte
fiable : zéro faux positif. Les leurres (*honeytokens*) sont l'une des meilleures
détections qui existent, précisément parce que le trafic légitime est nul.

## DCSync, AD CS et délégation

- **DCSync** : un 4662 avec les GUID des droits de réplication
  (`1131f6aa-…`, `1131f6ad-…`) dont le compte n'est **pas** un contrôleur de
  domaine. Côté réseau, une requête de réplication (DRSUAPI) qui part d'un poste
  de travail.
- **AD CS** : un certificat émis (4887) dont le **sujet** diffère du demandeur,
  surtout sur un modèle d'authentification : c'est la signature d'ESC1.
- **Délégation** : toute modification de
  `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) ou l'apparition d'un nouveau
  compte machine créé par un simple utilisateur.

## Ce que l'expert retient

L'attaquant expert lit les mêmes listes. Il demande des tickets AES pour passer
sous les règles RC4, il espace ses requêtes, il évite les comptes trop beaux pour
être vrais. La détection n'est jamais terminée : chaque règle doit être
**testée** contre une attaque rejouée, et réévaluée quand les outils évoluent.

## À retenir

- Pas de 4769, 4662 ou 4887 sans la stratégie d'audit qui les active.
- Kerberoasting : grouper par compte demandeur, compter les **services distincts** en RC4, exclure les comptes machine, choisir une fenêtre assez large.
- Un compte leurre avec SPN donne une alerte sans faux positif.
- DCSync = droits de réplication utilisés par un non-contrôleur ; ESC1 = sujet du certificat différent du demandeur.
