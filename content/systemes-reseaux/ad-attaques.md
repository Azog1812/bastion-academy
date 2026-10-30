# Les attaques classiques contre Active Directory

Ces attaques reviennent dans presque tous les tests d'intrusion internes et
dans les examens de certification offensive. Aucune n'exploite un bug : elles
exploitent des **choix de configuration** et le fonctionnement normal de
Kerberos et NTLM. C'est pour cela qu'elles marchent encore.

> Ces techniques ne se pratiquent que dans un laboratoire qui t'appartient
> (des machines virtuelles isolées, sans accès au réseau de ton entreprise).
> Les labs de Bastion Academy (v5) fourniront un environnement dédié.

## Kerberoasting

Rappel : n'importe quel utilisateur du domaine peut demander un ticket de
service, chiffré avec la clé du **compte de service**, elle-même dérivée de son
mot de passe.

1. L'attaquant, avec un simple compte, liste les comptes de service (ceux qui
   ont un SPN).
2. Il demande un ticket pour chacun : c'est une opération normale, rien n'est
   bloqué.
3. Il emporte les tickets et teste des mots de passe **hors ligne**, sans
   limite de vitesse ni verrouillage.

Les comptes de service ont souvent un mot de passe humain, ancien et jamais
changé, et des droits élevés. C'est la même faiblesse que le **secret JWT
faible** du niveau 2 : dès qu'un attaquant peut vérifier ses essais hors
ligne, seule la longueur du secret le protège.

**Défenses** : comptes de service gérés (**gMSA**, mots de passe aléatoires de
120 caractères renouvelés automatiquement), ou mots de passe d'au moins 25
caractères aléatoires ; chiffrement AES plutôt que RC4 ; alerte sur les rafales
de demandes de tickets.

## AS-REP roasting

Si l'option « ne pas exiger la pré-authentification Kerberos » est cochée sur
un compte, le KDC renvoie une réponse chiffrée avec la clé de ce compte **à
quiconque la demande**, sans preuve d'identité. Même conséquence : casse hors
ligne. **Défense** : ne jamais désactiver la pré-authentification, et
inventorier les comptes qui l'ont.

## Pass-the-hash et mouvement latéral

Vu à la leçon Windows : une empreinte NT volée dans la mémoire de LSASS
s'utilise telle quelle pour se connecter à d'autres machines. L'attaquant
saute de poste en poste, récupère à chaque fois les identifiants des personnes
connectées, jusqu'à tomber sur un administrateur du domaine qui a ouvert une
session au mauvais endroit. Le cousin Kerberos s'appelle *pass-the-ticket*.

## Cartographier le chemin : la logique des graphes

Des outils comme BloodHound lisent l'annuaire (rappel : tout utilisateur peut
le lire) et calculent les **chemins d'attaque** : « ce stagiaire est
administrateur local de ce poste, où un administrateur du domaine a une session
ouverte ». Les défenseurs utilisent exactement les mêmes outils pour trouver et
couper ces chemins avant les attaquants.

## Golden Ticket : la persistance ultime

Un attaquant devenu administrateur du domaine peut extraire la clé du compte
`krbtgt`. Il fabrique alors lui-même des TGT valides, pour n'importe quel
compte, pour des années. Changer le mot de passe des administrateurs ne suffit
pas : il faut **changer deux fois** celui de `krbtgt` (l'ancienne clé reste
acceptée une fois). C'est l'équivalent exact d'un `JWT_SECRET` volé : toute la
confiance repose sur une seule clé.

## La défense structurante : le modèle en tiers

| Tier | Contient | Règle |
|---|---|---|
| **0** | Contrôleurs de domaine, comptes Admins du domaine, PKI | Ne se connectent **jamais** à un tier inférieur |
| **1** | Serveurs d'applications et leurs admins | Ne se connectent pas aux postes de travail |
| **2** | Postes de travail et support | Ne peuvent administrer que leur tier |

Un administrateur du domaine qui ne se connecte jamais à un poste de travail ne
laisse jamais son empreinte dans la mémoire d'un poste compromis : le
mouvement latéral s'arrête au tier 2. C'est le **moindre privilège** appliqué à
une organisation entière, et le même principe que les rôles de Bastion,
relus en base à chaque requête.

## À retenir

- Kerberoasting et AS-REP roasting donnent des secrets cassables hors ligne :
  seuls des mots de passe longs et aléatoires (gMSA) protègent.
- Pass-the-hash enchaîne les machines ; LAPS et le modèle en tiers le coupent.
- Tout utilisateur peut lire l'annuaire : les défenseurs doivent cartographier
  les chemins d'attaque avant les attaquants.
- La clé `krbtgt` volée = Golden Ticket : double rotation obligatoire.
