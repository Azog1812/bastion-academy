# Délégation Kerberos et AD CS

Au niveau 3, les attaques contre Active Directory volaient des secrets :
Kerberoasting, pass-the-hash, Golden Ticket. Au niveau expert, on exploite des
**mécanismes de confiance** voulus par Microsoft, mais mal configurés. Ce sont
les chemins qu'empruntent les tests d'intrusion internes avancés, et ceux que
BloodHound dessine.

> Comme toujours : uniquement dans un laboratoire qui t'appartient.

## La délégation : agir au nom d'un utilisateur

Un serveur web doit parfois interroger une base de données **au nom** de
l'utilisateur connecté, avec ses droits à lui. Kerberos le permet de trois façons.

| Type | Principe | Risque |
|---|---|---|
| **Non contrainte** | Le serveur reçoit une copie du TGT de chaque utilisateur qui s'y connecte, utilisable **partout** | Compromettre ce serveur, c'est récupérer les TGT de tous ceux qui s'y connectent, y compris un administrateur du domaine. Pire : on peut **forcer** un contrôleur de domaine à s'y authentifier (attaques de « coercition » comme PetitPotam) et voler son TGT |
| **Contrainte** (S4U2Self, S4U2Proxy) | Le serveur ne peut déléguer que vers une liste de services | Avec la transition de protocole, le serveur obtient un ticket au nom de **n'importe quel** utilisateur pour ces services, sans que celui-ci se connecte |
| **Basée sur les ressources** (RBCD) | C'est la ressource cible qui liste qui peut déléguer vers elle (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | Quiconque peut **écrire** cet attribut sur une machine peut s'y faire passer pour un administrateur. Un droit d'écriture oublié devient un accès administrateur |

**Défenses** : supprimer la délégation non contrainte (hors contrôleurs de
domaine) ; mettre les comptes à privilèges dans le groupe **Protected Users** et
cocher « le compte est sensible et ne peut pas être délégué » ; auditer qui peut
écrire sur les objets ordinateurs ; limiter `ms-DS-MachineAccountQuota` à 0 pour
qu'un simple utilisateur ne puisse pas créer de compte machine.

## AD CS : la PKI, nouvelle cible favorite

**AD CS** (*Active Directory Certificate Services*) délivre des certificats.
Or un certificat permet de s'authentifier par Kerberos (PKINIT) : obtenir un
certificat au nom d'un administrateur, c'est **devenir** cet administrateur,
et ce, tant que le certificat est valide, même s'il change son mot de passe.

En 2021, Will Schroeder et Lee Christensen (SpecterOps) ont publié *Certified
Pre-Owned*, qui classe les mauvaises configurations en **ESC1, ESC2…** Les deux
plus célèbres :

- **ESC1** : un modèle de certificat qui permet à **tout utilisateur** de
  s'inscrire, autorise l'authentification client, et laisse le demandeur
  **choisir le nom** inscrit dans le certificat. Un stagiaire demande un
  certificat « au nom de l'administrateur du domaine ». Le serveur accepte.
- **ESC8** : l'inscription web d'AD CS (HTTP) accepte l'authentification NTLM
  sans protection contre le relais. L'attaquant force un contrôleur de domaine
  à s'authentifier vers lui, **relaie** cette authentification à AD CS, et
  obtient un certificat du contrôleur de domaine.

**Défenses** : auditer les modèles (outils Certipy, PSPKIAudit), retirer le
droit d'inscription aux groupes larges, refuser que le demandeur fournisse le
sujet, activer l'approbation par un responsable ; activer EPA et HTTPS (ou
désactiver l'inscription web) ; traiter les serveurs de PKI comme le **tier 0**,
au même rang que les contrôleurs de domaine.

## DCSync : se faire passer pour un contrôleur de domaine

Les contrôleurs de domaine se répliquent l'annuaire entre eux, empreintes de
mots de passe comprises. Un compte qui possède les droits de réplication
(*Replicating Directory Changes* et *Replicating Directory Changes All*) peut
demander cette réplication, depuis n'importe quel poste : c'est **DCSync**
(Mimikatz, `secretsdump`). Il obtient l'empreinte de `krbtgt`, donc de quoi
forger des Golden Tickets.

Ces droits n'appartiennent normalement qu'aux contrôleurs de domaine et aux
administrateurs. Les trouver sur un compte de service ou un utilisateur, c'est
souvent la trace d'une ancienne installation… ou d'un attaquant qui prépare son
retour.

## Le fil commun

Délégation, AD CS, DCSync : à chaque fois, un **droit** ou une **option** donne
plus de confiance que prévu. Les outils de graphe (BloodHound) les relient en
chemins d'attaque. Côté défense, la réponse est la même qu'au niveau 3 : le
modèle en tiers, le moindre privilège et l'audit régulier des droits, parce
qu'un chemin qu'on ne voit pas ne sera pas coupé.

## À retenir

- Délégation non contrainte : un serveur compromis livre les TGT de tous ses visiteurs ; RBCD : un droit d'écriture suffit à devenir administrateur d'une machine.
- AD CS : un certificat au nom d'un administrateur vaut ce compte (ESC1 : le demandeur choisit le nom ; ESC8 : relais NTLM vers l'inscription web).
- DCSync : les droits de réplication donnent toutes les empreintes, `krbtgt` compris.
- Défense : Protected Users, modèles de certificats audités, PKI au tier 0, audit des droits.
