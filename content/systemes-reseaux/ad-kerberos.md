# Active Directory et Kerberos

Dans une entreprise, des milliers de postes, serveurs et utilisateurs sont
gérés par **Active Directory** (AD). C'est l'annuaire central : qui existe,
qui appartient à quel groupe, qui peut se connecter où. Pour un attaquant,
c'est la **clé du royaume** : prendre le contrôle de l'AD, c'est prendre le
contrôle de toute l'entreprise.

## Le vocabulaire

| Terme | Définition |
|---|---|
| **Domaine** | Ensemble de comptes et de machines gérés ensemble (`corp.exemple.fr`) |
| **Contrôleur de domaine** (DC) | Serveur qui héberge l'annuaire et authentifie tout le monde |
| **Forêt** | Un ou plusieurs domaines liés par des relations d'approbation |
| **OU** (unité d'organisation) | Dossier de l'annuaire, sur lequel on applique des stratégies |
| **GPO** (stratégie de groupe) | Configuration poussée à des machines ou utilisateurs : mots de passe, logiciels, scripts |
| **Admins du domaine** | Le groupe qui contrôle tout le domaine |

L'annuaire s'interroge en **LDAP** (port 389, 636 en TLS). Point capital : par
défaut, **n'importe quel utilisateur authentifié** peut lire presque tout
l'annuaire, y compris les groupes, leurs membres et les sessions ouvertes. Un
attaquant qui obtient un simple compte de stagiaire peut donc cartographier le
chemin jusqu'aux administrateurs.

## Kerberos, l'authentification par tickets

Kerberos évite d'envoyer le mot de passe à chaque service. Le DC joue le rôle de
**KDC** (*Key Distribution Center*) et délivre des tickets.

```text
1. AS-REQ   utilisateur → KDC   « je suis alice », horodatage chiffré avec sa clé
2. AS-REP   KDC → utilisateur   un TGT (Ticket Granting Ticket), chiffré avec la clé du compte krbtgt
3. TGS-REQ  utilisateur → KDC   « voici mon TGT, je veux accéder au service SQL »
4. TGS-REP  KDC → utilisateur   un ticket de service, chiffré avec la clé du compte de service
5. AP-REQ   utilisateur → service SQL   présente le ticket ; le service le déchiffre avec sa propre clé
```

Trois détails expliquent toutes les attaques de la leçon suivante :

- La « clé » d'un compte est **dérivée de son mot de passe**.
- Le ticket de service (étape 4) est chiffré avec la clé du **compte de
  service**, et **tout utilisateur authentifié** peut le demander pour n'importe
  quel service enregistré (SPN).
- Le TGT est chiffré avec la clé du compte **krbtgt** : qui connaît cette clé
  peut fabriquer des TGT pour n'importe qui.

## Le parallèle avec Bastion

Kerberos et les jetons de Bastion résolvent le même problème : prouver son
identité sans renvoyer le mot de passe à chaque requête.

| Kerberos | Bastion |
|---|---|
| TGT, valable ~10 h, renouvelable | Jeton de rafraîchissement, 7 jours, à usage unique |
| Ticket de service, court | Jeton d'accès JWT, 15 minutes |
| Clé `krbtgt` qui signe les TGT | `JWT_SECRET` qui signe les jetons d'accès |
| Volée → *Golden Ticket*, accès total jusqu'à double rotation de la clé | Volée → n'importe quel jeton peut être forgé ; d'où le stockage en fichier secret, hors base |

Même leçon dans les deux mondes : **la clé qui signe les jetons est l'actif le
plus précieux du système**.

## À retenir

- AD est l'annuaire central ; le compromettre, c'est compromettre l'entreprise.
- Tout utilisateur du domaine peut lire l'essentiel de l'annuaire en LDAP.
- Kerberos : TGT puis ticket de service, chiffrés avec des clés dérivées de mots de passe.
- La clé `krbtgt` joue le même rôle que la clé de signature des JWT.
