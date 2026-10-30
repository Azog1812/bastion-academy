# Windows : comptes, jetons et secrets

La plupart des postes de travail en entreprise tournent sous Windows, et c'est
souvent par eux que commence une intrusion (pièce jointe piégée, macro,
identifiants volés). Comprendre comment Windows représente un utilisateur,
c'est comprendre ce qu'un attaquant cherche à voler.

## Identités : SID et groupes

Chaque compte et chaque groupe a un **SID** (*Security Identifier*), par
exemple `S-1-5-21-…-1001`. Windows raisonne en SID, pas en noms : renommer
« Administrateur » ne change rien pour un attaquant.

```powershell
whoami /user      # mon SID
whoami /groups    # mes groupes (dont « Administrateurs » si j'en fais partie)
whoami /priv      # mes privilèges
```

Quelques SID et groupes à connaître :

| Identité | Rôle |
|---|---|
| `SYSTEM` (`S-1-5-18`) | Le compte du système d'exploitation, plus puissant qu'un administrateur |
| `Administrateurs` (`S-1-5-32-544`) | Administrateurs locaux de la machine |
| SID se terminant par `-500` | Le compte administrateur intégré, même renommé |

## Le jeton d'accès

À l'ouverture de session, Windows crée un **jeton d'accès** (*access token*)
qui contient le SID de l'utilisateur, ses groupes et ses privilèges. Chaque
processus lancé en hérite, et Windows compare ce jeton aux **ACL** (listes de
contrôle d'accès) de chaque fichier, clé de registre ou service.

L'**UAC** découpe le jeton d'un administrateur en deux : un jeton filtré, sans
droits d'administration, utilisé par défaut, et un jeton complet obtenu après
confirmation (« Voulez-vous autoriser cette application… »). Microsoft le dit
lui-même : l'UAC est une **commodité**, pas une frontière de sécurité. Un
utilisateur qui est administrateur local reste une cible de choix.

Certains privilèges suffisent à devenir `SYSTEM` : `SeDebugPrivilege` (lire la
mémoire de n'importe quel processus), `SeImpersonatePrivilege` (souvent détenu
par les comptes de service, et exploité par toute une famille d'outils). C'est
pourquoi `whoami /priv` est la première commande d'un attaquant sous Windows,
comme `sudo -l` sous Linux.

## Où vivent les secrets

| Emplacement | Contenu | Pourquoi c'est une cible |
|---|---|---|
| Base **SAM** (registre) | Empreintes NT des comptes **locaux** | Lisible avec les droits SYSTEM |
| Processus **LSASS** | Secrets des sessions ouvertes : empreintes NT, tickets Kerberos | Un administrateur peut lire sa mémoire et repartir avec les identifiants de tous ceux qui se sont connectés |
| Gestionnaire d'identifiants, navigateurs | Mots de passe enregistrés | Accessibles à la session de l'utilisateur |

## L'empreinte NT, et pourquoi elle suffit

Windows stocke les mots de passe sous forme d'**empreinte NT** : un MD4 du mot
de passe, **sans sel**. Compare avec ce que tu as vu dans Bastion (scrypt,
sel aléatoire de 128 bits, coût mémoire élevé) :

| | Empreinte NT | scrypt dans Bastion |
|---|---|---|
| Sel | Aucun : deux comptes avec le même mot de passe ont la même empreinte | 128 bits aléatoires par empreinte |
| Coût | Une opération MD4, des milliards par seconde sur GPU | 128 Mio de mémoire par essai |

Pire : le protocole **NTLM** accepte l'empreinte elle-même comme preuve
d'identité. Un attaquant qui la vole n'a même pas besoin de la casser : il
l'utilise telle quelle pour s'authentifier ailleurs. C'est le **pass-the-hash**.
Le mot de passe d'un administrateur local identique sur 500 postes, et une seule
empreinte volée ouvre les 500 machines.

## Les défenses

- **LAPS** (*Local Administrator Password Solution*) : un mot de passe
  administrateur local **différent et aléatoire** sur chaque machine, renouvelé
  automatiquement. Le pass-the-hash latéral s'arrête net.
- **Credential Guard** isole les secrets de LSASS dans un environnement
  protégé par la virtualisation ; **LSA Protection** empêche la lecture de sa
  mémoire par des processus ordinaires.
- **Pas d'administrateur local au quotidien** : un compte standard pour
  travailler, un compte séparé pour administrer.
- Désactiver NTLM là où Kerberos suffit, et journaliser son usage.

## À retenir

- Windows raisonne en SID ; un processus porte le jeton de son utilisateur.
- L'UAC n'est pas une frontière de sécurité ; `whoami /priv` révèle les
  privilèges dangereux.
- L'empreinte NT n'est pas salée, et NTLM l'accepte comme preuve : pass-the-hash.
- LAPS, Credential Guard et la séparation des comptes coupent ces chemins.
