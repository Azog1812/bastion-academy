# Journaliser ce qui compte

Jusqu'ici, tu as attaqué. À partir de maintenant, tu changes de camp. Le premier
réflexe d'un défenseur n'est pas d'acheter un outil : c'est de se demander
**ce qu'il verrait** si l'attaque des niveaux précédents avait lieu chez lui.
La réponse dépend entièrement de ce qui est journalisé.

L'OWASP en a fait une catégorie de son Top 10 (A09 : *Security Logging and
Monitoring Failures*) : la plupart des intrusions sont découvertes des mois
après, et souvent par quelqu'un d'extérieur, faute de traces exploitables.

## À quoi servent les journaux

| Usage | Question à laquelle ils répondent |
|---|---|
| **Détection** | Une attaque est-elle en cours ? |
| **Investigation** | Qu'a fait l'attaquant, depuis quand, avec quel compte ? |
| **Imputabilité** | Qui a fait quoi ? (« ce n'est pas moi » ne tient pas face à une trace fiable) |
| **Conformité** | Peut-on prouver qu'un contrôle a fonctionné ? |

## Quoi journaliser

Côté application, l'OWASP recommande au minimum :

- les **authentifications**, réussies et échouées, et les verrouillages ;
- les **refus d'accès** (un IDOR qui échoue est un signal précieux) ;
- les **erreurs de validation** d'entrée, signe de sondage ;
- les **actions d'administration** et les changements de droits ;
- les erreurs serveur.

Côté système et réseau : l'authentification Windows (événements **4624**,
**4625**), la création de processus (**4688**, ou Sysmon 1), `auth.log` ou
`journald` sous Linux, les journaux DNS, proxy et pare-feu.

Et surtout, **ce qu'on ne journalise pas** : mots de passe, jetons, clés,
numéros de carte, données personnelles inutiles. Un journal qui contient des
secrets devient lui-même une cible.

## Comment journaliser

- **Format structuré** (JSON) : un champ `src_ip` se filtre, une phrase libre se devine.
- **Horodatage en UTC**, horloges synchronisées (NTP) : reconstituer une
  chronologie sur dix machines décalées de quelques minutes est un cauchemar.
- **Identifiant de corrélation** : la même requête doit pouvoir être suivie du
  proxy à la base de données.
- **Hors de portée de l'attaquant** : un attaquant qui obtient les droits
  administrateur efface ses traces locales. Les journaux partent vers un
  serveur central, en écriture seule.

## Dans Bastion

Ouvre `src/audit.ts` et `src/logger.ts` :

- chaque événement de sécurité (`auth.login`, `authz.denied`,
  `challenge.flag_shared`, `lab.start`…) est écrit dans une table **en ajout
  seul** : des déclencheurs SQL refusent toute modification ou suppression ;
- chaque entrée contient le **HMAC** de la précédente : effacer ou modifier une
  ligne casse la chaîne, et `node dist/cli.js verify-audit` indique la première
  entrée invalide, même si l'attaquant a supprimé les déclencheurs ;
- les journaux techniques sont en JSON, avec un `requestId`, et le logger
  **masque** les champs sensibles (`authorization`, `password`, `token`,
  `flag`…) avant même qu'ils soient écrits.

## À retenir

- Pas de détection sans journaux, pas d'enquête sans journaux fiables.
- Journaliser les succès **et** les échecs, les refus d'accès, l'administration.
- Jamais de secrets dans les journaux.
- Structuré, en UTC, corrélable, centralisé, protégé contre la modification.
