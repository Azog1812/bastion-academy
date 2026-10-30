# Contrôle d'accès aux fonctions

**API5:2023, Broken Function Level Authorization** : un utilisateur ordinaire
appelle une fonction réservée, le plus souvent une route d'administration. Là où
l'IDOR franchit une frontière **horizontale** (les données d'un autre
utilisateur), cette faille franchit une frontière **verticale** (les droits d'un
autre rôle).

## Les formes courantes

- Une route `/admin/…` qui vérifie l'authentification mais pas le rôle.
- Un lien d'administration simplement **caché** dans l'interface.
- Une route publique qui accepte une méthode inattendue : `GET /users/42` est
  protégé, `DELETE /users/42` ne l'est pas.
- Un rôle lu dans un jeton ou un cookie que le client peut modifier.

Masquer une URL n'est pas un contrôle d'accès : les URL se devinent
(`/admin`, `/api/v1/admin`), fuitent dans le code JavaScript livré au navigateur,
dans les journaux ou dans la documentation.

## À toi de jouer

Avec ton compte ordinaire sur Bastion lancé en local :

```bash
curl -i http://localhost:3000/v1/admin/audit -H "authorization: Bearer $TOKEN"
```

Réponse : `403`. Ta tentative est elle-même inscrite dans le journal d'audit,
sous l'action `authz.denied`.

## La défense de Bastion, en trois couches

**1. Une vérification de rôle côté serveur, sur la route elle-même.** Dans
`src/http/routes.ts`, chaque route d'administration passe par
`requireRole('admin')`. La vérification n'est pas dans le service appelé plus
loin, ni dans l'interface : elle est sur la route, visible à la relecture.

**2. Un rôle qui vient de la base, pas du jeton.** Le middleware `authenticate`
relit le rôle en base à chaque requête. Si un administrateur est rétrogradé, son
jeton encore valide ne lui donne plus rien dès la requête suivante. Le test
*an admin can read and verify the audit trail; a demotion applies instantly* le
démontre.

**3. Aucune route HTTP ne donne de privilège.** Pour devenir administrateur,
il faut exécuter une commande sur le serveur :

```bash
node dist/cli.js promote alice@lab.test
```

C'est une **frontière de confiance** séparée : un attaquant qui contrôlerait
entièrement l'API par HTTP ne pourrait toujours pas se promouvoir. La rotation
des clés de chiffrement suit le même principe. Une fonctionnalité qui n'est pas
exposée ne peut pas être attaquée par le réseau.

## Détecter, pas seulement bloquer

Chaque refus est journalisé (`authz.denied`) avec l'utilisateur, l'URL visée et
l'adresse IP, dans le journal d'audit chaîné par HMAC. Un compte qui essaie les
routes d'administration les unes après les autres est un signal d'alerte : la
défense ne s'arrête pas au `403`.

## Récapitulatif du niveau 2

| Faille | Cause | Défense clé de Bastion |
|---|---|---|
| Injection SQL | Donnée collée dans la requête | Requêtes paramétrées + lint + Semgrep |
| XSS | Texte transformé en HTML | `h()` + ESLint + CSP Trusted Types |
| CSRF | Authentification envoyée automatiquement | Bearer partout, trois routes à cookie protégées |
| Attaques JWT | Confiance dans le jeton | Liste blanche, claims obligatoires, version en base |
| Assignation de masse | Champs client copiés aveuglément | Schémas `.strict()`, réponses explicites |
| Accès aux fonctions | Rôle non vérifié côté serveur | `requireRole`, rôle en base, privilèges hors HTTP |

## À retenir

- Le serveur vérifie le rôle sur chaque route sensible, à chaque requête.
- Une fonction qui n'a pas besoin d'être sur le réseau ne doit pas y être.
- Un refus est aussi une information : journalise-le.
