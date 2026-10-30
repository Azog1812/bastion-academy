# Assignation de masse et fuite de propriétés

L'OWASP API Security Top 10 regroupe deux erreurs sous **API3:2023, Broken
Object Property Level Authorization** : laisser le client **écrire** une
propriété qu'il ne devrait pas toucher, et lui laisser **lire** une propriété
qu'il ne devrait pas voir.

## Écrire : l'assignation de masse

Le code vulnérable est séduisant de simplicité :

```js
// VULNÉRABLE : tout ce que le client envoie est copié dans l'objet
app.post('/inscription', (req, res) => {
  const user = { role: 'user', ...req.body };
  db.save(user);
});
```

Il suffit d'ajouter un champ pour devenir administrateur :

```json
{ "email": "pirate@lab.test", "password": "…", "role": "admin" }
```

Les variantes sont nombreuses : `isVerified`, `balance`, `ownerId`, `createdAt`,
ou `__proto__` pour polluer les prototypes JavaScript.

## Lire : la fuite de propriétés

L'erreur symétrique : renvoyer l'objet tel qu'il sort de la base.

```js
// VULNÉRABLE : renvoie aussi password_hash, failed_logins, token_version…
res.json(db.getUser(id));
```

Le jour où quelqu'un ajoute une colonne sensible, elle fuite dans l'API sans que
personne ne s'en rende compte.

## À toi de jouer

Avec Bastion lancé en local, tente l'assignation de masse :

```bash
curl -i -X POST http://localhost:3000/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"pirate@lab.test","password":"correct horse battery staple","role":"admin"}'
```

Réponse : `400`, avec le champ refusé indiqué dans `issues`. Le compte n'est pas
créé du tout.

## La défense de Bastion

**En écriture : des schémas stricts.** Tous les schémas de requête de
`src/http/schemas.ts` se terminent par `.strict()`. Un champ inconnu n'est pas
ignoré en silence : la requête entière est refusée. C'est une **liste blanche**
des champs acceptés, et non une liste noire des champs interdits.

Ignorer en silence serait moins sûr : le client croirait sa requête acceptée, et
une faute de frappe côté serveur pourrait un jour rendre le champ actif.

**En lecture : des réponses construites champ par champ.** Bastion ne renvoie
jamais une ligne de base de données telle quelle. Exemple frappant : les
réponses des quiz. Elles sont dans le contenu de la leçon, en mémoire sur le
serveur. `getLesson()` (`src/services/learning-service.ts`) construit
explicitement chaque question avec `id`, `prompt`, `choices` et `multiple`, et
rien d'autre. Le test *never sends quiz answers to the client* le vérifie.

## Ce que disent les tests

- *there is no HTTP path to become admin (mass assignment)* dans
  `test/security/authorization.test.ts` ;
- *rejects prototype-pollution keys instead of merging them* dans
  `test/security/input-and-transport.test.ts` ;
- dans `test/security/learning.test.ts`, une tentative d'envoyer
  `completedAt` pour antidater une leçon est refusée.

## À retenir

- Liste blanche des champs en entrée, et refus de tout le reste.
- Réponses construites explicitement, jamais un objet brut de la base.
- Une donnée qui ne doit pas sortir du serveur ne doit jamais être dans la réponse.
