# Corriger une IDOR, et le prouver

Tu as vu la faille et la méthode de test. Voici comment Bastion rend l'IDOR
impossible, en trois couches : le code, les tests et la CI.

## Couche 1 : le propriétaire est dans la requête SQL

Le correctif intuitif consiste à charger l'objet, puis à vérifier son
propriétaire :

```ts
// FRAGILE : « charger puis vérifier »
const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(id);
if (!note || note.owner_id !== userId) throw notFound();
```

Ça fonctionne… jusqu'au jour où quelqu'un ajoute un endpoint et oublie la
deuxième ligne. Bastion fait autrement : **le propriétaire fait partie de la
requête elle-même** (`src/services/note-service.ts`) :

```ts
const row = this.db
  .prepare('SELECT * FROM notes WHERE id = ? AND owner_id = ?')
  .get(noteId, ownerId);
if (!row) throw notFound('Note not found'); // même réponse dans tous les cas
```

Il n'existe aucun chemin de code où la note d'un autre est chargée en mémoire.
Et `ownerId` vient toujours du jeton vérifié, jamais d'un paramètre de la requête.

## Couche 2 : la même réponse pour « inexistant » et « pas à toi »

Répondre `403` pour la note d'un autre et `404` pour une note inexistante
permettrait à Mallory de **cartographier** les identifiants valides. Bastion
renvoie le même `404` avec le même message, et journalise la tentative en
`authz.denied`.

## Couche 3 : un test qui rejoue l'attaque

Le fichier `test/security/authorization.test.ts` fait exactement ce que tu as
fait à la main dans la leçon précédente :

```ts
const read = await t.http.get(`/v1/notes/${noteId}`).set(mallory.auth).expect(404);
const missing = await t.http.get('/v1/notes/00000000-0000-4000-8000-000000000000')
  .set(mallory.auth).expect(404);
expect(read.body.message).toBe(missing.body.message);
```

Si une modification réintroduit la faille, ce test échoue et la CI bloque la
fusion.

## Couche 4 : une règle d'analyse statique

Un test ne couvre que les endpoints qu'il connaît. Pour les **futurs**
endpoints, Bastion ajoute une règle Semgrep (`.semgrep/bastion.yml`,
`bastion-note-query-without-owner`) : toute requête SQL sur `notes` filtrée par
`id` sans `owner_id` fait échouer la CI. La règle de sécurité est écrite dans
le code, pas seulement dans la tête des développeurs.

## Récapitulatif

| Couche | Ce qu'elle garantit |
|---|---|
| `owner_id` dans le SQL | L'objet d'un autre n'est jamais chargé |
| Même `404` + audit | L'attaquant n'apprend rien, le défenseur voit tout |
| Test à deux comptes | La faille ne revient pas sur les routes existantes |
| Règle Semgrep | Elle ne revient pas non plus sur les nouvelles routes |

C'est le principe de Bastion Academy : une faille n'est vraiment corrigée que
si la correction est **prouvée** et **protégée contre la régression**.

## Pour aller plus loin

Ouvre `src/services/learning-service.ts` : la progression des apprenants suit
le même modèle. Toutes les requêtes sont filtrées par `user_id`, et aucune
route ne prend d'identifiant d'utilisateur en paramètre.
