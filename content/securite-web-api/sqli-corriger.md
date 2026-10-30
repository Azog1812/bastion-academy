# Corriger l'injection SQL, et l'interdire pour toujours

## La bonne défense : les requêtes paramétrées

Reprends ton fichier `sqli-lab.mjs` et remplace les deux dernières lignes de
requête par :

```js
// CORRIGÉ : la requête est fixe, les valeurs voyagent à part.
const sql = 'SELECT email, role FROM users WHERE email = ? AND password = ?';
console.log('Résultat :', db.prepare(sql).all(email, password));
```

Relance les trois attaques : elles renvoient toutes un résultat vide, alors
qu'Alice peut toujours se connecter.

Pourquoi ça marche ? Le texte de la requête est envoyé et **compilé avant**
que les valeurs arrivent. Les marqueurs `?` sont des emplacements de données :
quoi qu'ils contiennent, apostrophes et mots-clés compris, ils ne seront jamais
interprétés comme du SQL.

## Les fausses bonnes idées

| Idée | Pourquoi ça ne suffit pas |
|---|---|
| Échapper les apostrophes à la main | Un oubli suffit, et chaque base a ses subtilités d'encodage |
| Filtrer `SELECT`, `DROP`, `--` | Contournable (casse, commentaires, encodages) et casse des données légitimes |
| Valider le format des entrées | Utile en complément, mais un champ « commentaire » accepte forcément des apostrophes |

## Le cas piège : ce qu'on ne peut pas paramétrer

Un marqueur `?` remplace une **valeur**, pas un nom de colonne ni un mot-clé.
Pour un tri choisi par l'utilisateur (`ORDER BY`), on compare l'entrée à une
**liste blanche** :

```js
const SORTABLE = new Map([['date', 'updated_at'], ['titre', 'title']]);
const column = SORTABLE.get(req.query.sort) ?? 'updated_at';
```

L'utilisateur choisit une clé ; seul le code décide du SQL.

## Comment Bastion rend l'erreur impossible à commettre

Corriger une faille ne suffit pas : il faut empêcher qu'elle revienne. Bastion
empile quatre couches.

1. **Le code.** Toutes les requêtes passent par `prepare()` avec des `?`. Par
   exemple, dans `src/services/note-service.ts` :

   ```ts
   this.db.prepare('SELECT * FROM notes WHERE id = ? AND owner_id = ?').get(noteId, ownerId);
   ```

2. **Le lint.** `eslint.config.js` refuse tout gabarit avec interpolation et
   toute concaténation passés à `prepare()` ou `exec()`. Le message d'erreur
   explique pourquoi : *SQL injection risk: use bound parameters*.

3. **L'analyse statique en CI.** La règle Semgrep `bastion-sql-interpolation`
   (`.semgrep/bastion.yml`) bloque la fusion d'une PR qui en contiendrait une.

4. **Les tests.** `test/security/input-and-transport.test.ts` envoie de vraies
   charges (`' OR '1'='1`, `admin'--`, `x'; DROP TABLE users; --`,
   `UNION SELECT`) et vérifie qu'elles sont stockées comme du simple texte, et que
   la table `users` est intacte.

Il existe **une** exception, et elle est documentée : `PRAGMA user_version`
dans `src/db.ts`, car SQLite n'accepte pas de paramètre à cet endroit. La valeur
est un compteur de boucle, jamais une entrée externe. L'exception est annotée
pour ESLint et Semgrep, avec sa justification juste au-dessus. Une exception
revue et expliquée, c'est de la sécurité ; une exception silencieuse, c'est une
dette.

## Défense en profondeur

- **Moindre privilège** : le compte de base de données de l'application ne
  devrait pas pouvoir supprimer des tables ni lire celles des autres applications.
- **Erreurs génériques** : Bastion ne renvoie jamais un message SQL au client,
  ce qui prive l'attaquant de l'injection basée sur les erreurs.

## À retenir

- Requêtes paramétrées pour les valeurs, liste blanche pour les identifiants.
- Une règle de sécurité écrite dans le lint et la CI vaut mieux qu'une règle
  écrite dans un wiki.
- Toute exception doit être revue, justifiée et annotée.
