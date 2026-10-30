# Se défendre du XSS en profondeur

La règle de base de l'OWASP : **encoder la sortie selon son contexte**. Mais la
meilleure défense est de ne jamais avoir à le faire, en ne construisant jamais de
HTML à partir de texte.

## Règle 1 : insérer du texte, pas du HTML

```js
// SÛR : la chaîne devient un nœud texte, quel que soit son contenu
resultat.textContent = 'Résultats pour : ' + recherche;
```

`textContent` (ou `document.createTextNode`) n'interprète jamais de balisage.
Le payload `<img src=x onerror=…>` s'affiche tel quel, comme du texte.

Les API dangereuses, appelées *sinks*, sont celles qui transforment une chaîne en
HTML ou en code : `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write`, `eval`, `setTimeout` avec une chaîne, l'attribut `srcdoc`…

## Comment l'interface de Bastion Academy est construite

**Toute** l'interface passe par une seule fonction, `h()`, dans
`web/src/dom.ts` : elle crée les éléments avec `createElement` et y ajoute des
nœuds texte. Elle refuse même les attributs `on…` passés comme chaîne.

Les leçons sont écrites en Markdown. Au lieu d'utiliser une bibliothèque qui
produit du HTML puis de le nettoyer, `web/src/markdown.ts` transforme le Markdown
en **arbre de données**, puis chaque nœud devient un élément DOM. Conséquences :

- du HTML écrit dans une leçon s'affiche comme du texte ;
- un lien `javascript:` est rétrogradé en simple texte : seuls `https:` et les
  liens internes `#/` survivent.

Et pour que cette règle ne dépende pas de la vigilance de chacun, **ESLint
interdit** tous les sinks HTML dans `web/` (`eslint.config.js`).

## Règle 2 : une CSP stricte

La *Content Security Policy* indique au navigateur ce que la page a le droit de
charger et d'exécuter. Celle des pages de Bastion Academy (`src/http/web.ts`)
contient notamment :

```text
script-src 'self'
require-trusted-types-for 'script'
trusted-types
```

- `script-src 'self'` : seuls les fichiers JavaScript du site s'exécutent. Pas de
  script inline, pas d'`eval`.
- **Trusted Types** : les sinks comme `innerHTML` n'acceptent plus de simples
  chaînes, seulement des objets créés par une *politique* déclarée. Et
  `trusted-types` sans aucun nom signifie : **aucune politique autorisée**. Tout
  appel à `innerHTML` avec une chaîne lève donc une erreur.

C'est exactement l'erreur `TypeError` que tu as obtenue dans la console à la
leçon précédente.

## Pourquoi deux barrières ?

| Barrière | Ce qu'elle arrête | Ce qui peut la contourner |
|---|---|---|
| Règle de code (`h()` + ESLint) | Les erreurs du code de l'application | Une dépendance tierce, une exception mal revue |
| CSP + Trusted Types | Tout sink appelé avec une chaîne, d'où qu'il vienne | Un vieux navigateur sans Trusted Types |

Chaque barrière couvre la faiblesse de l'autre. Pour obtenir une XSS, il faut
**deux défaillances indépendantes**. C'est la définition de la défense en
profondeur.

## Et les jetons ?

Même en cas de XSS, le jeton de session longue durée reste hors d'atteinte
(cookie `HttpOnly`), et le jeton d'accès ne vit que quelques minutes, en mémoire.
On limite ainsi l'**impact** d'une faille qu'on n'aurait pas vue.

## Ce que disent les tests

- `test/unit/markdown.test.ts` vérifie que du HTML reste du texte, que les
  liens `javascript:`, `data:` ou `http:` disparaissent, et que le parseur ne se
  bloque pas sur une entrée pathologique.
- `test/security/web.test.ts` vérifie que chaque page est servie avec cette CSP,
  sans script ni style inline.

## À retenir

- Insérer du texte avec `textContent`, jamais une chaîne dans `innerHTML`.
- Une CSP stricte avec Trusted Types transforme une XSS en simple erreur.
- Limiter ce qu'un script injecté peut voler réduit l'impact d'une faille.
