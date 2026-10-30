# Durcir la vérification des JWT

Voici la fonction de vérification de Bastion (`src/crypto/tokens.ts`). Chaque
option ferme une des attaques de la leçon précédente.

```ts
const { payload } = await jwtVerify(token, key, {
  algorithms: ['HS256'],
  issuer: opts.issuer,
  audience: opts.audience,
  typ: 'at+jwt',
  requiredClaims: ['exp', 'iat', 'sub', 'jti'],
  clockTolerance: 5,
});
```

| Option | Attaque bloquée |
|---|---|
| `algorithms: ['HS256']` | `alg: none` et confusion d'algorithme : le serveur impose **sa** liste, il ne lit pas celle du jeton |
| `issuer`, `audience` | Un jeton émis par un autre service, ou pour un autre service |
| `typ: 'at+jwt'` | Un autre type de jeton (par exemple un *ID token* OpenID) présenté comme jeton d'accès |
| `requiredClaims` | Un jeton sans expiration, ou sans identifiant |
| `clockTolerance: 5` | Tolère 5 secondes de décalage d'horloge, pas plus |

Après la signature, Bastion **revérifie la structure** du contenu : `sub` doit
être une chaîne, `role` doit valoir `user` ou `admin`, `tv` doit être un nombre.
Une signature valide ne garantit pas un contenu sensé.

## Révoquer un jeton « sans état »

Un JWT est censé être vérifiable sans consulter la base. Problème : on ne peut
alors pas le révoquer avant son expiration. Bastion fait un compromis assumé
(ADR 0003) :

- Le jeton d'accès vit **15 minutes** par défaut (une heure au maximum, la configuration refuse davantage).
- Il porte une **version** (`tv`). À chaque requête, le middleware
  `authenticate` (`src/http/middleware.ts`) relit en base la version et le rôle
  de l'utilisateur. Un changement de mot de passe ou un « déconnecter partout »
  incrémente la version : tous les jetons en circulation deviennent invalides
  **immédiatement**.
- Le rôle vient de la base, pas du jeton : une rétrogradation prend effet à la
  requête suivante.

Le prix : une lecture en base par requête. Le gain : une révocation instantanée.

## Le jeton de rafraîchissement

Le jeton longue durée (7 jours) n'est pas un JWT mais une valeur aléatoire de
256 bits, dont la base ne stocke que l'empreinte SHA-256. Il est **à usage
unique** : chaque rafraîchissement en délivre un nouveau. Si un ancien jeton est
présenté, c'est qu'il a été copié : Bastion révoque alors **toute la famille** de
sessions (détection de réutilisation, RFC 9700).

## Ce que disent les tests

`test/unit/tokens.test.ts` rejoue chaque attaque :

- *rejects "alg: none" (unsigned token attack)* ;
- *rejects a payload modified after signing (privilege escalation attempt)* ;
- *rejects algorithms outside the allow-list, even with the right key (HS512)* ;
- *rejects a token of another type (e.g. an ID token)* ;
- *rejects a validly signed token whose claims are structurally wrong*.

Le test HS512 est intéressant : même signé avec **la bonne clé**, un jeton dans
un autre algorithme est refusé. La liste blanche n'est pas une formalité.

## À retenir

- Liste blanche d'algorithmes, `iss`, `aud`, `typ` et `exp` obligatoires.
- Revérifier la structure du contenu après la signature.
- Durée de vie courte + version en base = révocation immédiate.
