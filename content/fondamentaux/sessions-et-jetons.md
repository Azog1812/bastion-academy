# Sessions et jetons d'accès

HTTP est **sans état** : chaque requête est indépendante. Pour qu'un serveur se
souvienne que tu es connecté, il te remet une preuve que tu renvoies à chaque
requête.

## Deux grandes approches

- **Cookie de session** : le serveur garde la session en mémoire ou en base et
  te donne un identifiant aléatoire. Le navigateur le renvoie automatiquement,
  ce qui expose au CSRF si on ne s'en protège pas.
- **Jeton porteur (*bearer token*)** : le client envoie explicitement
  `Authorization: Bearer <jeton>`. Celui qui possède le jeton est authentifié,
  d'où l'importance de ne jamais le laisser fuiter.

Bastion utilise des jetons d'accès **JWT** à durée de vie courte, plus des
jetons de rafraîchissement opaques.

## Un JWT se lit, il ne se cache pas

Un JWT, c'est trois blocs base64url séparés par des points :
`en-tête.contenu.signature`. Décode le contenu de ton propre jeton :

```bash
echo "<partie du milieu du jeton>" | base64 -d
```

Tu verras ton identifiant, ta date d'expiration… en clair. La signature
garantit l'**intégrité** (personne ne peut modifier le contenu sans la clé),
pas la **confidentialité**. On ne met jamais de secret dans un JWT.

## Les attaques classiques, et ce que fait Bastion

| Attaque | Principe | Défense de Bastion |
|---|---|---|
| `alg: none` | Envoyer un jeton « non signé » en espérant que le serveur l'accepte | Liste blanche d'algorithmes : seul `HS256` est accepté |
| Jeton volé | Réutiliser le jeton d'un autre | Durée de vie courte (minutes) |
| Jeton de rafraîchissement rejoué | Réutiliser un ancien jeton de rafraîchissement | Rotation à usage unique : une réutilisation révoque toute la famille de sessions |
| Jeton « éternel » | Un JWT reste valide jusqu'à expiration, même après déconnexion | Version de jeton et rôle relus **en base** à chaque requête |

Le dernier point est un compromis assumé : on perd un peu du côté « sans état »
des JWT, mais une déconnexion ou une rétrogradation prend effet immédiatement.

## À retenir

- Un JWT est signé, pas chiffré : son contenu est lisible par tous.
- La signature n'a de valeur que si le serveur impose l'algorithme.
- Un bon système de jetons prévoit la révocation.
