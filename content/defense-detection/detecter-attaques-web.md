# Détecter les attaques web dans les journaux

Au niveau 2, tu as injecté du SQL, forgé des jetons, sauté d'un dossier à
l'autre. Toutes ces attaques laissent des traces dans les journaux d'accès du
serveur web. Encore faut-il savoir les lire, et ne pas confondre un client
nommé O'Connor avec un attaquant.

## Ce que montre un journal d'accès

```
203.0.113.9 - - [12/Jan/2026:09:14:02 +0100] "GET /produits?id=3%20AND%201=2 HTTP/1.1" 200 312 "-" "Mozilla/5.0"
```

Adresse source, date, méthode, chemin **et paramètres**, code de statut, taille
de la réponse, agent utilisateur. Le corps des requêtes `POST` n'y figure
généralement **pas** : une injection dans un formulaire de connexion est
invisible ici, il faut les journaux de l'application.

## Signatures : utiles, mais contournables

Les motifs classiques de l'injection SQL (`' OR '1'='1`, `UNION SELECT`,
`SLEEP(`, `ORDER BY` suivi d'un nombre) se repèrent bien, **après décodage**
de l'URL : `%27` est une apostrophe, `+` un espace. Les attaquants jouent sur :

- la **casse** (`UnIoN SeLeCt`) : d'où les comparaisons insensibles à la casse ;
- les **commentaires** SQL (`UNION/**/SELECT`) et les espaces alternatifs ;
- les **encodages** multiples (`%2527`, décodé deux fois).

C'est le travail de l'**OWASP Core Rule Set**, le jeu de règles des pare-feu
applicatifs (WAF) libres : des centaines de signatures, chacune avec ses faux
positifs connus.

## Les pièges classiques

| Règle naïve | Faux positif |
|---|---|
| Une apostrophe dans la requête | `nom=O'Connor`, `q=rock'n'roll` |
| Le mot `select` | `q=select ta taille` |
| Le mot `union` | `q=union jack` |
| L'agent utilisateur `sqlmap` | Aucun, mais l'attaquant qui change d'agent passe : **faux négatif** |

L'agent utilisateur est déclaré par le client : il ne prouve rien. Une règle
fondée uniquement sur lui détecte les attaquants négligents et manque les autres.

## Les signaux de comportement

Quand les signatures ne suffisent pas, le comportement trahit l'attaque :

- une **rafale d'erreurs 500** depuis la même adresse (l'injection casse la requête SQL) ;
- des **tailles de réponse qui alternent** entre deux valeurs : l'injection à
  l'aveugle du niveau 2, vue du côté du défenseur ;
- des **refus d'accès en série** sur des identifiants successifs : un IDOR en
  cours d'exploration. Dans Bastion, chaque refus produit un événement
  `authz.denied` dans le journal d'audit, et le runbook (`docs/runbook.md`) dit
  quoi faire quand ils se répètent.

## À retenir

- Le journal d'accès montre l'URL, rarement le corps : il faut aussi les journaux applicatifs.
- Décoder avant de comparer ; comparer sans tenir compte de la casse.
- L'agent utilisateur ne prouve rien.
- Signatures et comportement se complètent : l'un attrape le connu, l'autre l'inhabituel.
