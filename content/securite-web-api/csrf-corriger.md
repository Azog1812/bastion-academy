# Se défendre du CSRF

Il existe plusieurs défenses. Les meilleures combinaisons en empilent plusieurs,
indépendantes.

## Les défenses classiques

| Défense | Principe | Limite |
|---|---|---|
| **Cookie `SameSite`** | Le navigateur n'envoie pas le cookie sur une requête initiée par un autre site | `Lax` laisse passer les navigations GET ; certains vieux navigateurs l'ignorent |
| **Jeton anti-CSRF** | Un secret aléatoire, présent dans la page, que la requête doit renvoyer | À gérer partout, et annulé par une XSS |
| **Vérifier `Origin`** | Le navigateur indique l'origine de la requête ; on refuse les origines étrangères | L'en-tête n'est pas toujours présent |
| **Exiger un en-tête ou un type de contenu** | Un formulaire HTML ne peut envoyer ni en-tête personnalisé ni JSON | Repose sur la politique CORS du serveur |

## Le cas de Bastion Academy

Seules trois routes lisent le cookie de session : `/v1/session/login`,
`/v1/session/refresh` et `/v1/session/logout`. Toutes les autres utilisent un
jeton Bearer. La surface CSRF est donc réduite à **trois routes**, et ce n'est
pas un hasard : c'est un choix documenté dans l'ADR 0007.

Ces trois routes cumulent trois barrières (`src/http/session.ts`) :

1. **`SameSite=Strict`** sur le cookie : venant d'un autre site, la requête
   arrive sans cookie.
2. **JSON obligatoire** : un formulaire HTML ne sait envoyer que du
   `application/x-www-form-urlencoded`, du `multipart/form-data` ou du
   `text/plain`. Bastion répond `415` à tout le reste. Et un autre site qui
   tenterait un `fetch` en JSON déclencherait une requête de contrôle CORS
   (*preflight*) que Bastion n'autorise pour aucune origine.
3. **Vérification de `Origin`** : si la requête annonce une origine étrangère,
   elle est refusée avec un `403`, avant même de lire le cookie.

Le cookie lui-même est déclaré ainsi :

```text
__Host-bastion_rt=…; Max-Age=604800; Path=/; Secure; HttpOnly; SameSite=Strict
```

Le préfixe `__Host-` oblige le navigateur à refuser ce cookie s'il n'est pas
`Secure`, s'il a un attribut `Domain` ou un autre `Path` que `/`. Un sous-domaine
compromis ne peut donc pas l'écraser (*cookie tossing*).

## Vérifie-le toi-même

Avec Bastion lancé en local, simule une requête venant d'un autre site :

```bash
curl -i -X POST http://localhost:3000/v1/session/refresh \
  -H 'Origin: https://site-piege.example' \
  -H 'content-type: application/json' -d '{}'
```

Réponse : `403`, *Cross-origin request refused*. Essaie maintenant comme un
formulaire HTML :

```bash
curl -i -X POST http://localhost:3000/v1/session/refresh \
  -H 'content-type: application/x-www-form-urlencoded' -d 'x=1'
```

Réponse : `415`. Le test `test/security/web.test.ts` (*rejects cross-origin and
non-JSON requests on cookie routes*) rejoue ces attaques et vérifie qu'après
chacune, la vraie session fonctionne toujours.

## À retenir

- Réduire le nombre de routes à cookie, c'est réduire la surface CSRF.
- `SameSite=Strict`, JSON obligatoire et contrôle d'`Origin` : trois barrières
  indépendantes.
- Le préfixe `__Host-` protège le cookie contre l'écrasement par un sous-domaine.
