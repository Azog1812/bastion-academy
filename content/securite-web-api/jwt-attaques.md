# Attaquer des JWT

Tu as vu au niveau 1 qu'un JWT est **signé, pas chiffré**. Cette leçon passe de
l'autre côté : comment un attaquant tente de forger ou de détourner un jeton.

## Le catalogue des attaques

| Attaque | Principe | Ce qui la rend possible |
|---|---|---|
| **`alg: none`** | Un jeton dont l'en-tête dit « pas de signature », avec une signature vide | Le serveur choisit l'algorithme d'après l'en-tête du jeton |
| **Confusion d'algorithme** | Le serveur attend du RS256 (clé publique/privée). L'attaquant signe en HS256 en utilisant **la clé publique** comme secret HMAC | Même cause : l'algorithme vient du jeton |
| **Secret faible** | Un jeton HS256 permet de tester des secrets hors ligne, sans limite de vitesse | Un secret court ou tiré d'un dictionnaire |
| **Modification du contenu** | Changer `"role":"user"` en `"admin"` | Une signature mal ou pas vérifiée |
| **Jeton éternel** | Un jeton volé reste valide indéfiniment | Pas d'`exp`, ou pas de révocation |
| **Mauvais destinataire** | Un jeton émis pour un autre service est accepté ici | `iss` et `aud` non vérifiés |

Le point commun des deux premières : **faire confiance au jeton pour savoir
comment vérifier le jeton**. C'est comme laisser un visiteur choisir le
contrôle qu'il va passer.

## À toi de jouer : forger un jeton contre Bastion

Lance Bastion en local et crée un compte (voir le README). Puis fabrique un
jeton `alg: none` qui prétend être administrateur :

```bash
B=http://localhost:3000
H=$(printf '{"alg":"none","typ":"at+jwt"}' | base64 | tr -d '=' | tr '/+' '_-')
P=$(printf '{"sub":"x","role":"admin","tv":0}' | base64 | tr -d '=' | tr '/+' '_-')
curl -i $B/v1/admin/audit -H "authorization: Bearer $H.$P."
```

Réponse : `401`, *Authentication required*. Le jeton n'est même pas arrivé jusqu'à
la vérification cryptographique : le middleware `authenticate`
(`src/http/middleware.ts`) exige trois parties non vides, et une signature vide
ne passe pas ce premier filtre. Et s'il le passait, la liste blanche
d'algorithmes le refuserait (leçon suivante). Deux contrôles indépendants, encore.

Essaie maintenant de modifier ton **vrai** jeton. Récupère un jeton d'accès
valide, décode sa partie centrale, remplace `"role":"user"` par
`"role":"admin"`, réencode-la et renvoie le jeton avec la signature d'origine.
Réponse : `401`, *Invalid access token* cette fois. La signature HMAC couvre l'en-tête et le contenu : un
seul octet modifié, et elle ne correspond plus.

## Le secret faible, ou pourquoi la longueur compte

Un jeton HS256 intercepté suffit pour tester des millions de secrets par seconde
avec des outils comme hashcat, sans jamais toucher le serveur. Si le secret est
`secret123`, il tombe en quelques secondes, et l'attaquant peut alors signer
**n'importe quel** jeton.

Bastion génère ses secrets avec `node dist/cli.js gen-secrets` : 32 octets
aléatoires (256 bits). Et la configuration refuse de démarrer si le secret est
trop court ou ressemble à une valeur d'exemple (`src/config.ts`).

## À retenir

- Ne jamais laisser le jeton décider de l'algorithme de vérification.
- Un secret HMAC doit être long et aléatoire, jamais choisi par un humain.
- Un jeton doit expirer, viser un destinataire précis, et pouvoir être révoqué.
