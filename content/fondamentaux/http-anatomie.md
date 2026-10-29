# Anatomie d'une requête HTTP

HTTP est un protocole texte : le client envoie une requête, le serveur renvoie
une réponse. Voici une vraie requête vers l'API Bastion :

```http
PUT /v1/notes/3f1c9a2e-8b7d-4c1e-9f00-2a6b5c4d3e21 HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6ImF0K2p3dCJ9...
Content-Type: application/json

{"title":"courses","body":"lait, pain","version":1}
```

| Partie | Exemple | Rôle |
|---|---|---|
| Méthode | `PUT` | L'action : lire (`GET`), créer (`POST`), remplacer (`PUT`), supprimer (`DELETE`) |
| Chemin | `/v1/notes/3f1c…` | La ressource visée, souvent avec son identifiant |
| En-têtes | `Authorization`, `Content-Type` | Les métadonnées : qui je suis, quel format j'envoie |
| Corps | `{"title": …}` | Les données envoyées |

## Tout ce qui vient du client est contrôlé par l'attaquant

C'est la phrase la plus importante de ce parcours. Méthode, chemin, paramètres,
en-têtes, corps : **tout** peut être modifié à la main, avec `curl`, un proxy
comme Burp Suite ou quelques lignes de script. Le navigateur n'est qu'un client
parmi d'autres.

Essaie avec Bastion lancé en local :

```bash
curl -i http://localhost:3000/v1/me
```

Tu obtiens un `401` : pas de jeton, pas d'accès.

## Les codes de statut

| Code | Sens | Exemple dans Bastion |
|---|---|---|
| `200` / `201` / `204` | Succès | Note lue, créée, supprimée |
| `400` | Requête invalide | Champ inconnu dans le JSON |
| `401` | Non authentifié | Jeton absent, expiré ou falsifié |
| `403` | Authentifié, mais pas autorisé | Un utilisateur simple sur une route admin |
| `404` | Introuvable | Note inexistante… ou appartenant à quelqu'un d'autre |
| `429` | Trop de requêtes | Limitation de débit, verrouillage après échecs |

Le `404` pour la note d'un autre est un choix délibéré. Tu verras pourquoi
dans le module IDOR.

## À retenir

- Une requête = méthode + chemin + en-têtes + corps.
- Chaque octet de la requête est sous le contrôle de l'attaquant.
- Les codes de statut racontent ce que le serveur a décidé.
