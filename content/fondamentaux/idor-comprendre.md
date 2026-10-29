# Comprendre l'IDOR

**IDOR** (*Insecure Direct Object Reference*), appelée **BOLA** (*Broken Object
Level Authorization*) dans l'OWASP API Security Top 10, est la faille
**n°1** des API. Elle est simple, fréquente et souvent critique.

## Le principe

Une API expose des objets par leur identifiant :

```http
GET /v1/notes/1042
Authorization: Bearer <jeton de Mallory>
```

Le serveur authentifie Mallory, charge la note 1042… et la lui renvoie, **sans
vérifier qu'elle lui appartient**. Mallory n'a plus qu'à essayer 1041, 1043, etc.

Mallory est bien authentifiée : le problème est une **autorisation par objet**
manquante (revois la leçon *Authentification et autorisation*).

## Pourquoi c'est si fréquent

Le code vulnérable a l'air parfaitement normal :

```ts
// VULNÉRABLE : l'objet est chargé par son seul identifiant
app.get('/notes/:id', requireAuth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).end();
  res.json(note);
});
```

Rien ne choque à la relecture. Les tests « normaux » passent : chaque
utilisateur lit ses propres notes. Seul un test **avec deux comptes** révèle
le problème.

## Les UUID ne suffisent pas

Remplacer `1042` par un UUID aléatoire rend les identifiants impossibles à
deviner, mais ne corrige rien : un identifiant finit toujours par fuiter
(lien partagé, capture d'écran, journaux, autre endpoint qui le liste). La
défense, c'est le **contrôle d'accès**, pas le secret de l'identifiant.

## L'impact

Selon l'objet : lecture de données personnelles (confidentialité),
modification de la commande d'un autre (intégrité), suppression du compte d'un
autre (disponibilité). Des fuites massives de données ont eu exactement cette
cause.

## À retenir

- IDOR = le serveur ne vérifie pas que l'objet appartient à l'utilisateur.
- Le code vulnérable a l'air normal : il faut le tester avec deux comptes.
- Des identifiants imprévisibles ralentissent l'attaque, ils ne la corrigent pas.
