# Authentification et autorisation

Ces deux mots se ressemblent, et les confondre est à l'origine d'une grande
partie des failles applicatives.

## Deux questions différentes

- **Authentification** : *qui es-tu ?* Le serveur vérifie une preuve d'identité
  (mot de passe, clé, code à usage unique) et délivre une session ou un jeton.
- **Autorisation** : *as-tu le droit de faire **cette** action sur **cette**
  ressource ?* Elle se pose **à chaque requête**, après l'authentification.

Être authentifié ne donne aucun droit en soi. Alice est bien Alice, mais ça ne
l'autorise pas à lire les notes de Bob.

## Les niveaux d'autorisation

1. **Par fonction** : « seuls les administrateurs peuvent lire le journal
   d'audit ». Dans Bastion, c'est `requireRole('admin')`.
2. **Par objet** : « tu ne peux modifier que *tes* notes ». C'est le plus
   souvent oublié, et c'est l'objet du module IDOR de ce parcours.
3. **Par propriété** : « tu peux modifier le titre de ton compte, pas ton
   rôle ». Bastion le garantit avec des schémas stricts qui rejettent tout
   champ inconnu (protection contre l'*assignation de masse*).

## La règle d'or : le serveur décide

Masquer un bouton dans l'interface n'est **pas** un contrôle d'accès. Un
attaquant n'utilise pas ton interface : il envoie ses propres requêtes HTTP,
avec les outils qu'il veut. Toute vérification qui n'a lieu que dans le
navigateur peut être contournée.

> Dans Bastion Academy, même le verrouillage des modules et la correction des
> quiz sont faits côté serveur. Tu peux modifier le front-end autant que tu
> veux : tu ne débloqueras rien.

## À retenir

- Authentification = identité ; autorisation = droits, à chaque requête.
- L'autorisation se fait par fonction, par objet et par propriété.
- Seul le serveur fait foi.
