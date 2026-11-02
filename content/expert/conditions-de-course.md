# Les conditions de course

Une carte cadeau ne s'utilise qu'une fois. Le code le vérifie : « la carte
est-elle déjà utilisée ? Non ? Alors je crédite, puis je la marque utilisée. »
Chaque ligne est correcte. Et pourtant, envoyée **vingt fois en même temps**,
la même carte peut être créditée vingt fois.

C'est une **condition de course** (*race condition*, CWE-362) : le résultat
dépend de l'ordre dans lequel s'exécutent des opérations concurrentes. Aucun
scanner ne la trouve en envoyant une requête à la fois, et aucune revue de code
ligne par ligne ne la voit si l'on ne pense pas au temps qui passe entre deux
lignes.

## Vérifier, puis utiliser : le TOCTOU

La forme la plus courante s'appelle **TOCTOU** (*Time Of Check to Time Of
Use*) : entre le moment où l'on vérifie une condition et celui où l'on agit en
conséquence, l'état a pu changer.

```js
const carte = await db.lireCarte(code);        // vérification
if (carte.utilisee) return refuser();
await banque.verifierFraude(code);              // ← la fenêtre de course
await db.crediter(compte, carte.montant);       // utilisation
await db.marquerUtilisee(code);
```

Vingt requêtes arrivent ensemble. Toutes lisent `utilisee = false` avant que la
première ait fini : toutes créditent. Plus la fenêtre est longue (un appel
réseau, une requête lente), plus l'attaque est facile. Mais même sans `await`
explicite, deux processus ou deux serveurs derrière un répartiteur de charge
suffisent.

## Où chercher

Partout où une règle métier dit « une seule fois » ou « pas plus de » :

| Cible | Limite contournée |
|---|---|
| Codes promo, cartes cadeaux, parrainages | Usage unique |
| Virements, retraits, achats | Solde suffisant |
| Votes, avis, inscriptions | Un par personne |
| Codes de vérification, MFA | Nombre d'essais, usage unique du code |
| Jetons de rafraîchissement | Rotation : l'ancien ne doit plus servir |

James Kettle (PortSwigger) a appelé ces cas des **dépassements de limite**
(*limit overrun*) et a présenté en 2023 l'**attaque en un seul paquet**
(*single-packet attack*) : avec HTTP/2, on prépare vingt requêtes, on retient
leur dernier octet, puis on les libère dans un même paquet TCP. Elles arrivent
au serveur à moins d'une milliseconde d'écart, et la gigue du réseau ne gâche
plus l'attaque. Burp Suite l'intègre (« envoyer le groupe en parallèle »).

## Se défendre : rendre l'opération atomique

Ajouter un délai, un verrou en mémoire ou « vérifier deux fois » ne suffit pas :
le premier serveur ne voit pas le verrou du second. La vérification et
l'écriture doivent devenir **une seule opération indivisible**, et c'est la base
de données qui l'arbitre :

```sql
UPDATE cartes SET utilisee = 1
 WHERE code = ? AND utilisee = 0
RETURNING montant;
```

Une seule requête peut passer `utilisee` de 0 à 1 ; les autres ne modifient
aucune ligne et repartent les mains vides. C'est un **compare-and-set**.
D'autres outils existent : contrainte d'unicité, transaction en isolation
`SERIALIZABLE`, `SELECT … FOR UPDATE`, clé d'idempotence.

## Ce que fait Bastion

L'invariant 5 l'impose : « l'atomicité vient de la base, jamais de la boucle
d'événements ». Bastion revendique le jeton avec un `UPDATE`
conditionnel (`… WHERE id = ? AND revoked_at IS NULL`) : une seule requête
modifie la ligne, la perdante est traitée comme un rejeu et toute la famille de
jetons est révoquée (`src/services/auth-service.ts`). Même principe pour la
MFA : un pas de temps TOTP est revendiqué par compare-and-set avant que le code
compte (invariant 14). Le test `authentication.test.ts` envoie deux
rafraîchissements **en parallèle** avec le même jeton et vérifie qu'un seul
réussit.

Quand la vérification et l'écriture ne tiennent pas en une seule requête, elles
passent dans **une transaction** (`db.transaction()`, ADR 0020) : la tête de la
chaîne d'audit et l'entrée suivante, ou « est-ce ton dernier second facteur ? » puis
la suppression. Pour prouver qu'une course est vraiment fermée, il faut un test qui
**échoue sans la protection**. Or une base SQLite dans le processus répond si vite
que deux requêtes ne s'entremêlent presque jamais : le test passerait même avec le
bug. Bastion teste donc ses courses contre `withLatency()` (`test/helpers.ts`), une
base qui laisse la main avant chaque requête, comme le ferait un serveur distant.

Bastion s'est fait prendre lui-même. Le compteur d'échecs de connexion était bien
incrémenté de façon atomique, mais le verrou du compte était posé par une **deuxième**
requête. Huit mauvais mots de passe envoyés ensemble passaient tous entre les deux :
huit essais jugés au lieu de cinq. Toute la suite de tests tourne aussi sur un vrai
PostgreSQL (ADR 0021), et c'est là que le test l'a montré. Le comptage et le verrou
tiennent désormais dans une seule transaction. Morale : une opération atomique ne
protège que ce qu'elle contient.

## À retenir

- Une condition de course exploite le temps entre la vérification et l'action (TOCTOU).
- Cibles : tout ce qui est « à usage unique » ou « limité » ; on attaque en parallèle.
- Un délai ou un verrou en mémoire ne protège pas : la vérification et l'écriture doivent être atomiques, côté base.
- Tester une limite, c'est envoyer les requêtes ensemble, pas l'une après l'autre.
