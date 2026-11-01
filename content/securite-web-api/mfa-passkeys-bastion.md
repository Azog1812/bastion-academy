# Les passkeys dans le code de Bastion

Bastion vérifie les passkeys lui-même, sans bibliothèque, avec `node:crypto`
(ADR 0016). Toute la vérification tient dans `src/crypto/webauthn.ts` ; chaque
contrôle répond à une attaque de la leçon précédente.

## Les données signées par le navigateur

```ts
if (c.type !== type) throw new WebAuthnError(`expected a ${type} ceremony`);
if (typeof c.challenge !== 'string' || !same(Buffer.from(c.challenge, 'base64url'), challenge)) throw ...
if (typeof c.origin !== 'string' || !rp.origins.includes(c.origin)) throw new WebAuthnError('origin not allowed');
if (c.crossOrigin === true) throw new WebAuthnError('cross-origin ceremonies are refused');
```

- `type` : une réponse d'**enregistrement** ne peut pas servir de **connexion**, et
  inversement.
- `challenge` : comparé en temps constant au défi émis par le serveur. Ce défi est
  aléatoire (32 octets), stocké haché, **supprimé dès qu'il est présenté**, valable
  5 minutes, et lié à l'étape de connexion qui l'a demandé.
- `origin` : comparaison **exacte** avec la liste configurée
  (`WEBAUTHN_ORIGINS`). C'est ici qu'échoue le proxy d'hameçonnage.

## Les données signées par l'authentificateur

```ts
if (!same(auth.rpIdHash, sha256(Buffer.from(rp.id)))) throw new WebAuthnError('assertion for another RP ID');
if (!(auth.flags & FLAG_UP)) throw new WebAuthnError('user presence flag not set');
```

Le hachage du RP ID prouve que la clé a été créée pour `localhost` (ou le domaine
configuré). Le drapeau *user present* prouve qu'un humain a touché la clé : un
logiciel malveillant ne peut pas faire signer en silence.

Puis la signature, sur `authenticatorData || SHA-256(clientDataJSON)`, avec la
clé publique enregistrée : ES256 (P-256), Ed25519 ou RS256 ; aucun autre
algorithme n'est accepté.

## Le compteur contre le clonage

```ts
if ((auth.signCount !== 0 || credential.signCount !== 0) && auth.signCount <= credential.signCount) {
  throw new CloneWarning('signature counter did not increase');
}
```

Une clé de sécurité compte ses signatures. Si le compteur présenté ne dépasse pas
celui que le serveur a vu, une **copie** de la clé existe : la connexion est
refusée et l'événement `passkey.clone_detected` part dans le journal d'audit
(et dans Wazuh, règle de niveau 12). Les passkeys synchronisées entre appareils
ne comptent pas (toujours 0) : pas de fausse alerte. La mise à jour du compteur
est un *compare-and-set* : deux connexions simultanées avec le même compteur ne
passent pas toutes les deux.

## Lire des données hostiles

Les réponses WebAuthn contiennent du **CBOR**, un format binaire. Il est lu
*avant* toute vérification de signature : c'est donc une entrée d'attaquant.
Le décodeur de Bastion (`src/crypto/cbor.ts`) refuse les longueurs indéfinies,
les étiquettes, les nombres flottants et les clés de dictionnaire en double, vérifie
chaque longueur annoncée contre les octets restants **avant** d'allouer, et
plafonne la profondeur et le nombre d'éléments. Un en-tête qui annonce 2⁶⁴ octets
échoue immédiatement.

## Se connecter sans mot de passe

Une passkey peut aussi remplacer le mot de passe **et** le second facteur
(ADR 0017). Le bouton « Se connecter avec une passkey » demande un défi qui ne
nomme aucun compte : le navigateur propose les passkeys qu'il garde pour ce site,
et l'authentificateur renvoie le *user handle*, l'identifiant de compte enregistré
avec la clé. Trois règles rendent ce raccourci sûr :

```ts
// La clé doit appartenir au compte que le user handle désigne.
.prepare('SELECT ... FROM passkeys WHERE user_id = ? AND credential_id = ?').get(userId, ...)
// Seule, la passkey doit avoir vérifié un code PIN ou une biométrie.
if (requireUserVerification && !(auth.flags & FLAG_UV)) throw new UserVerificationRequired(...)
```

- Ta clé valide présentée avec l'identifiant d'un autre compte ne trouve **rien**.
- Le drapeau *user verified* (UV) est exigé : sans lui, une clé USB trouvée par
  terre suffirait à entrer. Avec lui, la passkey réunit deux facteurs (ce que tu
  possèdes, et ton PIN ou ton empreinte) : c'est ce que le NIST appelle un
  authentificateur cryptographique multifacteur.
- Chaque échec reçoit la même réponse, `Passkey not recognised`, et **ne compte pas**
  comme un échec de connexion : le user handle vient de la requête, donc compter
  donnerait à n'importe qui un bouton pour verrouiller n'importe quel compte.
  Inversement, un compte verrouillé par quelqu'un qui devine le mot de passe
  reste ouvert à sa passkey : une signature ne se devine pas.

## La récupération de compte, le maillon faible

Une connexion forte ne vaut que ce que vaut le chemin qui la contourne. Chez
Bastion, une passkey perdue se remplace avec une autre passkey, ou avec le mot de
passe **plus** un code TOTP ou un code de secours. Tout perdu ? Seul l'opérateur,
sur la machine, peut réinitialiser le compte (`node dist/cli.js recover-account`) :
tous les facteurs et toutes les sessions sont supprimés, y compris la passkey
qu'un attaquant aurait pu ajouter. Jamais de lien par e-mail ni de question
secrète : le compte serait alors aussi faible que la boîte mail.

## Ce que Bastion ne vérifie pas, exprès

L'**attestation** (quel modèle d'authentificateur a créé la clé) n'est pas
demandée : une plateforme d'apprentissage n'impose pas de marque de clé, et ne pas
la demander protège la vie privée de l'utilisateur. Une banque ou une
administration peut, elle, exiger des authentificateurs certifiés.

## Essaie

1. Ouvre Bastion à l'adresse `http://localhost:3000` (pas `127.0.0.1` : une adresse
   IP ne peut pas être un RP ID), page **Compte**, et ajoute une passkey.
2. Déconnecte-toi, reconnecte-toi : après le mot de passe, choisis « Utiliser une
   passkey ».
3. Déconnecte-toi encore et choisis « Se connecter avec une passkey », sans saisir
   d'e-mail.
4. Lis `test/security/passkeys.test.ts` et `test/security/passkey-login.test.ts` :
   chaque attaque de ces deux leçons y est jouée par un authentificateur logiciel,
   et refusée.

## À retenir

- Origine, RP ID, défi à usage unique, présence, signature, compteur : six
  contrôles, chacun contre une attaque précise.
- Le CBOR est lu avant la signature : un décodeur strict et borné est une
  mesure de sécurité.
- Supprimer le **dernier** second facteur exige le mot de passe **et** un code de
  secours, comme désactiver le TOTP.
