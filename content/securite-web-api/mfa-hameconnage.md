# Hameçonner un second facteur

Un mot de passe volé ne suffit plus quand le compte demande un code à 6 chiffres
(TOTP). Les attaquants l'ont compris depuis longtemps : ils ne volent plus le
mot de passe, ils volent **la session entière**, en direct.

## L'attaque de l'homme du milieu (AiTM)

Des outils comme Evilginx ou Modlishka placent un **proxy inverse** entre la
victime et le vrai site. La victime reçoit un lien vers `bastion-academy.example`
au lieu de `localhost:3000`. Le proxy lui montre le vrai site, page par page :

1. La victime tape son e-mail et son mot de passe : le proxy les transmet au vrai
   site, qui demande le code à 6 chiffres.
2. La victime tape le code : le proxy le transmet aussitôt. Le code est valide
   30 secondes, le relais prend une fraction de seconde.
3. Le vrai site ouvre la session : le proxy garde le **cookie de session** et
   laisse la victime continuer sans rien remarquer.

Le TOTP n'a pas échoué : il a été **relayé**. Rien dans le code ne dit sur quel
site il a été tapé. Bastion limite déjà les dégâts (un code ne sert qu'une fois,
les échecs comptent dans le verrouillage), mais un code relayé une seule fois
suffit à l'attaquant.

## Ce qui rend une passkey différente

Une passkey (WebAuthn, FIDO2) est une paire de clés. La clé privée reste dans
l'authentificateur (clé USB, téléphone, puce de l'ordinateur). Pour se connecter,
le site envoie un défi aléatoire, et l'authentificateur le **signe**. Deux
informations sont signées avec lui, et l'utilisateur ne peut pas les changer :

- l'**origine** de la page, écrite par le navigateur (`http://localhost:3000`, ou
  `https://bastion-academy.example` sur le site piégé) ;
- le **RP ID**, le domaine pour lequel la clé a été créée : l'authentificateur ne
  propose même pas la clé sur un autre domaine.

Le proxy peut relayer la signature, mais elle dit « signé pour
`bastion-academy.example` ». Le vrai serveur la refuse. Il n'y a **rien à
relayer** qui fonctionne : c'est pour cela que le NIST classe les passkeys parmi
les authentificateurs *résistants à l'hameçonnage*, contrairement aux codes TOTP,
SMS ou notifications push.

## Les autres attaques, et leurs parades

| Attaque | Parade côté serveur |
|---|---|
| Rejouer une ancienne signature | Le défi est aléatoire et à usage unique |
| Présenter la clé d'un autre compte | La liste des clés autorisées et la recherche en base sont propres au compte |
| Cloner une clé de sécurité | Le compteur de signatures doit augmenter ; s'il recule, deux copies existent |
| Enregistrer sa propre clé sur le compte d'une victime | L'ajout d'une passkey exige le mot de passe, dans une session déjà passée au second facteur |

## À retenir

- Un code TOTP ou SMS se relaie en temps réel : il ne protège pas contre un proxy
  d'hameçonnage.
- Une passkey signe un défi **avec l'origine et le domaine** : une signature
  obtenue sur un faux site ne vaut rien sur le vrai.
- Le serveur doit vérifier l'origine, le RP ID, le défi, la signature et le compteur :
  oublier une seule vérification rouvre la porte.
