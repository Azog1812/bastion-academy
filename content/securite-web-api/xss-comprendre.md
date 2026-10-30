# Comprendre les trois familles de XSS

Le **cross-site scripting** (XSS) permet à un attaquant d'exécuter son JavaScript
**dans la page d'une victime**, avec les droits de la victime sur le site. Le
navigateur ne peut pas distinguer ce script de celui de l'application : pour lui,
tout vient du même site.

## Les trois familles

| Famille | Où vit la charge | Exemple |
|---|---|---|
| **Réfléchie** | Dans la requête (URL, formulaire), renvoyée aussitôt dans la page | Un lien piégé `/recherche?q=…` envoyé par e-mail |
| **Stockée** | Dans la base de données, servie à chaque visiteur | Un commentaire ou un pseudo contenant du HTML |
| **Basée sur le DOM** | Uniquement côté client : le JavaScript de la page insère une donnée dans le DOM | `el.innerHTML = location.hash` |

La XSS stockée est souvent la plus grave : une seule charge touche **tous** les
visiteurs, administrateurs compris.

## Le cœur du problème : du texte devient du HTML

```js
// VULNÉRABLE : la chaîne est interprétée comme du HTML
resultat.innerHTML = 'Résultats pour : ' + recherche;
```

Si `recherche` vaut `<img src=x onerror=alert(document.domain)>`, le navigateur
crée une image, échoue à la charger… et exécute l'attribut `onerror`. Pas
besoin de balise `script` : les vecteurs sont innombrables.

## Ce que peut faire le script injecté

Tout ce que la victime peut faire sur le site : lire ce que la page affiche,
envoyer des requêtes en son nom, modifier la page pour lui faire saisir son mot
de passe. Il peut aussi lire tout ce qui est accessible au JavaScript, en
particulier un jeton stocké dans `localStorage`.

Il ne peut **pas** lire un cookie marqué `HttpOnly`. C'est pour cette raison que
Bastion Academy garde son jeton de session longue durée dans un cookie
`HttpOnly` et son jeton d'accès uniquement en mémoire.

## À toi de jouer : attaquer Bastion Academy

Ouvre Bastion Academy dans ton navigateur, connecte-toi, puis ouvre les outils
de développement (F12), onglet **Console**. Essaie d'injecter du HTML comme le
ferait une faille :

```js
document.querySelector('main').innerHTML = '<img src=x onerror=alert(1)>';
```

Tu obtiens une erreur `TypeError` qui mentionne *TrustedHTML*, et rien n'est
inséré. Essaie aussi :

```js
document.cookie;          // le cookie de session n'apparaît pas (HttpOnly)
localStorage.length;      // 0 : aucun jeton stocké côté client
```

Tu viens de constater, dans un vrai navigateur, les défenses que la leçon
suivante explique.

## À retenir

- XSS = du texte contrôlé par l'attaquant devient du code dans la page.
- Réfléchie, stockée ou DOM : la cause est toujours une insertion non sûre.
- Un jeton lisible par JavaScript est un jeton volable par XSS.
