# Comprendre le CSRF

Le **Cross-Site Request Forgery** fait exécuter à ton navigateur une action sur
un site où tu es connecté, depuis un **autre** site, sans que tu le saches.

## Le mécanisme

Tu es connecté à ta banque, qui t'authentifie par un cookie. Tu visites ensuite
un site piégé qui contient ce formulaire, envoyé automatiquement :

```html
<form action="https://banque.example/virement" method="POST">
  <input type="hidden" name="vers" value="IBAN-de-l-attaquant">
  <input type="hidden" name="montant" value="5000">
</form>
<script>document.forms[0].submit()</script>
```

Le navigateur envoie la requête à la banque **avec ton cookie**, car il joint
automatiquement les cookies d'un site à toute requête vers ce site. Le serveur
voit une requête authentifiée et légitime en apparence. L'attaquant ne lit pas
la réponse : il n'en a pas besoin, l'action est faite.

## Les conditions d'une attaque CSRF

1. L'authentification repose sur quelque chose que le navigateur envoie **tout
   seul** : un cookie, ou une authentification HTTP Basic.
2. L'action a un effet (virement, changement d'e-mail, suppression).
3. L'attaquant peut prédire tous les paramètres de la requête.

## Pourquoi les jetons Bearer y échappent

L'API de Bastion authentifie la plupart des requêtes avec l'en-tête
`Authorization: Bearer <jeton>`. Le navigateur n'ajoute **jamais** cet en-tête
de lui-même : c'est le code JavaScript de l'application qui le fait. Un site
tiers ne peut pas le faire ajouter, puisqu'il ne connaît pas le jeton. La
condition 1 tombe, et avec elle le CSRF classique.

Mais l'interface web de Bastion Academy utilise **un** cookie : celui qui
contient le jeton de rafraîchissement, pour qu'il soit hors de portée du
JavaScript (voir le module XSS). Les trois routes qui lisent ce cookie,
`/v1/session/login`, `/refresh` et `/logout`, sont donc exposées au CSRF par
nature. La leçon suivante montre comment elles sont protégées.

## Un piège à connaître : XSS bat CSRF

Si un site a une faille XSS, toutes les protections CSRF tombent : le script
injecté s'exécute **sur** le site, il peut lire les jetons anti-CSRF et envoyer
les requêtes qu'il veut. C'est pour cette raison que ce module vient après le
module XSS.

## À retenir

- CSRF = un autre site utilise ton authentification automatique.
- Cookies et authentification Basic sont concernés ; les en-têtes Bearer, non.
- Une XSS annule les défenses CSRF.
