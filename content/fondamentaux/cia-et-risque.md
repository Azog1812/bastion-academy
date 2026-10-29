# Confidentialité, intégrité, disponibilité

Avant de parler d'attaques, il faut savoir **ce qu'on protège**. Presque tout en
sécurité se ramène à trois propriétés, souvent appelées la triade **CIA**
(*Confidentiality, Integrity, Availability*).

## Les trois propriétés

| Propriété | Question | Exemple d'atteinte |
|---|---|---|
| **Confidentialité** | Seules les bonnes personnes peuvent-elles lire l'information ? | Une base de données clients publiée sur un forum |
| **Intégrité** | L'information est-elle exacte et non modifiée à notre insu ? | Un IBAN remplacé dans une facture par un attaquant |
| **Disponibilité** | L'information et le service sont-ils accessibles quand on en a besoin ? | Un rançongiciel qui chiffre tous les serveurs |

On ajoute souvent la **traçabilité** : pouvoir dire après coup *qui a fait quoi*.
Dans Bastion, c'est le rôle du journal d'audit chaîné par HMAC : modifier une
ligne passée casse toute la chaîne, et `verify()` désigne la première ligne altérée.

## Vulnérabilité, menace, risque

Ces trois mots ne sont pas synonymes :

- une **vulnérabilité** est une faiblesse : un mot de passe par défaut, un
  contrôle d'accès oublié ;
- une **menace** est ce qui peut l'exploiter : un attaquant opportuniste, un
  employé mécontent, un script automatisé ;
- le **risque** combine les deux, pondérés par l'**impact** (ce qu'on perd) et la
  **vraisemblance** (la probabilité que ça arrive).

Une vulnérabilité sans menace crédible ni impact est un risque faible. Une
faille triviale sur des données de santé est un risque majeur. C'est ce
raisonnement qui permet de **prioriser**, et c'est exactement ce que fait le
[modèle de menace de Bastion](https://github.com/Azog1812/bastion-academy/blob/main/docs/threat-model.md) :
chaque menace y est reliée à un contrôle et à un test.

## À retenir

- On protège la confidentialité, l'intégrité et la disponibilité.
- Un risque = une menace × une vulnérabilité × un impact.
- La sécurité est une affaire de **priorités**, pas de perfection.
