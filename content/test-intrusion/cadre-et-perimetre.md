# Le test d'intrusion : cadre, périmètre, méthode

Un test d'intrusion (*pentest*) n'est pas « pirater avec la permission ». C'est
une **prestation** : un client mandate un auditeur pour trouver ce qu'un
attaquant trouverait, dans un cadre écrit, et pour lui expliquer comment le
corriger. Sans ce cadre, les mêmes gestes sont un délit.

## Le cadre légal

En France, accéder ou se maintenir frauduleusement dans un système (article
323-1 du Code pénal), l'entraver ou en modifier les données (323-2, 323-3) est
puni d'emprisonnement et d'amende. L'article 323-3-1 vise même la **détention**
d'outils conçus pour ces infractions, sauf motif légitime, comme la recherche
ou la sécurité informatique.

Ce qui rend un test légal, c'est l'**autorisation écrite** de celui qui a le
pouvoir de la donner, sur un **périmètre** précis. Un e-mail d'un stagiaire ne
suffit pas, et un serveur hébergé chez un tiers (cloud, prestataire) peut
exiger aussi l'accord de l'hébergeur.

## La convention d'audit

Avant la première commande, l'auditeur et le client signent une convention
(*rules of engagement*) qui fixe :

| Élément | Exemple |
|---|---|
| **Périmètre** | « www.exemple.test et l'API api.exemple.test ; l'intranet est exclu » |
| **Dates et horaires** | Heures ouvrées uniquement, pour qu'une équipe puisse réagir |
| **Techniques exclues** | Déni de service, ingénierie sociale, attaques physiques |
| **Contacts d'urgence** | Qui appeler si un service tombe ou si une vraie intrusion est découverte |
| **Données** | Que faire des données sensibles rencontrées ; destruction en fin de mission |

En France, l'ANSSI qualifie les prestataires d'audit (**PASSI**) : pour les
administrations et les opérateurs critiques, c'est souvent une obligation.

## Boîte noire, grise, blanche

- **Boîte noire** : l'auditeur part de rien, comme un attaquant externe.
- **Boîte grise** : il reçoit un compte utilisateur, comme un client ou un employé.
- **Boîte blanche** : il a accès au code et à l'architecture. C'est le plus
  efficace pour un temps donné : on ne paie pas des jours de découverte.

## Une méthode, pas une improvisation

Le **PTES** (*Penetration Testing Execution Standard*) découpe la mission en
sept phases : échanges préalables, collecte d'informations, modélisation des
menaces, analyse des vulnérabilités, exploitation, post-exploitation, rapport.
Pour le web, l'**OWASP WSTG** (*Web Security Testing Guide*) liste les tests à
mener, catégorie par catégorie. Une méthode garantit qu'on n'oublie rien, et
qu'on peut **prouver** qu'on a testé ce qu'on dit avoir testé.

## À retenir

- Pas d'autorisation écrite, pas de test : c'est la seule différence avec un délit.
- La convention fixe périmètre, dates, techniques exclues, contacts, données.
- Boîte noire, grise ou blanche : un choix de réalisme contre efficacité.
- PTES et OWASP WSTG structurent la mission de bout en bout.
