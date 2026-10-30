# Rédiger le rapport

Le client ne voit pas les nuits passées sur la mission. Il voit le **rapport**.
C'est le seul livrable qui reste, et le seul qui fait corriger quoi que ce soit.
Un test brillant mal raconté ne sert à rien.

## Deux lecteurs, deux parties

| Partie | Lecteur | Contenu |
|---|---|---|
| **Synthèse managériale** | Direction | Une page, sans jargon : le niveau de risque global, les deux ou trois problèmes majeurs et leur impact métier, les priorités |
| **Partie technique** | Équipes qui corrigent | Chaque constat, assez précis pour être **reproduit** et **corrigé** |

Entre les deux : le périmètre réellement testé, les dates, la méthode, et ce
qui n'a **pas** pu être testé. Un rapport qui laisse croire que tout a été
couvert est trompeur.

## Un constat bien écrit

Pour chaque vulnérabilité :

1. **Titre** explicite : « Traversée de répertoires sur /documents », pas « Problème 4 ».
2. **Gravité** et vecteur CVSS, justifiés.
3. **Description** : où, quoi, pourquoi c'est un problème.
4. **Preuve** : la requête exacte, la réponse, des captures. Le développeur
   doit pouvoir rejouer le test en quelques minutes.
5. **Impact** concret : « permet de lire le secret de signature, donc de se
   connecter en administrateur », pas « pourrait compromettre la sécurité ».
6. **Recommandation** actionnable : la correction, avec une référence
   (OWASP, CWE). Pas « sécuriser l'application ».

Les chaînes de failles font l'objet d'un constat à part : c'est souvent le
résultat le plus important de la mission.

## Exemple

> **Traversée de répertoires sur `/documents`** — Élevée
> `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`
>
> Le paramètre `nom` est concaténé au dossier des documents sans contrôle :
> `GET /documents?nom=../config/app.env` renvoie la configuration de
> production, dont le secret de signature des jetons (voir la chaîne C-1).
>
> **Recommandation** : servir les documents par identifiant plutôt que par nom ;
> à défaut, résoudre le chemin et vérifier qu'il reste dans le dossier autorisé
> (CWE-22). Sortir les secrets de l'arborescence de l'application.

## Le rapport est lui-même sensible

Il décrit comment entrer chez le client : il se transmet **chiffré**, à des
destinataires nommés, et l'auditeur détruit ses copies et les données
collectées à la date prévue par la convention.

## À retenir

- Une synthèse pour décider, une partie technique pour corriger.
- Chaque constat : titre clair, gravité justifiée, preuve rejouable, impact concret, recommandation actionnable.
- Dire ce qui n'a pas été testé.
- Le rapport est un document sensible : chiffré, diffusion restreinte, destruction prévue.
