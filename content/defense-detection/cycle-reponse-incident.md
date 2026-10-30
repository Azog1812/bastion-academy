# La réponse à incident

Une alerte est confirmée : ce n'est pas un faux positif. Que fait-on, dans
quel ordre, et qui prévient-on ? Improviser à ce moment-là, c'est presque
toujours empirer les choses. La réponse à incident se **prépare**.

## Le cycle

Le guide de référence est le **NIST SP 800-61**. Sa révision 2 décrivait
quatre phases, encore très utilisées :

1. **Préparation** : équipe, contacts, outils, procédures (*playbooks*),
   journaux déjà en place. Tout ce qui ne peut pas s'improviser.
2. **Détection et analyse** : confirmer l'incident, en mesurer l'étendue, le
   qualifier (gravité, données touchées).
3. **Confinement, éradication, récupération** : arrêter la propagation, retirer
   l'accès de l'attaquant, remettre en service proprement.
4. **Retour d'expérience** : qu'est-ce qui a manqué ? Nouvelles règles de
   détection, correctifs, procédures.

La **révision 3** (avril 2025) range ces activités dans les fonctions du NIST
Cybersecurity Framework 2.0 (*Govern, Identify, Protect, Detect, Respond,
Recover*) : la réponse à incident n'est plus une activité à part, elle fait
partie de la gestion du risque de toute l'organisation.

## Confiner sans détruire les preuves

Le réflexe « j'éteins la machine » efface la mémoire vive : les processus de
l'attaquant, ses connexions réseau, parfois sa seule trace. Il vaut mieux :

- **isoler du réseau** (VLAN de quarantaine, règle de pare-feu), sans éteindre ;
- **révoquer** les accès compromis : mots de passe, jetons, clés ;
- **préserver** les preuves avant de nettoyer (leçon suivante).

## Quelques décisions déjà prises dans Bastion

Le fichier `docs/runbook.md` contient les procédures de Bastion pour ses
propres alertes. Par exemple, sur `auth.refresh_reuse_detected` (un jeton de
rafraîchissement rejoué), la plateforme a **déjà** révoqué toute la famille de
sessions : il reste à prévenir l'utilisateur et à chercher comment le jeton a
fuité. C'est de la préparation : la réponse est codée avant que l'incident
n'arrive.

## Les obligations

En France et dans l'Union européenne :

- une **violation de données personnelles** doit être notifiée à la **CNIL**
  dans les **72 heures** après en avoir pris connaissance (RGPD, article 33),
  et aux personnes concernées si le risque est élevé ;
- le **CERT-FR** (ANSSI) peut être sollicité, et certaines entités régulées
  ont des obligations de déclaration propres (directive NIS 2).

## À retenir

- Préparation, détection et analyse, confinement-éradication-récupération, retour d'expérience.
- Isoler plutôt qu'éteindre ; révoquer les accès ; préserver avant de nettoyer.
- Les procédures s'écrivent avant l'incident.
- Violation de données personnelles : 72 heures pour notifier la CNIL.
