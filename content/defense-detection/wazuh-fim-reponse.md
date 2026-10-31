# Intégrité des fichiers, audit et réponse active

Lire des journaux ne suffit pas : un attaquant qui a pris la main sur un serveur
peut les effacer, ou ne rien y laisser. L'agent Wazuh observe donc aussi la
machine elle-même. Trois capacités reviennent dans toutes les offres d'emploi SOC :
la surveillance d'intégrité, l'audit de configuration et la réponse active.

## La surveillance d'intégrité (FIM)

Le module **syscheck** calcule l'empreinte des fichiers surveillés et alerte
quand l'un d'eux est créé, modifié ou supprimé. Les cibles classiques :
`/etc/passwd`, `/etc/sudoers`, les clés SSH autorisées, les binaires système, la
racine d'un site web (un *webshell* déposé est un fichier qui apparaît).

```xml
<syscheck>
  <directories realtime="yes" whodata="yes">/etc,/usr/bin</directories>
  <directories realtime="yes">/var/www/html</directories>
  <ignore>/etc/mtab</ignore>
</syscheck>
```

- Sans option, la vérification est **périodique** : une modification suivie d'un
  retour en arrière entre deux passages passe inaperçue.
- `realtime="yes"` alerte dès la modification.
- `whodata="yes"` ajoute **qui** a modifié le fichier (utilisateur, processus), grâce
  à auditd sous Linux et à l'audit Windows. C'est ce qui transforme « sudoers a
  changé » en « `www-data`, via `/bin/sh` lancé par le serveur web, a modifié
  sudoers », autrement dit une compromission.

Le piège : surveiller tout le disque. Les fichiers qui changent normalement (journaux,
caches, bases de données) noient les vraies alertes. On surveille ce qui **ne doit
pas** changer, et on exclut le reste explicitement.

## L'audit de configuration (SCA)

Le module **SCA** (*Security Configuration Assessment*) vérifie chaque machine
contre des politiques, notamment les **benchmarks CIS** : connexion SSH de root
autorisée ? mots de passe sans expiration ? pare-feu inactif ? Chaque contrôle
ressort en réussi ou en échec, avec la remédiation. Le SIEM ne se contente plus de
voir l'attaque : il montre les portes laissées ouvertes **avant** l'attaque, ce
que le niveau 3 t'a appris à fermer à la main.

Wazuh signale aussi les paquets installés qui ont des **vulnérabilités connues** (CVE),
à partir de l'inventaire envoyé par les agents.

## La réponse active

Une règle peut déclencher une **commande** sur l'agent : bloquer une IP dans le
pare-feu (`firewall-drop`), désactiver un compte, isoler la machine. En général, la
commande s'annule seule après un délai.

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>
```

C'est puissant, et c'est dangereux :

- **Usurpation** : si un attaquant peut faire apparaître l'IP de ta passerelle ou de
  ton DNS dans des échecs d'authentification, la réponse active les bloque pour lui.
  Une liste blanche des adresses critiques est indispensable.
- **Faux positifs** : une règle trop large coupe un utilisateur légitime, ou toute
  une agence derrière la même IP publique.
- **Pouvoir** : le serveur Wazuh peut faire exécuter des commandes par des milliers
  d'agents. Le compromettre, c'est compromettre le parc. Le SIEM doit être plus
  protégé que ce qu'il surveille.

La bonne pratique : réponse active seulement sur des règles **éprouvées**, à très
faible taux de faux positifs, avec un délai d'expiration et une liste blanche. Le
reste passe par un analyste.

## À retenir

- FIM : `realtime` pour la vitesse, `whodata` pour savoir qui ; surveiller ce qui ne doit pas changer.
- SCA : la configuration des machines comparée aux benchmarks CIS, avec la remédiation.
- Réponse active : utile sur des règles éprouvées, avec liste blanche et expiration ; un attaquant peut la retourner contre toi.
- Un SIEM qui pilote les postes est une cible de premier rang.
