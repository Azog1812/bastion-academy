# Architecture et déploiement de Wazuh

Tu as écrit des règles de détection au format Sigma : un format **portable**, que
chaque SIEM traduit dans son propre langage. En entreprise, ces règles tournent
dans un vrai SIEM. **Wazuh** est l'un des plus déployés : il est open source,
gratuit, et on le croise dans les PME, chez les prestataires de SOC et dans les
administrations. Il est né en 2015 d'un fork d'OSSEC, un détecteur d'intrusion
sur les hôtes (HIDS), puis il est devenu une plateforme SIEM et XDR complète.

## Les quatre composants

| Composant | Rôle | Bâti sur |
|---|---|---|
| **Agent** | Installé sur chaque machine surveillée : collecte les journaux, surveille l'intégrité des fichiers, audite la configuration, exécute les réponses actives | Wazuh |
| **Serveur** (*manager*) | Reçoit les événements, les **décode**, leur applique les **règles** et produit les alertes ; expose une API de gestion | Wazuh (héritage OSSEC) |
| **Indexeur** | Stocke et indexe les alertes pour la recherche | Fork d'OpenSearch |
| **Tableau de bord** | Interface web : recherche, tableaux, gestion des agents | Fork d'OpenSearch Dashboards |

Le cœur de la détection se trouve dans le **serveur**. L'indexeur et le tableau de
bord servent à stocker et à consulter. C'est aussi ce qui coûte en mémoire : la
documentation recommande **8 Gio de RAM et 4 vCPU** pour une installation tout-en-un
jusqu'à 25 agents. C'est pour cela que ce module est optionnel dans Bastion Academy.

## Le trajet d'un événement

```
poste (agent) ──1514/tcp──► serveur : décodage → règles → alerte ──► indexeur ──► tableau de bord
```

1. L'agent lit un journal (`/var/log/auth.log`, le journal d'événements Windows…)
   et l'envoie au serveur, **chiffré**, sur le port **1514**.
2. Le serveur le **décode** : il en extrait des champs (`srcip`, `user`…).
3. Il évalue les **règles**. Une règle qui correspond produit une **alerte**, avec
   un niveau de 0 à 16.
4. L'alerte part à l'indexeur ; l'analyste la voit dans le tableau de bord.

Des équipements sans agent (pare-feu, routeurs) peuvent aussi envoyer leurs
journaux en syslog au serveur.

## Les ports à connaître

| Port | Service | Qui doit pouvoir y accéder |
|---|---|---|
| 1514/tcp | Connexion des agents | Les machines surveillées |
| 1515/tcp | Inscription des agents | Les machines surveillées, au moment de l'inscription |
| 55000/tcp | API du serveur | Le tableau de bord et les administrateurs |
| 9200/tcp | API de l'indexeur | Le serveur et le tableau de bord |
| 443/tcp | Tableau de bord | Les analystes |

Un SIEM est une **cible de choix** : il voit tout, il est souvent joignable depuis
tout le réseau, et ses administrateurs ont la main sur des milliers de postes, car
la réponse active exécute des commandes sur les agents. Ne jamais exposer l'API
(55000) ni l'inscription (1515) à Internet. On protège l'inscription par un mot de
passe ou par des certificats, et on change les identifiants par défaut dès
l'installation.

## Inscrire un agent

À l'inscription, l'agent obtient une **clé** propre, qui chiffre ensuite ses
échanges avec le serveur. L'agent se configure dans `ossec.conf` (adresse du
serveur, journaux à lire) ; on peut aussi pousser une configuration commune depuis
le serveur à des **groupes** d'agents (`agent.conf`). C'est la méthode retenue
en entreprise : tous les serveurs web reçoivent la même configuration.

## À retenir

- Agent (collecte), serveur (décodage et règles), indexeur (stockage), tableau de bord (consultation).
- La détection a lieu sur le serveur ; l'indexeur et le tableau de bord sont la partie gourmande.
- Ports : 1514 agents, 1515 inscription, 55000 API, 9200 indexeur, 443 tableau de bord. Pas d'exposition à Internet.
- Un SIEM est une cible : identifiants changés, inscription protégée, accès filtrés.
