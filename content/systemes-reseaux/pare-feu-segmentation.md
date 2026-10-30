# Casse-le, répare-le : segmenter et filtrer le réseau

Dans un réseau « plat », toute machine peut joindre toutes les autres. Il suffit
alors d'un poste compromis pour atteindre la base de données, le contrôleur de
domaine et les sauvegardes. La **segmentation** découpe le réseau en zones, et
le **filtrage** ne laisse passer entre elles que les flux nécessaires.

## Les principes

- **Refus par défaut** (*default deny*) : tout est interdit, puis on autorise
  explicitement chaque flux utile. L'inverse (tout autoriser, puis bloquer ce
  qui semble dangereux) laisse toujours passer ce qu'on n'a pas prévu.
- **Filtrer dans les deux sens.** Le filtrage **sortant** (*egress*) est
  souvent oublié. C'est pourtant lui qui empêche un serveur compromis de
  télécharger des outils, de joindre le serveur de commande de l'attaquant
  (C2) ou d'exfiltrer des données.
- **Zones de confiance** : DMZ pour ce qui est exposé à Internet, zone
  applicative, zone de données, zone d'administration. Les flux entre zones
  passent par un pare-feu.
- **Zero Trust** : être « à l'intérieur » du réseau ne donne aucun droit.
  Chaque requête est authentifiée et autorisée, comme si elle venait
  d'Internet. Bastion vérifie le jeton et relit le rôle en base à chaque
  requête, quel que soit l'appelant.

## Casse-le : un pare-feu hôte en une règle

Sur une machine Linux de test, ou une VM, avec `nftables` :

```bash
# Tout refuser en entrée, sauf la boucle locale et les connexions déjà établies
sudo nft add table inet filtre
sudo nft add chain inet filtre entree '{ type filter hook input priority 0; policy drop; }'
sudo nft add rule inet filtre entree iif lo accept
sudo nft add rule inet filtre entree ct state established,related accept
```

Depuis une autre machine, refais le scan de la leçon précédente : les ports
passent de `closed` à `filtered`. Pour revenir en arrière :
`sudo nft delete table inet filtre`. Ne fais pas cela sur une machine distante à
laquelle tu es connecté en SSH : tu t'enfermerais dehors.

Sous Windows, le pare-feu intégré suit la même logique (`Get-NetFirewallProfile`
affiche l'action par défaut de chaque profil).

## Répare-le : le réseau de Bastion en Kubernetes

Lis `deploy/k8s/networkpolicy.yaml`. Deux règles suffisent :

```yaml
# 1. Tout interdire, dans les deux sens, pour tous les pods du namespace
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# 2. Autoriser uniquement l'ingress controller à joindre l'API, sur le port 3000
ingress:
  - from:
      - namespaceSelector:
          matchLabels:
            kubernetes.io/metadata.name: ingress-nginx
    ports:
      - protocol: TCP
        port: 3000
```

Et **aucune règle de sortie** : l'API n'a besoin de joindre personne, pas même
un serveur DNS. Conséquence directe pour un attaquant qui aurait obtenu une
exécution de code (leçon sur les conteneurs) : pas de `curl` vers son serveur,
pas de connexion inverse, pas d'exfiltration.

Ce choix a un coût, assumé : si Bastion devait un jour appeler un service
externe (un KMS, une API d'e-mail), il faudrait ouvrir **ce flux précis**, vers
**cette destination précise**, et le documenter. C'est le prix du refus par
défaut, et il est faible comparé à ce qu'il évite.

## Lier en local : la segmentation la plus simple

Avant même un pare-feu, la question est « sur quelle interface ce service
écoute-t-il ? ». En local, Bastion est publié sur `127.0.0.1:3000` uniquement,
et les futurs labs volontairement vulnérables le seront aussi. Un service
vulnérable que le réseau ne peut pas joindre n'est exploitable que depuis la
machine elle-même.

## À retenir

- Refus par défaut, puis autorisation explicite de chaque flux utile.
- Le filtrage sortant coupe le téléchargement d'outils, le C2 et l'exfiltration.
- Zero Trust : l'emplacement réseau ne prouve rien, chaque requête est vérifiée.
- Bastion : NetworkPolicy *default deny* dans les deux sens, une seule entrée,
  aucune sortie.
