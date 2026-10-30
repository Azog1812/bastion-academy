# La reconnaissance

« Donnez-moi six heures pour abattre un arbre, je passerai les quatre premières
à affûter ma hache. » En test d'intrusion, l'affûtage s'appelle la
**reconnaissance** : la surface d'attaque qu'on n'a pas trouvée ne sera jamais
testée.

## Passive : sans toucher la cible

La reconnaissance passive n'envoie aucun paquet à la cible. Elle s'appuie sur
des sources publiques (**OSINT**, *Open Source Intelligence*) :

| Source | Ce qu'elle révèle |
|---|---|
| **DNS** et WHOIS | Sous-domaines, serveurs de messagerie, hébergeurs |
| **Journaux de transparence des certificats** | Chaque certificat TLS émis est publié : la liste des noms de domaine d'une organisation, y compris `preprod.` ou `vpn.` |
| Moteurs comme Shodan ou Censys | Services exposés et leurs versions, déjà scannés par d'autres |
| Dépôts de code publics | Clés d'API oubliées, noms de serveurs internes, fichiers de configuration |
| Offres d'emploi, réseaux sociaux | Technologies utilisées (« maîtrise de Struts 2 exigée ») |

## Active : interroger la cible

Une fois le périmètre confirmé, la reconnaissance active interroge
directement les systèmes autorisés :

- **scan de ports et de services** (`nmap`, niveau 3) ;
- **découverte de contenu** : des outils comme `ffuf` essaient des milliers de
  chemins (`/admin`, `/backup.zip`, `/.git/`) et notent ceux qui répondent ;
- **identification des technologies** : en-têtes `Server` et `X-Powered-By`,
  pages d'erreur, noms des cookies de session.

C'est bruyant : un SOC qui surveille (niveau 5) voit des centaines de 404 depuis
la même adresse. Ce n'est pas grave en test d'intrusion, c'est même une
information utile pour le client : **a-t-il vu le test ?**

## Ce que les erreurs racontent

Les messages d'erreur sont une mine pour l'auditeur : une trace de pile révèle
le langage et les bibliothèques, un « fichier introuvable : /var/www/app/… »
révèle l'arborescence du serveur. C'est pourquoi Bastion ne renvoie jamais de
détails internes : chaque erreur inattendue devient une réponse générique avec
un identifiant de requête, et le détail reste dans les journaux du serveur
(`src/errors.ts`, invariant 7).

## Organiser ce qu'on trouve

Chaque élément découvert est noté : hôte, port, service, version, chemin
intéressant, et **d'où vient l'information**. Ce journal de bord alimente
l'analyse des vulnérabilités, puis le rapport.

## À retenir

- Passive d'abord : DNS, transparence des certificats, moteurs, dépôts publics.
- Active ensuite, dans le périmètre : ports, contenu, technologies.
- Les messages d'erreur trahissent l'architecture : côté défense, ne rien dévoiler.
- Tout noter, avec la source : la reconnaissance nourrit tout le reste.
