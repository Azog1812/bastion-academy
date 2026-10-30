# La désérialisation non sûre

Sérialiser, c'est transformer un objet en suite d'octets pour le stocker ou
l'envoyer ; désérialiser, c'est reconstruire l'objet. Rien d'inquiétant… tant
que le format se contente de **données**. Certains formats natifs reconstruisent
aussi des **types**, et donc du comportement : désérialiser un message forgé par
un attaquant revient alors à exécuter son code. C'est la CWE-502, et elle figure
dans l'OWASP Top 10 sous « défaillances d'intégrité des logiciels et des
données » (A08:2021).

## Pourquoi un format peut exécuter du code

| Langage | Mécanisme | Ce que l'attaquant contrôle |
|---|---|---|
| **Python** | `pickle` | Un objet peut indiquer, via `__reduce__`, une fonction à appeler pour se reconstruire, par exemple `os.system` |
| **PHP** | `unserialize()` | Les objets recréés déclenchent des méthodes magiques (`__wakeup`, `__destruct`) avec des attributs choisis par l'attaquant |
| **Java** | `ObjectInputStream` | `readObject()` des classes présentes dans le *classpath* |
| **.NET** | `BinaryFormatter` | Même problème ; Microsoft l'a déclaré dangereux, puis retiré de .NET 9 |

La documentation de Python le dit en tête de page : ne jamais désérialiser avec
`pickle` des données qui ne sont pas dignes de confiance. Ici, le format lui-même
*est* la vulnérabilité.

## Les chaînes de gadgets

En Java ou en PHP, l'attaquant ne peut pas envoyer de code : seulement des
objets de classes **déjà présentes** dans l'application. Il assemble alors une
**chaîne de gadgets** : la méthode appelée à la désérialisation d'un objet A
appelle une méthode de B, qui appelle C… jusqu'à un gadget qui exécute une
commande. Les gadgets viennent souvent de bibliothèques courantes (Apache
Commons Collections, en 2015, a touché des milliers d'applications) ; l'outil
`ysoserial` en catalogue des dizaines.

Leçon défensive majeure : **la faille n'est pas dans la bibliothèque qui
contient les gadgets**. Elle est dans le point d'entrée qui désérialise des
données non fiables. Supprimer un gadget ne fait que déplacer le problème vers
le suivant.

## Les reconnaître pendant un test

- Des cookies, paramètres ou champs cachés en Base64 qui commencent par
  `rO0AB` (Java sérialisé, octets `AC ED 00 05`), `gASV` (pickle protocole 4),
  `O:8:"` (PHP), ou `AAEAAAD/////` (.NET `BinaryFormatter`).
- Des files de messages, caches ou sessions partagés entre services.
- Des fonctions d'import et d'export de « fichiers projet ».

## Le cousin JavaScript : la pollution de prototype

JSON ne recrée pas de types, mais fusionner récursivement un objet fourni par
l'utilisateur dans un autre peut écrire dans `__proto__` et modifier **tous** les
objets de l'application : un `isAdmin` qui apparaît partout, ou une option qui
mène à l'exécution de commande. C'est pourquoi le moteur de détection de Bastion
valide les clés sur l'objet brut et rejette `__proto__` au lieu de l'ignorer
(ADR 0010), et pourquoi toutes ses entrées passent par des schémas zod
`.strict()` (invariant 3).

## Se défendre

1. **N'accepter que des formats de données** : JSON, Protobuf, MessagePack, sans
   types ni classes, puis **valider** le contenu avec un schéma strict.
2. Si un format natif est inévitable : **signer** le contenu (HMAC) et vérifier la
   signature *avant* de désérialiser, ou restreindre les classes autorisées
   (filtres de désérialisation de Java, `allowed_classes` de PHP).
3. Isoler et surveiller les composants qui désérialisent : moindre privilège,
   pas de shell, pas de réseau sortant.

## À retenir

- Un format qui recrée des types peut exécuter du code : la désérialisation de données non fiables est une exécution de code à distance en puissance.
- Les chaînes de gadgets réutilisent du code déjà présent ; la faille est le point d'entrée, pas le gadget.
- Repère les signatures (`rO0AB`, `gASV`, `O:8:"`) dans les cookies et les paramètres.
- Défense : formats de données uniquement, schémas stricts, signature avant désérialisation.
