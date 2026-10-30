# Écrire une règle de détection

Chaque SIEM a son langage de requête (SPL pour Splunk, KQL pour Microsoft
Sentinel, EQL pour Elastic). Pour ne pas réécrire ses règles à chaque
changement d'outil, la communauté a créé **Sigma** : un format ouvert, en YAML,
qui se convertit vers chacun d'eux. C'est l'équivalent, pour les détections, de
ce qu'est un standard de fichier pour un traitement de texte.

## Une règle Sigma

```yaml
title: Téléchargement avec certutil
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: '-urlcache'
  condition: selection
falsepositives:
  - Rares usages d'administration
level: high
```

- `selection` : un bloc de conditions, **toutes** obligatoires (ET) ;
- une liste de valeurs pour un même champ signifie **l'une d'elles** (OU) ;
- les **modificateurs** (`|contains`, `|startswith`, `|endswith`) précisent la comparaison ;
- les comparaisons sont **insensibles à la casse** : `PowerShell` et `powershell` sont égaux ;
- `condition` combine les blocs (`selection and not filter`).

## Le langage des défis de Bastion

Les défis utilisent un sous-ensemble de Sigma, en JSON :

```json
{
  "match": [
    { "image|endswith": "certutil.exe", "command_line|contains": "-urlcache" },
    { "image|endswith": "mshta.exe", "command_line|contains": "http" }
  ],
  "exclude": { "parent_image|endswith": "agent.exe" },
  "threshold": { "groupBy": "src_ip", "distinct": "user", "min": 8, "windowSeconds": 600 }
}
```

| Clé | Sens |
|---|---|
| `match` | Un bloc, ou une liste de blocs (OU entre les blocs, ET dans un bloc) |
| `exclude` | Les événements à écarter : l'activité légitime connue |
| `threshold` | Règle de comportement : par valeur de `groupBy`, au moins `min` événements (ou `min` valeurs différentes de `distinct`) dans une fenêtre de `windowSeconds` |

Modificateurs : `contains`, `startswith`, `endswith`, et `gte` / `lte` pour les nombres.

**Pas d'expressions régulières**, volontairement. Ta règle s'exécute sur le
serveur de la plateforme : une expression mal construite, comme `(a+)+$`, peut
prendre un temps exponentiel sur une entrée bien choisie (*ReDoS*) et bloquer
tous les utilisateurs. Sigma les autorise (`|re`), mais un SIEM les exécute
sur ses propres ressources, pas sur celles d'une application partagée.

## La méthode

1. **Lire les données** avant d'écrire quoi que ce soit : à quoi ressemble
   l'activité normale ?
2. Écrire une première règle **large**, regarder ce qu'elle attrape.
3. Resserrer : ajouter une condition, ou une exclusion pour l'activité légitime
   **identifiée**, jamais une exclusion trop large (« tout ce qui vient de
   10.0.0.0/8 » exclurait l'attaquant déjà à l'intérieur).
4. **Tester** contre des données connues. C'est ce que fait la plateforme, et
   ce que font les équipes matures en intégration continue : la détection
   devient du code (*detection as code*), versionnée, revue et testée.

## À retenir

- Sigma : un format ouvert pour écrire une détection une fois et la porter partout.
- ET dans un bloc, OU entre les valeurs d'un champ et entre les blocs.
- Exclure l'activité légitime précisément, jamais largement.
- Une règle non testée contre des données réelles est une hypothèse.
