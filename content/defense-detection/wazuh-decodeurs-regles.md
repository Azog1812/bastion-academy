# Décodeurs et règles Wazuh

Une ligne de journal n'est que du texte. Pour qu'une règle puisse dire « 8 échecs
depuis la même IP », il faut d'abord savoir **où est l'IP** dans la ligne. Wazuh
sépare donc les deux étapes : les **décodeurs** extraient des champs, puis les
**règles** décident.

## Trois étapes

```
Oct 31 10:02:11 web01 sshd[812]: Invalid user blimey from 203.0.113.7 port 52144
```

1. **Pré-décodage** : l'en-tête syslog donne la date, la machine (`web01`) et le
   programme (`sshd`).
2. **Décodage** : le décodeur `sshd` reconnaît le message et extrait
   `srcip = 203.0.113.7`, `srcport = 52144`, `srcuser = blimey`.
3. **Règles** : Wazuh cherche la règle la plus précise qui correspond. Ici, la règle
   fournie **5710** (« sshd: Attempt to login using a non-existent user »), de niveau 5.
   Si la même IP recommence, la règle fournie **5712** (« brute force trying to get
   access to the system ») monte au niveau 10.

Pour un journal au format JSON, comme les journaux de Bastion, le décodeur JSON
intégré extrait tous les champs sans écrire d'expression régulière.

## Une règle

Wazuh fournit des milliers de règles, organisées en arbre : une règle enfant
précise une règle parente avec `<if_sid>`. Tes propres règles vont dans
`/var/ossec/etc/rules/local_rules.xml`, avec des identifiants **entre 100000 et
120000** : une mise à jour de Wazuh n'écrase jamais ce fichier.

La règle 5712 est une règle de corrélation. Voici comment on en écrit une du même
genre, avec ses propres seuils :

```xml
<group name="local,authentification,">
  <rule id="100100" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_srcip />
    <description>sshd : 8 comptes inexistants essayés en 2 minutes depuis $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

| Élément | Sens |
|---|---|
| `level="10"` | Gravité, de 0 à 16. Le niveau 0 ignore l'événement ; par défaut, une alerte n'est enregistrée qu'à partir du niveau 3 |
| `<if_sid>` | Correspond si la règle parente vient de correspondre **à cet événement** |
| `<if_matched_sid>` | Correspond si la règle parente a correspondu **plusieurs fois récemment** (avec `frequency`) |
| `frequency` / `timeframe` | Nombre de correspondances (de 2 à 9999) dans une fenêtre en secondes |
| `<same_srcip />` | Les événements comptés doivent venir de la **même IP source** (`same_source_ip` en est l'ancien nom) |
| `<field name="…">` | Teste un champ décodé, par exemple un champ d'un journal JSON |
| `<mitre>` | Rattache l'alerte à une technique MITRE ATT&CK |

Tu reconnais la règle de seuil du module précédent : `groupBy` devient
`same_srcip`, `min` devient `frequency`, `windowSeconds` devient `timeframe`. Les
concepts se transposent d'un SIEM à l'autre ; seule la syntaxe change.

## Réduire le bruit sans tout éteindre

Pour faire taire un faux positif, ne modifie pas la règle fournie : écris une règle
enfant de **niveau 0**, la plus étroite possible.

```xml
<rule id="100110" level="0">
  <if_sid>5710</if_sid>
  <srcip>10.0.5.20</srcip>
  <description>Échecs SSH attendus : scanner de conformité interne</description>
</rule>
```

C'est l'équivalent du bloc `exclude` d'une règle Sigma. Le piège est le même :
une exclusion trop large (tout un sous-réseau, un compte de service entier) crée un
angle mort que l'attaquant apprendra vite à utiliser.

## Tester avant de déployer

`/var/ossec/bin/wazuh-logtest` rejoue une ligne de journal et affiche les trois
étapes : les champs décodés, la règle retenue, son niveau. Une règle se teste avec
**l'attaque et le trafic légitime**, exactement comme dans les défis de détection.
Une règle non testée ne sait que deux choses : se taire pendant l'attaque, ou
réveiller le SOC pour rien.

## À retenir

- Décodeurs (extraire les champs) puis règles (décider) ; le JSON se décode tout seul.
- Règles personnalisées dans `local_rules.xml`, identifiants de 100000 à 120000.
- `if_sid` pour préciser, `if_matched_sid` + `frequency` + `timeframe` + `same_srcip` pour corréler.
- Un faux positif se traite par une règle enfant de niveau 0, étroite ; on teste avec `wazuh-logtest`.
