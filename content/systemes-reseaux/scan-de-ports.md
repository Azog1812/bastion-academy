# Scanner des ports, légalement

La reconnaissance est la première phase de tout test d'intrusion : avant
d'attaquer, on cartographie. Le scan de ports répond à la question « quels
services cette machine expose-t-elle ? ».

> **Le cadre légal d'abord.** En France, accéder ou tenter d'accéder
> frauduleusement à un système (article 323-1 du Code pénal) est puni, et un
> scan peut suffire à constituer une tentative ou à déclencher une plainte.
> Ne scanne **que** ta propre machine, ou une cible pour laquelle tu as une
> autorisation **écrite**. Dans cette leçon, la seule cible est `127.0.0.1`.

## Ce que fait un scanner

Rappelle-toi la poignée de main TCP. Pour chaque port, le scanner envoie un
`SYN` et observe :

| Réponse | État | Interprétation |
|---|---|---|
| `SYN-ACK` | **open** | Un programme écoute |
| `RST` | **closed** | La machine répond, mais rien n'écoute |
| Rien, ou ICMP « interdit » | **filtered** | Un pare-feu bloque |

Le *SYN scan* (`-sS`) n'achève pas la poignée de main : il envoie `RST` au lieu
du dernier `ACK`. Il est plus rapide et laisse moins de traces dans les
journaux applicatifs, mais un pare-feu ou un IDS le voit très bien.

## À toi de jouer, sur ta machine

Installe nmap (paquet `nmap` sous Linux, installeur officiel sous Windows et
macOS), lance Bastion, puis :

```bash
nmap -sT -p 1-10000 127.0.0.1           # connexions TCP complètes, 10 000 premiers ports
nmap -sV -p 3000 127.0.0.1              # identifier le service et sa version
```

Que dit `-sV` sur le port 3000 ? Il tente de deviner le logiciel à partir de
ses réponses. Bastion ne publie ni en-tête `Server`, ni `X-Powered-By`
(`app.disable('x-powered-by')` dans `src/app.ts`). Moins d'informations, c'est
moins de failles connues à essayer.

Compare avec ta liste `ss -tlnp` de la première leçon : le scan voit-il les
mêmes ports ? Un service lié à `127.0.0.1` est visible ici parce que tu scannes
depuis la machine elle-même. Depuis une autre machine du réseau, il serait
invisible.

## Lire un résultat comme un attaquant

Pour chaque port ouvert, un pentesteur se pose trois questions :

1. **Quel service, quelle version ?** On recherche ensuite les vulnérabilités
   connues (CVE) de cette version.
2. **Doit-il être exposé ?** Une base de données (`5432`, `3306`, `27017`) ou
   un tableau de bord d'administration joignable depuis le réseau est souvent
   une faille à lui seul.
3. **Est-il protégé ?** Authentification, chiffrement, limitation du débit.

## Le point de vue du défenseur

- **Moins de ports, moins de surface.** Chaque service non nécessaire est
  arrêté ou lié à `127.0.0.1`.
- **Filtrer par défaut.** Un pare-feu qui bloque tout sauf le nécessaire
  transforme `closed` en `filtered` et ralentit la cartographie.
- **Détecter.** Un scan produit des centaines de connexions vers des ports
  différents en quelques secondes : c'est l'un des signaux les plus simples à
  repérer (niveau 5).

## À retenir

- Ne scanne que ce qui t'appartient, ou avec une autorisation écrite.
- open / closed / filtered se déduisent de la poignée de main TCP.
- Une version de logiciel affichée, c'est une liste de CVE offerte.
- Côté défense : fermer, lier en local, filtrer, détecter.
