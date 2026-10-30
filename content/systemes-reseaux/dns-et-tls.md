# DNS et TLS : à qui je parle vraiment ?

Taper `github.com` dans un navigateur déclenche deux questions de confiance :

1. **DNS** : quelle adresse IP correspond à ce nom ?
2. **TLS** : la machine qui répond est-elle vraiment `github.com`, et notre
   échange est-il à l'abri des oreilles indiscrètes ?

Si l'une des deux réponses est truquée, tout le reste (mot de passe, cookies,
jetons) part chez l'attaquant.

## DNS, l'annuaire d'Internet

Ta machine demande à un **résolveur** (celui de ta box, de ton entreprise ou
public), qui interroge à son tour les serveurs faisant autorité.

```bash
dig +short github.com A        # adresses IPv4
dig +short github.com AAAA     # adresses IPv6
dig github.com MX +short       # serveurs de courrier
dig _dmarc.github.com TXT +short
```

(Sous Windows : `Resolve-DnsName github.com`.)

Les types d'enregistrements à connaître :

| Type | Contenu | Intérêt en sécurité |
|---|---|---|
| `A` / `AAAA` | Adresse IPv4 / IPv6 | La cible d'un détournement |
| `CNAME` | Alias vers un autre nom | *Subdomain takeover* si la cible est abandonnée |
| `MX` | Serveurs de courrier | Cartographie, hameçonnage |
| `TXT` | Texte libre : SPF, DMARC, preuves de propriété | Usurpation d'e-mails si SPF/DMARC sont absents |
| `NS` | Serveurs qui font autorité | Qui contrôle vraiment le domaine |

## Les attaques sur DNS

- **Empoisonnement de cache** : injecter une fausse réponse dans un résolveur,
  qui la sert ensuite à tous ses clients. DNSSEC signe les réponses pour l'empêcher.
- **Subdomain takeover** : `docs.exemple.fr` est un `CNAME` vers un service cloud
  supprimé depuis. Un attaquant recrée ce service à son nom et sert son contenu
  sous le domaine de la victime, cookies compris.
- **Résolveur hostile** : sur un Wi-Fi public, le réseau te donne son résolveur.
  DNS chiffré (DoH, DoT) protège la question ; TLS protège la suite.

Le DNS est aussi une **mine d'or pour la reconnaissance** : les noms de
sous-domaines (`vpn.`, `staging.`, `admin.`) révèlent l'architecture. Les
journaux publics de certificats (Certificate Transparency) en listent souvent
des centaines.

## TLS : chiffrer et authentifier

TLS apporte trois garanties :

| Garantie | Comment |
|---|---|
| **Confidentialité** | Chiffrement symétrique (AES-GCM, ChaCha20) avec une clé négociée |
| **Intégrité** | Chiffrement authentifié : un octet modifié est détecté |
| **Authenticité du serveur** | Un **certificat** signé par une autorité de confiance prouve que la clé appartient bien à ce nom |

Sans la troisième, les deux premières ne servent à rien : tu aurais une
conversation parfaitement chiffrée… avec l'attaquant. C'est le principe de
l'**homme du milieu** (*man-in-the-middle*).

Regarde un certificat de près :

```bash
openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Tu vois le nom couvert (`subjectAltName`), l'autorité émettrice (`issuer`) et
la période de validité. Le navigateur vérifie la **chaîne** jusqu'à une
autorité racine qu'il connaît.

## HSTS : interdire le retour en clair

Même avec TLS, un attaquant placé sur le réseau peut intercepter la toute
première requête `http://` et empêcher la redirection vers `https://`
(*SSL stripping*). L'en-tête **HSTS** demande au navigateur de ne plus jamais
utiliser HTTP pour ce domaine. Bastion l'envoie (`src/app.ts`) :

```ts
strictTransportSecurity: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
```

Deux ans, sous-domaines compris, et éligible à la liste *preload* intégrée aux
navigateurs : même la toute première visite est protégée.

## À retenir

- DNS dit *où* aller, TLS prouve *à qui* on parle. Il faut les deux.
- Un certificat lie une clé à un nom ; sans vérification, le chiffrement ne
  protège de rien.
- HSTS ferme la porte au retour forcé vers HTTP.
- Le DNS public est la première étape de toute reconnaissance.
