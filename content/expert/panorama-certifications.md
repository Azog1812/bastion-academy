# Les certifications du domaine

Une certification ne remplace pas l'expérience, mais elle ouvre des portes :
certains appels d'offres l'exigent, les recruteurs filtrent dessus, et
préparer un examen pratique force à combler ses lacunes. Encore faut-il choisir
celle qui correspond à ce qu'on veut faire.

## Deux familles

- Les certifications **théoriques** (QCM) vérifient un socle de connaissances.
  Elles sont reconnues par les ressources humaines et parfois exigées par
  contrat.
- Les certifications **pratiques** donnent un environnement à compromettre ou à
  défendre, en temps limité, puis demandent un rapport. Elles prouvent un
  savoir-faire, et c'est ce que regardent les équipes techniques.

## Panorama

| Certification | Organisme | Type | Pour qui |
|---|---|---|---|
| **Security+** | CompTIA | QCM | Socle généraliste, souvent la première |
| **CEH** | EC-Council | QCM (et une version pratique) | Vocabulaire offensif, très présente dans les offres d'emploi |
| **eJPT** | INE | Pratique | Premier examen offensif pratique |
| **PenTest+** | CompTIA | QCM et questions pratiques | Méthodologie de test d'intrusion |
| **OSCP / OSCP+** | OffSec | Pratique, 24 heures | La référence offensive : machines Linux, Windows et Active Directory |
| **CPTS** | Hack The Box | Pratique, plusieurs jours | Test d'intrusion complet et rapport professionnel |
| **OSWE**, **OSEP** | OffSec | Pratique | Experts : exploitation web en boîte blanche ; contournement des défenses et AD avancé |
| **GPEN**, **GCIH** | GIAC (SANS) | QCM et questions pratiques | Test d'intrusion ; réponse à incident |
| **CISSP** | ISC2 | QCM, expérience exigée | Management de la sécurité, très demandée pour les postes à responsabilité |

Les formats, les prix et les règles changent : vérifie toujours la page
officielle de l'organisme avant de t'inscrire.

## Zoom sur l'OSCP+

Depuis novembre 2024, l'examen de l'OSCP délivre l'**OSCP+**, qui expire au
bout de trois ans (l'OSCP « historique » reste sans date d'expiration). Le
format, tel que décrit par OffSec :

- **23 heures et 45 minutes** pour compromettre les machines, puis 24 heures pour
  envoyer le rapport ;
- trois machines **indépendantes** (60 points : accès initial puis élévation de
  privilèges) et un ensemble **Active Directory** de trois machines (40 points),
  abordé avec des identifiants fournis, comme après un hameçonnage réussi ;
- **70 points** pour réussir, les points bonus ont disparu ;
- le rapport compte : une machine compromise mais mal documentée peut ne
  rapporter aucun point.

Ce que ce parcours t'a donné pour cet examen : la méthode (niveau 4),
l'élévation de privilèges Linux et Windows et les attaques AD (niveaux 3 et 6),
les failles web (niveau 2) et le rapport (niveau 4).

## Et en France ?

Il n'existe pas de certification d'État pour les auditeurs, mais l'ANSSI
**qualifie** des prestataires d'audit (PASSI, vu au niveau 4). Les auditeurs d'un
PASSI doivent démontrer leurs compétences, et les certifications pratiques sont
un argument reconnu. Côté défense, les qualifications **PDIS** (détection) et
**PRIS** (réponse à incident) jouent le même rôle pour les SOC et les CERT.

## Choisir

1. Commence par ce que tu veux **faire** (pentest, SOC, réponse à incident,
   sécurité applicative), pas par la certification la plus célèbre.
2. Lis des offres d'emploi de ta région : quelles certifications citent-elles ?
3. Une certification pratique d'entrée, puis une avancée, vaut mieux qu'une
   collection de QCM.

## À retenir

- QCM pour le socle et les ressources humaines, examen pratique pour prouver un savoir-faire.
- OSCP+ : 24 heures, trois machines indépendantes et un ensemble AD, 70 points sur 100, puis un rapport ; expire après trois ans.
- En France, l'ANSSI qualifie des prestataires (PASSI, PDIS, PRIS), pas des personnes.
- Choisir selon le métier visé, et vérifier les règles sur le site officiel.
