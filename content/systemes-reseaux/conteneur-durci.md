# Casse-le, répare-le : durcir un conteneur

Un conteneur n'est pas une machine virtuelle : c'est un **processus Linux**
isolé par le noyau (namespaces, cgroups). Il partage le noyau de l'hôte. Un
conteneur mal configuré peut donc offrir l'hôte entier à un attaquant.

## Casse-le : un conteneur trop permissif

Avec Docker installé, compare ces deux lancements :

```bash
# 1. Conteneur par défaut : l'utilisateur est root
docker run --rm alpine id
# uid=0(root) gid=0(root) ...

# 2. Conteneur « privilégié » : désactive presque toute l'isolation
docker run --rm --privileged alpine sh -c 'ls /dev | head; cat /proc/self/status | grep CapEff'
```

Dans le second cas, `CapEff` vaut `000001ffffffffff` (ou proche) : **toutes**
les capabilities. Le conteneur voit les disques de l'hôte dans `/dev` et peut
les monter. Un attaquant qui atteint un tel conteneur peut lire et modifier le
système de fichiers de l'hôte : c'est une évasion de conteneur.

Autres configurations qui mènent au même résultat :

| Configuration | Pourquoi c'est grave |
|---|---|
| `-v /var/run/docker.sock:/var/run/docker.sock` | Piloter Docker = lancer un conteneur privilégié = root sur l'hôte |
| `-v /:/host` | Le système de fichiers de l'hôte est monté, en écriture |
| `--pid=host`, `--network=host` | Le conteneur voit les processus ou le réseau de l'hôte |
| `USER` absent dans le Dockerfile | root dans le conteneur, et une faille du noyau suffit pour sortir |

## Répare-le : la configuration de Bastion

Lis `docker-compose.yml`. Chaque ligne retire un pouvoir dont l'application n'a
pas besoin :

```yaml
ports:
  - "127.0.0.1:3000:3000"   # joignable depuis cette machine seulement
read_only: true             # système de fichiers en lecture seule
tmpfs:
  - /tmp:size=16m,mode=1777
cap_drop: [ALL]             # aucune capability
security_opt:
  - no-new-privileges:true  # un binaire SUID ne peut plus élever les droits
pids_limit: 128             # pas de « fork bomb »
mem_limit: 768m
```

Et l'image elle-même (`Dockerfile`) :

- base **distroless** : pas de shell, pas de gestionnaire de paquets ;
- `USER 65532:65532` : jamais root ;
- code et contenu en `0555`, propriété de root : non modifiables par l'application.

En Kubernetes (`deploy/k8s/deployment.yaml`), les mêmes règles sont imposées par
le `securityContext` (`runAsNonRoot`, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, profil
`seccomp` `RuntimeDefault`), et le namespace applique le profil **restricted**
des *Pod Security Standards*, qui refuse un pod qui ne les respecte pas.

## À toi de jouer : vérifier, pas croire

Construis et lance Bastion avec Docker (`docker compose up --build`), puis :

```bash
docker compose exec bastion /bin/sh            # échoue : il n'y a pas de shell
docker inspect --format '{{.Config.User}}' bastion:local
docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' \
  $(docker compose ps -q bastion)
```

Tu dois obtenir `65532:65532`, puis `true [ALL]`. La CI fait la même vérification
à chaque build, et lance un test de fumée avec `--read-only --cap-drop ALL` :
si une modification future casse ces garanties, la fusion est bloquée.

## La défense en profondeur, appliquée

Imagine qu'un attaquant trouve une faille d'exécution de code dans Bastion :

1. il n'a **pas de shell** pour enchaîner ses commandes ;
2. il est **UID 65532**, sans capability, sans possibilité d'élévation ;
3. il ne peut **rien écrire** hors de `/data` et `/tmp` ;
4. en Kubernetes, **aucune connexion sortante** n'est autorisée (dernière leçon
   de ce parcours) : impossible de télécharger un outil ou d'exfiltrer les données.

Aucune de ces couches n'est parfaite. Ensemble, elles transforment une faille
critique en incident contenu.

## À retenir

- Un conteneur partage le noyau de l'hôte : `--privileged` ou le socket Docker
  équivalent à root sur l'hôte.
- Non-root, lecture seule, zéro capability, `no-new-privileges`, pas de shell.
- Une garantie de sécurité doit être testée en CI, sinon elle finit par disparaître.
