# COFRAP - PoC serverless OpenFaaS

Ce projet implemente un parcours de gestion d'identites avec mot de passe et double authentification TOTP sur une architecture serverless.

```text
Utilisateur -> Frontend Nginx -> OpenFaaS -> Fonctions Python -> PostgreSQL
```

L'environnement d'execution repose sur Kubernetes avec Minikube et OpenFaaS Community deploye par Helm.

## Fonctionnalites

- creation d'un utilisateur par un administrateur ;
- generation d'un mot de passe aleatoire de 24 caracteres ;
- generation d'un secret TOTP compatible avec une application d'authentification ;
- hachage du mot de passe avec bcrypt ;
- chiffrement du secret TOTP avec Fernet avant stockage ;
- remise des identifiants par un lien temporaire utilisable une seule fois ;
- authentification par username, mot de passe et code TOTP ;
- activation du compte apres la premiere authentification reussie ;
- expiration et renouvellement des identifiants apres six mois.

## Fonctions OpenFaaS

| Fonction | Role |
| --- | --- |
| `generate-password` | Genere un mot de passe conforme a la politique COFRAP. |
| `generate-totp` | Genere un secret TOTP et une URI `otpauth`. |
| `generate-qr` | Transforme une URI en QR code PNG Base64. |
| `create-user` | Cree l'utilisateur, protege ses secrets et prepare leur remise. |
| `authenticate-user` | Verifie le mot de passe, le code TOTP et la date d'expiration. |
| `rotate-credentials` | Renouvelle le mot de passe et le secret TOTP. |
| `redeem-credentials` | Ouvre une seule fois une remise temporaire d'identifiants. |

## Prerequis

Installer les outils suivants :

- Docker Desktop en mode conteneurs Linux ;
- Minikube ;
- `kubectl` ;
- Helm ;
- Python 3.12 ou une version compatible ;
- OpenFaaS CLI (`faas-cli`) ;
- un compte Docker Hub pour reconstruire et publier les images.

Verifier les installations :

```powershell
docker version
minikube version
kubectl version --client
helm version
python --version
.\tools\faas-cli\faas-cli.exe version
```

Si le binaire local n'est pas conserve, remplacer `./tools/faas-cli/faas-cli.exe` par `faas-cli` dans les commandes suivantes.

## Tests unitaires depuis VS Code

Ouvrir ce dossier dans VS Code, puis ouvrir `Terminal > New Terminal`.

Installer les dependances de test dans un environnement virtuel :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m ensurepip --upgrade
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Lancer les tests fonction par fonction :

```powershell
python -m pytest -p no:cacheprovider generate-password
python -m pytest -p no:cacheprovider generate-totp
python -m pytest -p no:cacheprovider generate-qr
python -m pytest -p no:cacheprovider create-user
python -m pytest -p no:cacheprovider authenticate-user
python -m pytest -p no:cacheprovider rotate-credentials
python -m pytest -p no:cacheprovider redeem-credentials
```

Resultat attendu : `30 passed` au total. L'option `-p no:cacheprovider` evite la creation de `.pytest_cache` sur les postes Windows qui refusent ce dossier.

## 1. Demarrer Kubernetes

```powershell
minikube start --driver=docker
minikube status
kubectl get nodes
```

Le noeud doit etre `Ready` et l'API Kubernetes doit etre `Running`.

## 2. Installer OpenFaaS Community

Cette etape n'est necessaire que lors de la premiere installation du cluster.

```powershell
helm repo add openfaas https://openfaas.github.io/faas-netes/
helm repo update
kubectl create namespace openfaas
kubectl create namespace openfaas-fn
helm upgrade openfaas openfaas/openfaas --install --namespace openfaas --set functionNamespace=openfaas-fn --set generateBasicAuth=true
kubectl get pods -n openfaas
```

Si un namespace existe deja, l'erreur `AlreadyExists` peut etre ignoree.

Exposer d'abord le gateway dans un terminal laisse ouvert :

```powershell
kubectl port-forward -n openfaas svc/gateway 8080:8080
```

Dans un second terminal, recuperer le mot de passe administrateur et connecter la CLI :

```powershell
$encodedPassword = kubectl -n openfaas get secret basic-auth -o jsonpath="{.data.basic-auth-password}"
$openfaasPassword = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedPassword))
$openfaasPassword | .\tools\faas-cli\faas-cli.exe login --username admin --password-stdin --gateway http://127.0.0.1:8080
```

L'interface OpenFaaS est alors accessible sur <http://127.0.0.1:8080/ui/>.

## 3. Creer les secrets Kubernetes

Ne jamais enregistrer les valeurs de ces secrets dans Git.

```powershell
$dbPassword = Read-Host "Mot de passe PostgreSQL"
$fernetKey = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

kubectl create namespace cofrap-data --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic cofrap-postgres-secret -n cofrap-data --from-literal=POSTGRES_DB=cofrap --from-literal=POSTGRES_USER=cofrap_app --from-literal=POSTGRES_PASSWORD="$dbPassword" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic cofrap-postgres-password -n openfaas-fn --from-literal=cofrap-postgres-password="$dbPassword" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic credential-delivery-key -n openfaas-fn --from-literal=credential-delivery-key="$fernetKey" --dry-run=client -o yaml | kubectl apply -f -
```

Pour remplacer un secret existant, le supprimer explicitement puis recreer uniquement celui concerne.

## 4. Deployer PostgreSQL

```powershell
kubectl apply -f .\k8s\postgres.yaml
kubectl rollout status deployment/postgres -n cofrap-data
kubectl get pods,svc,pvc -n cofrap-data
```

Sur une base deja initialisee, appliquer la migration de remise temporaire :

```powershell
Get-Content .\k8s\migrations\001_credential_deliveries.sql | kubectl exec -i -n cofrap-data deployment/postgres -- psql -U cofrap_app -d cofrap
```

## 5. Deployer les fonctions

### Utiliser les images publiques existantes

Les images referencees dans `stack.yaml` doivent etre publiees en mode public sur Docker Hub, condition necessaire avec OpenFaaS Community. Verifier que les tags indiques existent avant cette commande.

```powershell
.\tools\faas-cli\faas-cli.exe deploy -f .\stack.yaml --gateway http://127.0.0.1:8080
.\tools\faas-cli\faas-cli.exe list --gateway http://127.0.0.1:8080
```

### Reconstruire les images

Se connecter a Docker Hub :

```powershell
docker login
```

Remplacer `fatymbaye` dans `stack.yaml` par son propre namespace Docker Hub. Sous Linux, `faas-cli build` peut construire toute la pile directement. Avec certaines versions de `faas-cli` sous Windows, le chemin `C:\...\template.yml` est interprete a tort comme une URL. Dans ce cas, generer d'abord les contextes, puis utiliser Docker :

```powershell
.\tools\faas-cli\faas-cli.exe build -f .\stack.yaml

docker build -t VOTRE_USERNAME/create-user:0.4.0 .\build\create-user
docker build -t VOTRE_USERNAME/authenticate-user:0.2.0 .\build\authenticate-user
docker build -t VOTRE_USERNAME/rotate-credentials:0.2.0 .\build\rotate-credentials

docker push VOTRE_USERNAME/create-user:0.4.0
docker push VOTRE_USERNAME/authenticate-user:0.2.0
docker push VOTRE_USERNAME/rotate-credentials:0.2.0

.\tools\faas-cli\faas-cli.exe deploy -f .\stack.yaml --gateway http://127.0.0.1:8080
```

Les autres images ne doivent etre reconstruites que si leur code ou leur tag a change.

## 6. Deployer le frontend

Pour utiliser l'image publique existante :

```powershell
kubectl apply -f .\k8s\frontend.yaml
kubectl rollout status deployment/cofrap-frontend
kubectl port-forward svc/cofrap-frontend 8082:80
```

Le dernier terminal doit rester ouvert. L'application est accessible sur <http://127.0.0.1:8082/>.

Pour reconstruire le frontend avec son propre namespace Docker Hub :

```powershell
docker build -t VOTRE_USERNAME/cofrap-frontend:0.4.0 .\frontend
docker push VOTRE_USERNAME/cofrap-frontend:0.4.0
```

Modifier ensuite l'image dans `k8s/frontend.yaml` avant `kubectl apply`.

## 7. Scenario de verification

1. Ouvrir <http://127.0.0.1:8082/>.
2. Creer un utilisateur depuis l'espace d'administration.
3. Scanner le QR de remise temporaire.
4. Ouvrir le lien une seule fois et recuperer le mot de passe ainsi que le QR TOTP.
5. Ajouter le compte dans une application TOTP.
6. S'authentifier avec l'adresse, le mot de passe et le code a six chiffres.
7. Verifier que le message `Acces autorise` apparait uniquement apres une authentification reussie.

Consulter les utilisateurs sans afficher les secrets :

```powershell
kubectl exec -it -n cofrap-data deployment/postgres -- psql -U cofrap_app -d cofrap -c 'SELECT id, username, generated_at, expires_at, active FROM users ORDER BY id;'
```

## Securite

- les mots de passe sont haches avec bcrypt et ne sont pas decryptables ;
- les secrets TOTP sont chiffres avec Fernet ;
- les cles et mots de passe Kubernetes ne sont pas versionnes ;
- les jetons de remise sont hashes en base ;
- une remise expire apres dix minutes et ne peut etre ouverte qu'une fois ;
- PostgreSQL et le gateway sont exposes localement uniquement par port-forward.

OpenFaaS Community exige des images publiques. Le Scale-to-Zero appartient aux fonctionnalites commerciales et n'est pas active dans ce PoC.

## Structure

```text
frontend/                 Interface web et proxy Nginx
k8s/                      Manifests PostgreSQL, frontend et migrations
*-user/                   Fonctions de creation et d'authentification
generate-*/               Fonctions atomiques de generation
rotate-credentials/       Renouvellement des identifiants
redeem-credentials/       Remise temporaire a usage unique
stack.yaml                Definition des fonctions OpenFaaS
*.drawio                   Diagrammes d'architecture
```