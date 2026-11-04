cd projects/acme-app
git pull
npm install
npm run dev
git checkout -b fix/login-redirect
vim src/routes/auth.js
npm test
git add -A
git commit -m "fix: redirect after login when next param is set"
git push
gh pr create --fill
kubectl get pods -n staging
kubectl logs -n staging deploy/acme-api --tail=100
aws s3 ls s3://acme-app-uploads-staging/ | head
docker compose up -d postgres redis
psql postgres://acme:acme@localhost:5432/acme_dev -c 'select count(*) from users;'
npm run migrate
curl -s localhost:3000/healthz | jq
cd ~
ls -la Downloads
tar xzf Downloads/node-exporter.tar.gz
sudo apt update && sudo apt upgrade -y
nvm use 22
node --version
cd projects/acme-app
git log --oneline -10
git stash
git checkout main
git pull
git stash pop
npm run lint -- --fix
gh pr checks
kubectl rollout status -n staging deploy/acme-api
gcloud auth application-default login
gcloud config set project acme-app-staging
history | tail -50
