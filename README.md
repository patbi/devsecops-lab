[![DevSecOps Pipeline](https://github.com/patbi/devsecops-lab/actions/workflows/security.yml/badge.svg)](https://github.com/patbi/devsecops-lab/actions/workflows/security.yml)


[![CodeQL](https://github.com/patbi/devsecops-lab/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/patbi/devsecops-lab/actions/workflows/github-code-scanning/codeql)


# Nous avons couvert la mise en place d'un Pipeline DevSecOps avec GitHub Actions

*Comprendre le DevSecOps grâce à l'apprentissage par la pratique*

# Table des matières

1. [Etape 1: Mettre en place un pipeline CI/CD sécurisé]()

## Scénario

Nous héritons d'une application Node.js volontairement vulnérable. Notre mission : créer un pipeline DevSecOps pour détecter et corriger toutes les failles avant le déploiement.


## Section 1 : Setup
### 1.1 Créer le projet

```bash
# Créer un nouveau repo sur GitHub
# Puis cloner
git clone https://github.com/<notre-username>/<repo>.git
cd devsecops-lab

# Structure
mkdir -p src .github/workflows
```

### 1.2 Application vulnérable : src/package.json :

```bash
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "jsonwebtoken": "8.5.1"
  }
}
```

### src/server.js :

```bash
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();


const DB_CONNECTION = "mongodb://admin:SuperSecret123!@prod-db.company.com:27017/myapp";
const STRIPE_SECRET_KEY = "sk_live_51Hqp9K2eZvKYlo2C8xO3n4y5z6a7b8c9d0e1f2g3h4i5j";
const SENDGRID_API_KEY = "SG.nExT2-QRDzJcEV39HqCxTg.KnLmOpQrStUvWxYz1234567890aBcDeF";
app.use(express.json());

app.post('/api/login', (req, res) => {
 const { username, password } = req.body;

 if (username === 'admin' && password === 'admin') {
 const token = jwt.sign({ username }, JWT_SECRET);
 res.json({ token });
 } else {
 res.status(401).json({ error: 'Invalid credentials' });
 }
});

app.get('/debug', (req, res) => {
 res.json({
    dbConnection: DB_CONNECTION,
    stripeKey: STRIPE_SECRET_KEY,
    sendgridKey: SENDGRID_API_KEY,
    env: process.env
  });
});
app.listen(3000, () => console.log('Server running on port 3000'));
```


### Dockerfile :

```bash
FROM node:14
WORKDIR /app
COPY src/package*.json ./
RUN npm install
COPY src/ ./
EXPOSE 3000
CMD ["node", "server.js"]
```


2. [Etape 2: Détecter automatiquement les vulnérabilités (SAST, SCA, DAST)]()
	
## Section 2 : Pipeline DevSecOps

### 2.1 Workflow GitHub Actions | Créez le fichier security.yml dans le rep | .github/workflows/security.yml 

### Ensuite entrez le code ci-dessous  .

```bash
name: DevSecOps Pipeline

on: [push, pull_request]

jobs:
  # ═══════════════════════════════════════
  # 1. BUILD
  # Construit l'image Docker de l'application
  # Permet de valider que le code compile et de préparer l'image pour le scan de vulnérabilités
  # ═══════════════════════════════════════
  build:
    name: 🏗️ Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t vuln-app:${{ github.sha }} .
      
      - name: Save image
        run: docker save vuln-app:${{ github.sha }} > image.tar
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: docker-image
          path: image.tar

  # ═══════════════════════════════════════
  # 2. SAST - Analyse statique du code (Static Application Security Testing)
  # Détecte les vulnérabilités dans le CODE SOURCE : injection SQL, XSS, failles de sécurité
  # Outil : Semgrep avec règles OWASP Top 10, security-audit, et détection de secrets
  # ═══════════════════════════════════════
  sast:
    name: 🔍 SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

  # ═══════════════════════════════════════
  # 3. SCA - Analyse des dépendances (Software Composition Analysis)
  # Détecte les vulnérabilités dans les BIBLIOTHÈQUES et packages tiers (npm, etc.)
  # Outil : npm audit pour vérifier les CVE connues dans les dépendances Node.js
  # ═══════════════════════════════════════
  sca:
    name: 📦 SCA
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install dependencies
        working-directory: ./src
        run: npm install

      - name: npm audit
        working-directory: ./src
        run: |
          npm audit --json > audit.json
          npm audit

      - uses: actions/upload-artifact@v4
        with:
          name: npm-audit
          path: src/audit.json

  # ═══════════════════════════════════════
  # 4. SECRET DETECTION
  # Détecte les SECRETS accidentellement committés : clés API, mots de passe, tokens
  # Outil : Gitleaks qui scanne tout l'historique Git (fetch-depth: 0)
  # ⚠️ Critique : évite les fuites de credentials et violations de sécurité
  # ═══════════════════════════════════════
  secrets:
    name: 🔐 Secrets
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # ═══════════════════════════════════════
  # 5. CONTAINER SCAN
  # Scanne l'IMAGE DOCKER pour détecter les vulnérabilités dans l'OS et les packages système
  # Outil : Trivy qui analyse les CVE dans les couches Docker (image de base, packages installés)
  # Recherche les vulnérabilités CRITICAL uniquement (pragmatisme DevSecOps)
  # ═══════════════════════════════════════
  container-scan:
    name: 🐳 Container Scan
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: docker-image

      - name: Load image
        run: docker load < image.tar

      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: vuln-app:${{ github.sha }}
          format: 'table'
          exit-code: '1'
          severity: 'CRITICAL'

  # ═══════════════════════════════════════
  # 6. RAPPORT FINAL
  # Génère un résumé de tous les scans de sécurité
  # Vérifie le statut de chaque job et fait ÉCHOUER le pipeline si des vulnérabilités sont détectées
  # S'exécute toujours (if: always()) même si des jobs précédents ont échoué
  # ═══════════════════════════════════════
  report:
    name: 📊 Report
    runs-on: ubuntu-latest
    needs: [sast, sca, secrets, container-scan]
    if: always()
    steps:
      - name: Generate JSON Report
        run: |
          cat > security-report.json <<EOF
          {
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
            "repository": "${{ github.repository }}",
            "commit": "${{ github.sha }}",
            "branch": "${{ github.ref_name }}",
            "workflow_run": "${{ github.run_id }}",
            "results": {
              "sast": {
                "status": "${{ needs.sast.result }}",
                "tool": "Semgrep"
              },
              "sca": {
                "status": "${{ needs.sca.result }}",
                "tool": "npm audit"
              },
              "secrets": {
                "status": "${{ needs.secrets.result }}",
                "tool": "Gitleaks"
              },
              "container_scan": {
                "status": "${{ needs.container-scan.result }}",
                "tool": "Trivy"
              }
            },
            "summary": {
              "total_checks": 4,
              "passed": $(echo '${{ needs.sast.result }} ${{ needs.sca.result }} ${{ needs.secrets.result }} ${{ needs.container-scan.result }}' | grep -o "success" | wc -l),
              "failed": $(echo '${{ needs.sast.result }} ${{ needs.sca.result }} ${{ needs.secrets.result }} ${{ needs.container-scan.result }}' | grep -o "failure" | wc -l),
              "overall_status": "$([[ "${{ needs.sast.result }}" == "failure" ]] || [[ "${{ needs.sca.result }}" == "failure" ]] || [[ "${{ needs.secrets.result }}" == "failure" ]] || [[ "${{ needs.container-scan.result }}" == "failure" ]] && echo "FAILED" || echo "PASSED")"
            }
          }
          EOF

          echo "📄 Security Report Generated:"
          cat security-report.json | jq '.'

      - name: Upload JSON Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json

      - name: Summary
        run: |
          echo "## 🔒 Security Scan Complete" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### Job Results:" >> $GITHUB_STEP_SUMMARY
          echo "- SAST: ${{ needs.sast.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- SCA: ${{ needs.sca.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- Secrets: ${{ needs.secrets.result }}" >> $GITHUB_STEP_SUMMARY
          echo "- Container Scan: ${{ needs.container-scan.result }}" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "📥 **JSON Report available in artifacts**" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY

          if [[ "${{ needs.sast.result }}" == "failure" ]] || \
             [[ "${{ needs.sca.result }}" == "failure" ]] || \
             [[ "${{ needs.secrets.result }}" == "failure" ]] || \
             [[ "${{ needs.container-scan.result }}" == "failure" ]]; then
            echo "❌ **Security issues detected!**" >> $GITHUB_STEP_SUMMARY
            echo "" >> $GITHUB_STEP_SUMMARY
            echo "⚠️ Please review the failed jobs above" >> $GITHUB_STEP_SUMMARY
            exit 1
          else
            echo "✅ All security checks passed" >> $GITHUB_STEP_SUMMARY
          fi
```


3. [Etape 3: Corriger les failles de sécurité courantes]()

## Section 3 : Analyse des résultats 

### 3.1 Vulnérabilités détectées

Après l'exécution du pipeline, nous observons ceci :

![Preview](https://github.com/patbi/devsecops-lab/blob/main/vul-d.png) 

### 3.1 Vulnérabilités détectées

![Preview](https://github.com/patbi/devsecops-lab/blob/main/ic-d.png)


- GitHub Security : Onglet "Security" > "Code scanning"

- Artifacts : Télécharger les rapports JSON

- Logs : Détails dans chaque job


![Preview](https://github.com/patbi/devsecops-lab/blob/main/wkf-1.png) 


4. [Etape 4: Comprendre le DevSecOps en pratique]()

## Section 4 : Corrections

### 4.1 Mise à jour des dépendances | src/package.json (corrigé) :

```bash
{
 "name": "secure-app",
 "version": "2.0.0",
 "dependencies": {
 "express": "^4.18.2",
 "jsonwebtoken": "^9.0.2",
 "helmet": "^7.1.0",
 "express-rate-limit": "^7.1.0",
 "express-validator": "^7.0.1",
 "dotenv": "^16.3.1"
 }
}
```



### 4.2 Code sécurisé | src/server.js (corrigé) :

```bash
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// ✅ Secret depuis variable d'environnement
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}

// ✅ Sécurité
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// ✅ Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

// ✅ Validation des entrées
app.post('/api/login',
  loginLimiter,
  [
    body('username').isString().trim().notEmpty(),
    body('password').isString().notEmpty().isLength({ min: 8 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { username, password } = req.body;
    
    // Ici : vérification réelle avec bcrypt + DB
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
      const token = jwt.sign(
        { username },
        SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  }
);

// ✅ Endpoint de santé (sans infos sensibles)
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// ✅ Pas d'endpoint de debug en production
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug', (req, res) => {
    res.json({ message: 'Debug mode' });
  });
}

app.listen(3000, () => console.log('✅ Secure server running'));
```

### 4.3 Variables d'environnement | .env.example :

```bash
JWT_SECRET=generate-a-strong-random-secret-min-32-chars
ADMIN_USER=admin
ADMIN_PASS=strong-password-here
NODE_ENV=production
```

![Preview](https://github.com/patbi/devsecops-lab/blob/main/add-pk.png) 


### Ajoutez .env au .gitignore :

```bash
echo ".env" >> .gitignore
```

### 4.4 Dockerfile sécurisé

```bash
# ✅ Image Alpine (plus légère et sécurisée) - Version la plus récente
FROM node:22-alpine

WORKDIR /app

# ✅ Copie des dépendances d'abord (cache)
COPY src/package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY src/ ./

# ✅ Utilisateur non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3000

# ✅ Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

CMD ["node", "server.js"]
```

### 4.5 GitHub Secrets

- Allez dans Settings > Secrets and variables > Actions
- Ajoutez :

```bash
JWT_SECRET : (générez avec openssl rand -base64 32)
ADMIN_USER : admin
ADMIN_PASS : (mot de passe fort)
```

### 4.6 Section | SAST - Analyse statique du code (Static Application Security Testing) - Updated

```bash
  sast:
    name: 🔍 SAST
    runs-on: ubuntu-latest
    steps:
      - name: checkout code
        uses: actions/checkout@v4
      
      - name: Install semgrep
        run: pip install Semgrep 
      
      - name: Run semgrep
        run: semgrep --config auto --error || true
```


### 4.7 Commit des corrections

```bash
git add .
git commit -m "fix: Apply all security fixes"
git push origin main
```

Le pipeline devrait maintenant être vert ! ✅

