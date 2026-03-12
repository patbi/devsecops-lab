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

2. [Etape 2: Détecter automatiquement les vulnérabilités (SAST, SCA, DAST)]()
	
	 - step
	 - step
	 - step
	 - step
	 - step
	 - step

3. [Etape 3: Corriger les failles de sécurité courantes]()

	 - step
	 - step
	 - step
	 - step
	 - step
	 - step

4. [Etape 4: Comprendre le DevSecOps en pratique]()

	 - step
	 - step
	 - step
	 - step
	 - step
	 - step

