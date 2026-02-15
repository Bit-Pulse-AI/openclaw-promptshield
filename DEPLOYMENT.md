# Deployment Guide: Push to GitHub

## Overview

This guide walks you through pushing the OpenClaw Shield repository to your GitHub account.

## Prerequisites

1. **GitHub Account**: Ensure you have a GitHub account
2. **Git Installed**: Git should be installed on your local machine
3. **GitHub CLI (Optional)**: For easier repository creation

## Method 1: Using GitHub Web Interface (Recommended)

### Step 1: Create Repository on GitHub

1. Go to https://github.com/new
2. Set repository details:
   - **Repository name**: `openclaw-shield`
   - **Description**: "AI Security Posture Management for OpenClaw - Integrates Azure AI Content Safety, Prompt Shields, and Microsoft Purview to protect AI agents from prompt injections, data leakage, and rogue behavior"
   - **Visibility**: Choose Public or Private
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
3. Click "Create repository"

### Step 2: Push Local Repository

On your local machine (or where you have the repository):

```bash
# Navigate to the repository
cd /home/claude/openclaw-shield

# Add GitHub remote (replace USERNAME with your GitHub username)
git remote add origin https://github.com/junhao-bitpulse/openclaw-shield.git

# Verify remote
git remote -v

# Push to GitHub
git push -u origin master
```

If you prefer to use `main` as the default branch name:

```bash
# Rename master to main
git branch -M main

# Push to GitHub
git push -u origin main
```

### Step 3: Authenticate

When prompted for credentials:

**Option A: Personal Access Token (Recommended)**
1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Set scopes: `repo` (full control of private repositories)
4. Copy the token
5. Use token as password when pushing

**Option B: SSH (More Secure)**
```bash
# Generate SSH key (if you don't have one)
ssh-keygen -t ed25519 -C "jun@bitpulse.ai"

# Add SSH key to ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Copy public key
cat ~/.ssh/id_ed25519.pub

# Add to GitHub: Settings → SSH and GPG keys → New SSH key
# Then use SSH URL instead:
git remote set-url origin git@github.com:junhao-bitpulse/openclaw-shield.git
git push -u origin master
```

---

## Method 2: Using GitHub CLI

If you have GitHub CLI installed:

```bash
# Authenticate with GitHub
gh auth login

# Create repository and push
cd /home/claude/openclaw-shield
gh repo create openclaw-shield --public --source=. --remote=origin --push

# Or for private repository:
gh repo create openclaw-shield --private --source=. --remote=origin --push
```

---

## Post-Deployment Steps

### 1. Set Repository Topics

On GitHub, add topics to help others discover your repository:
- `ai-security`
- `prompt-injection`
- `azure`
- `openai`
- `claude`
- `computer-use`
- `dlp`
- `microsoft-purview`
- `security-posture-management`

### 2. Configure Branch Protection

Settings → Branches → Add rule:
- Branch name pattern: `main` (or `master`)
- ✅ Require pull request reviews before merging
- ✅ Require status checks to pass before merging
- ✅ Require signed commits (optional)

### 3. Enable GitHub Actions

The repository includes a CI/CD workflow (`.github/workflows/ci.yml`) that will automatically run on pushes and pull requests.

To enable:
1. Go to repository → Actions tab
2. Click "I understand my workflows, go ahead and enable them"

### 4. Add Repository Secrets

For CI/CD to work with Azure integration tests (optional):

Settings → Secrets and variables → Actions → New repository secret:
- `AZURE_CONTENT_SAFETY_ENDPOINT`
- `AZURE_CONTENT_SAFETY_KEY`

### 5. Update README Badges (Optional)

Add status badges to your README:

```markdown
![CI/CD](https://github.com/junhao-bitpulse/openclaw-shield/workflows/CI%2FCD/badge.svg)
![License](https://img.shields.io/github/license/junhao-bitpulse/openclaw-shield)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
```

### 6. Create Initial Release

```bash
# Tag the initial version
git tag -a v0.1.0 -m "Initial release: OpenClaw Shield v0.1.0"
git push origin v0.1.0

# Or use GitHub Releases UI:
# Go to Releases → Draft a new release
# Tag: v0.1.0
# Title: OpenClaw Shield v0.1.0 - Initial Release
# Description: <copy from CHANGELOG>
```

---

## Repository Structure

After pushing, your repository will look like this:

```
openclaw-shield/
├── .github/
│   └── workflows/
│       └── ci.yml              # CI/CD pipeline
├── docs/
│   ├── api-reference.md        # API documentation
│   ├── incident-response.md    # Security incident playbook
│   └── purview-integration.md  # Purview DLP integration guide
├── openclaw_shield/
│   ├── __init__.py
│   └── shields.py              # Main shield implementations
├── .env.example                # Environment template
├── .gitignore
├── Dockerfile
├── LICENSE
├── README.md
├── docker-compose.yml
├── requirements.txt
├── setup.sh                    # Setup script
└── DEPLOYMENT.md              # This file
```

---

## Sharing & Collaboration

### Make Repository Public

If you want to share with the community:

1. Settings → Danger Zone → Change repository visibility
2. Select "Make public"
3. Type repository name to confirm

### Invite Collaborators

Settings → Collaborators → Add people

### Create Discussion Forum

Settings → Features → Enable Discussions

---

## Marketing & Community

### 1. Share on Social Media

Example announcement:

> 🛡️ Excited to announce OpenClaw Shield! 
> 
> An open-source AI Security Posture Management framework for OpenClaw (Claude Computer Use), integrating Azure AI Content Safety & Microsoft Purview.
> 
> Features:
> ✅ 3-layer defense (Input/Execution/Output)
> ✅ Prompt injection detection
> ✅ DLP integration
> ✅ Incident response playbook
> 
> Check it out: https://github.com/junhao-bitpulse/openclaw-shield
> 
> #AIsSecurity #OpenSource #Azure #Claude

### 2. Submit to Awesome Lists

- Awesome AI Security
- Awesome LLM Security
- Awesome Azure

### 3. Write Blog Post

Consider writing a blog post explaining:
- Why you built this
- Architecture decisions
- Integration with Azure/Purview
- Use cases and examples

### 4. Present at Meetups

- AI Security meetups
- Azure user groups
- DevSecOps conferences

---

## Continuous Development

### Branching Strategy

```bash
# Create development branch
git checkout -b develop
git push -u origin develop

# For features
git checkout -b feature/new-shield develop
# ... make changes ...
git push -u origin feature/new-shield
# Create pull request on GitHub
```

### Release Process

1. Update version in `openclaw_shield/__init__.py`
2. Update CHANGELOG.md
3. Create release branch: `git checkout -b release/v0.2.0`
4. Tag: `git tag -a v0.2.0 -m "Release v0.2.0"`
5. Push: `git push origin v0.2.0`
6. Create GitHub Release with release notes

---

## Troubleshooting

### Authentication Issues

**Problem**: `fatal: Authentication failed`

**Solution**:
```bash
# Clear cached credentials
git credential-cache exit

# Try again with fresh token
git push -u origin master
```

### Large File Warning

**Problem**: Warning about large files

**Solution**:
```bash
# Use Git LFS for large files
git lfs install
git lfs track "*.model"
git lfs track "*.bin"
```

### Push Rejected

**Problem**: `! [rejected] master -> master (fetch first)`

**Solution**:
```bash
# Pull latest changes
git pull origin master --rebase

# Push again
git push -u origin master
```

---

## Next Steps

After successful deployment:

1. ✅ Star your own repository (for visibility)
2. ✅ Watch repository for notifications
3. ✅ Set up project board for issue tracking
4. ✅ Create CONTRIBUTING.md for community guidelines
5. ✅ Add CODE_OF_CONDUCT.md
6. ✅ Set up Discussions for Q&A
7. ✅ Create issue templates
8. ✅ Add security policy (SECURITY.md)

---

## Support

If you encounter issues:

1. Check GitHub's authentication documentation
2. Visit https://github.com/junhao-bitpulse/openclaw-shield/issues
3. Contact: jun@bitpulse.ai

---

**Congratulations! Your repository is now on GitHub! 🎉**
