# CI/CD Setup Guide

This repository now has two GitHub Actions workflows:

- CI: .github/workflows/ci.yml
- CD: .github/workflows/cd.yml

## What CI does

- Runs Flask backend tests in RequestingAndApproval with pytest.

## What CD does

- Packages RequestingAndApproval as a downloadable build artifact.
- Builds and pushes a Docker image for the backend to GHCR.
- Optionally deploys backend to your server via SSH if deploy secrets are configured.

## Required repository secrets

### For optional backend server deployment over SSH

- DEPLOY_HOST
- DEPLOY_USER
- DEPLOY_SSH_KEY
- DEPLOY_GHCR_USER
- DEPLOY_GHCR_TOKEN
- SECRET_KEY
- JWT_SECRET_KEY
- DB_HOST
- DB_USER
- DB_PASS
- DB_NAME
- RATE_LIMIT_STORAGE_URI
- FRONTEND_ORIGINS

## Notes

- If SSH deploy secrets are missing, the backend server deploy job is skipped.
- Docker image is always pushed to GHCR on push to main/master.
- Deploy job now also requires RATE_LIMIT_STORAGE_URI and FRONTEND_ORIGINS for production-safe startup.
