# FinalWebAPP File Index

This index documents the current project structure by responsibility.

## 1. Backend Core
- main.py: Main Flask application, route handlers, security, auth, workflow, reports, mobile API, PDF annotation helpers.
- config.py: Environment loading and MySQL connection factory.
- sendotp.py: OTP generation/verification and email sending helpers.
- requirements.txt: Python dependency definitions.
- locustfile.py: Basic load test script.
- README.md: Project-level readme (present in root).

## 2. Backend Tests
- tests/conftest.py: Pytest fixtures and test app setup.
- tests/test_app.py: Route/helper tests.

## 3. Web Templates
- templates/admin.html: Admin dashboard and management views.
- templates/annotate.html: PDF annotation UI.
- templates/dean.html: Dean/Reviewer dashboard.
- templates/forgot_password.html: Password reset request page.
- templates/gsddashboard.html: GSD dashboard.
- templates/IT.html: IT management dashboard.
- templates/login.html: Web login page.
- templates/reset_password.html: Token-based reset page.
- templates/signup.html: Signup page with OTP verification flow.
- templates/user.html: User dashboard and request submission modal.

## 4. Web Static Assets
### 4.1 Shared root static files
- static/chart.js: Chart utility for reports.
- static/IT.css: IT dashboard styles.
- static/login.css: Login styles.
- static/login.js: Login page interactions.
- static/pdf.min.js: PDF processing/view support.
- static/signup.css: Signup styles.
- static/PHINMAEd_Logo.png, static/eye.png, static/hide.png: image assets.

### 4.2 Admin assets
- static/admin/admin.css: Admin-specific styles.
- static/admin/admin.js: Admin-specific behavior.
- static/admin/sign.css: Signature-related styles.
- static/admin/sign.js: Signature-related behavior.

### 4.3 Dean assets
- static/dean/dean.css
- static/dean/dean.js

### 4.4 GSD assets
- static/gsd/gsd.css
- static/gsd/gsd.js

### 4.5 User assets
- static/user/user.css
- static/user/user.js
- static/user/sweetalert.js
- static/user/coc.png
- static/user/coclogo.png

### 4.6 Toast utility
- static/alltoast/toast.js

### 4.7 Vendor assets
- static/vendor/lucide.min.js

### 4.8 Font assets
- static/fonts/css/*.css
- static/fonts/webfonts/*

## 5. Mobile App (Flutter)
Root: moble/app/

### 5.1 App logic
- moble/app/lib/main.dart: App entry and session gate.
- moble/app/lib/api_service.dart: HTTP API service layer.
- moble/app/lib/login_page.dart: Login/signup/OTP UI and logic.
- moble/app/lib/homepage.dart: Main app pages and navigation.

### 5.2 Flutter platform folders
- moble/app/android/
- moble/app/ios/
- moble/app/linux/
- moble/app/macos/
- moble/app/web/
- moble/app/windows/

### 5.3 Flutter config and metadata
- moble/app/pubspec.yaml
- moble/app/analysis_options.yaml
- moble/app/README.md

## 6. Generated or Tooling Folders
- .git/: Git metadata.
- .venv/: Virtual environment.
- .pytest_cache/: Test cache.
- __pycache__/: Python bytecode cache.
- moble/app/build/: Generated Flutter build output.
- .vscode/: Editor workspace settings.

## 7. Documentation Files
- docs/SYSTEM_DOCUMENTATION.md: Full architecture, API, security, and operations documentation.
- docs/FILE_INDEX.md: This file-level index.
