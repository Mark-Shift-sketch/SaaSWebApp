# FinalWebAPP System Documentation

## 1. System Overview
FinalWebAPP is a request submission and approval platform with:
- Web interface for User, Reviewer, Dean, Admin, AssistantAdmin, SuperAdmin, IT.
- Mobile Flutter client for User role flows.
- Workflow-driven routing for approvals and send-back actions.
- Document upload, annotation, signed PDF generation, and report export.
- OTP-based verification for signup and secure admin PIN operations.

Primary backend entrypoint:
- main.py

Supporting backend modules:
- config.py
- sendotp.py

## 2. High-Level Architecture
### Backend
- Framework: Flask
- Database: MySQL via mysql-connector-python
- Session auth for web routes
- Bearer token auth for mobile API routes
- Security middleware and headers configured in main.py

### Web Frontend
- Jinja templates in templates/
- Feature-specific JS/CSS in static/

### Mobile Frontend
- Flutter app in moble/app/
- API consumption from Flask endpoints under /api/mobile/* and selected shared APIs

### Testing and Load
- Unit/integration tests under tests/
- Load test script in locustfile.py

## 3. Directory and File Documentation
## 3.1 Root Backend Files
### main.py
Monolithic Flask application containing:
- Environment and app bootstrapping
- Security settings (session cookies, CSRF setup, CORS, security headers)
- Rate limiting (Flask-Limiter)
- Authentication helpers (session and token)
- Dashboard pages and role routing
- Request type management
- Request create/read/update flows
- Approval, rejection, send-back workflow control
- Admin PIN setup, OTP verification, amount edit protection
- Annotation APIs and signed PDF generation
- Report APIs and CSV export
- IT administration APIs and actions
- Web auth flows (signup, login, forgot/reset password, change password)
- Mobile APIs (departments, OTP, signup, login, profile, requests, notifications)

### config.py
- Loads environment variables
- Exposes database connection helper get_connection
- Holds email credential variables consumed by email sender functions

### sendotp.py
- OTP send and verify utilities
- Signup OTP issue/verify logic with cooldown and expiry checks
- Generic email helpers for request updates and CC with attachments

### requirements.txt
- Python dependency lock file
- Includes Flask, Flask-WTF, Flask-CORS, Flask-Limiter, MySQL connector, Argon2, PDF tooling, test tooling, and additional packages

### locustfile.py
- Basic Locust performance script
- Simulates repeated access to /login and /

## 3.2 Templates (templates/)
### login.html
- Web login page

### signup.html
- Web signup page with OTP-first flow

### forgot_password.html
- Password reset request page

### reset_password.html
- Reset password form using signed token route

### user.html
- User dashboard page
- Request creation modal and request list/history sections

### dean.html
- Dean/Reviewer dashboard page

### admin.html
- Admin/AssistantAdmin/SuperAdmin dashboard page
- Includes request management, reports, notifications, settings, PIN controls

### gsddashboard.html
- GSD dashboard page

### IT.html
- IT management dashboard (users, departments, roles, positions)

### annotate.html
- Document annotation page for request PDFs

## 3.3 Static Assets (static/)
### static/admin/
- admin.js: Admin dashboard behavior, table filtering, workflow actions, PIN settings, modals, report interactions
- admin.css: Admin layout, components, modals, toasts
- sign.js / sign.css: Signature-related UI behavior/styles used by admin flow

### static/dean/
- dean.js: Dean dashboard interactions, status updates, notifications, filtering
- dean.css: Dean dashboard styling

### static/gsd/
- gsd.js: GSD shipment and copy modal interactions, status toasts
- gsd.css: GSD styling

### static/user/
- user.js: User dashboard loading, request submission, file validation, notifications, toasts, modal logic
- user.css: User dashboard styling, modals, toast UI
- sweetalert.js: Alert utility

### static/alltoast/
- toast.js: Shared toast behavior

### static/vendor/
- lucide.min.js: Icon library script

### static/fonts/
- Font Awesome and webfont assets

### other static files
- chart.js: Charting utility used in reporting screens
- login.js, login.css, signup.css, IT.css: page-specific scripts and styles
- pdf.min.js: PDF viewing/interaction support

## 3.4 Mobile App Files (moble/app/lib/)
### main.dart
- Flutter app entry point
- Session gate to route user to login or homepage based on stored token + profile fetch

### login_page.dart
- Mobile login and signup UI
- OTP send/verify flow for mobile signup
- Token persistence with shared_preferences

### api_service.dart
- Base URL resolution by platform
- API wrapper methods:
  - fetchMobileUserProfile
  - fetchUserNotifications
  - fetchActivityLogs
  - fetchUserDashboard

### homepage.dart
- Mobile home shell
- Dashboard, Notifications, Settings tabs
- Reads API data and manages local notification read state

## 3.5 Tests (tests/)
### conftest.py
- Pytest setup
- Test app fixture with SECRET_KEY fallback and CSRF disabled in tests

### test_app.py
- Route-level and helper-level tests including:
  - login page availability
  - auth redirects
  - dashboard load with mocked DB
  - token helpers
  - password reset helpers
  - logout behavior
  - security headers

## 4. Backend API Documentation
## 4.1 Page Routes
- GET /
- GET /dean
- GET /udashboard
- GET /gsd_dashboard
- GET /admin
- GET /IT
- GET /annotate/<request_id>
- GET /download_attachment/<request_id>
- GET /download_template/<type_id>
- GET /logout

## 4.2 Authentication and Account Routes
- GET, POST /signup
- GET, POST /login
- GET, POST /forgot-password
- GET, POST /reset-password/<token>
- POST /change_password
- POST /delete_account

## 4.3 OTP Routes
- POST /send-otp
- POST /verify

## 4.4 User APIs
- GET, OPTIONS /api/user_dashboard
- GET /api/user-profile
- GET, OPTIONS /api/user_notifications
- GET, POST /api/requests
- GET /api/request-types
- POST /create_request
- POST /api/request/<request_id>/user-complete

## 4.5 Admin APIs
- GET /api/admin/live
- GET /api/admin/pin/status
- POST /api/admin/pin/setup
- POST /api/admin/pin/request-otp
- POST /api/admin/pin/verify-otp
- POST /api/admin/pin/change
- POST /api/request/<request_id>/amount
- GET /api/request/<request_id>/workflow
- POST /api/request/<request_id>/workflow
- POST /api/request/<request_id>/status
- POST /api/request/<request_id>/send-back
- POST /api/request/<request_id>/complete
- POST /api/request/<request_id>/admin-complete
- POST /api/request/<request_id>/cc

## 4.6 Request Type Management
- POST /add_request_type
- POST /edit_request_type
- GET /delete_request_type/<id>

## 4.7 Annotation and PDF APIs
- GET /api/request/<request_id>/annotations
- POST /api/request/<request_id>/annotations
- POST /api/request/<request_id>/annotate

## 4.8 Reports and Logs APIs
- GET /api/reports
- GET /api/reports/export
- GET /api/reports/chartdata
- GET /api/activity_logs

## 4.9 IT Administration APIs
- GET /api/it/stats
- GET /api/it/users
- POST /api/it/user/update
- POST /create_user
- POST /create_role
- POST /create_position
- POST /create_dept

## 4.10 Mobile APIs
- GET /api/mobile/departments
- POST, OPTIONS /api/mobile/send-otp
- POST, OPTIONS /api/mobile/verify-otp
- POST, OPTIONS /api/mobile/signup
- POST /api/mobile/login
- GET /api/mobile/user-profile
- GET /api/mobile/requests
- GET /api/mobile/notifications

## 5. Database Table Usage Summary
Tables referenced by application logic include:
- users
- roles
- departments
- positions
- requests
- request_status
- request_types
- request_type_reviewers
- request_type_approvers
- request_workflow_reviewers
- request_workflow_approvers
- request_actions
- request_annotations
- otp_codes
- activity_logs
- notifications
- inventory

Note:
- main.py contains runtime schema checks for admin PIN columns on users table.

## 6. Security Model Documentation
Implemented controls:
- Mandatory SECRET_KEY at startup
- Session cookie settings (HTTPOnly, SameSite, Secure via env)
- CSRF protection for form routes, explicit exemptions for mobile JSON APIs
- CORS policy for API routes
- Security headers after each response (nosniff, frame deny, referrer policy, CORP, CSP)
- Rate limits via Flask-Limiter (global and endpoint-specific)
- Argon2id password hashing for user passwords with verify and rehash support
- OTP verification with cooldown and expiry
- Role and session guards on sensitive routes
- Admin PIN lockout logic for amount-edit action path
- Upload guards: size limit, extension, mime and signature checks for PDFs

## 7. Environment Variables
Required and commonly used variables:
- SECRET_KEY
- DB_HOST
- DB_USER
- DB_PASSWORD
- DB_NAME
- email
- pass

Security/session variables:
- SESSION_COOKIE_SAMESITE
- SESSION_COOKIE_SECURE
- PERMANENT_SESSION_LIFETIME

Rate limiting variables:
- RATE_LIMIT_DEFAULT_DAY
- RATE_LIMIT_DEFAULT_HOUR
- RATE_LIMIT_STORAGE_URI

Network/runtime variables:
- FRONTEND_ORIGINS
- PORT
- FLASK_DEBUG

## 8. Request Lifecycle
1. User creates request with amount and PDF attachment.
2. Request is assigned to first workflow stage.
3. Reviewer/approver performs approve/reject/send-back actions.
4. Status and request_actions are updated.
5. Notification and email flows are triggered.
6. On completion, admin/user completion and optional CC flow are available.
7. Annotation routes can store overlays and produce signed PDFs.

## 9. Operational Documentation
## 9.1 Local Run
- Install dependencies from requirements.txt
- Set required environment variables
- Run main.py with configured Python interpreter

## 9.2 Tests
- Run pytest from project root
- Current tests validate routing, token helpers, basic security headers, and selected auth flows

## 9.3 Load Test
- locustfile.py provides starter tasks against login/home
- Extend with authenticated and workflow scenarios for realistic testing

## 10. Known Maintenance Notes
- main.py is large and can be split into blueprints for maintainability:
  - auth
  - user
  - admin
  - it
  - mobile
  - reports
- Consider documenting a formal database schema migration flow instead of runtime DDL checks.
- Keep API contracts in sync with Flutter client methods in api_service.dart.

## 11. Suggested Next Documentation Files (Optional)
If deeper docs are needed, add:
- docs/API_REFERENCE.md with request and response samples
- docs/DB_SCHEMA.md with table/column definitions and indexes
- docs/DEPLOYMENT.md for Gunicorn, reverse proxy, TLS, and env setup
- docs/TROUBLESHOOTING.md for common runtime issues
