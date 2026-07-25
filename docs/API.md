# Cerberus AI — API Reference

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication
All protected endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <access_token>
```

---

## Authentication Endpoints

### POST /auth/register
Register a new user account.

**Request:**
```json
{
  "full_name": "John Doe",
  "company_name": "Acme Corp",
  "job_title": "Security Engineer",
  "email": "john@acme.com",
  "phone_number": "+1234567890",
  "company_location": "New York, USA",
  "password": "SecurePass123!",
  "confirm_password": "SecurePass123!"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Registration successful. Please verify your email.",
  "user_id": "uuid",
  "email_masked": "joh***@acme.com"
}
```

### POST /auth/verify-otp
Verify email with 6-digit OTP code.

### POST /auth/login
Authenticate and receive JWT tokens.

### POST /auth/refresh
Refresh an expired access token.

---

## Engagement Endpoints

### GET /engagements
List all engagements (paginated, filterable).

### GET /engagements/{id}
Get engagement details.

### GET /engagements/{id}/summary
Get engagement summary with phase statistics.

---

## AI Conversation Endpoints

### POST /ai/{engagement_id}/message
Send a message to the Cerberus AI agent.

### GET /ai/{engagement_id}/history
Get full conversation history.

### GET /ai/{engagement_id}/summary
Get AI-generated engagement summary.

### POST /ai/{engagement_id}/confirm-summary
Confirm summary and proceed to scope generation.

---

## OSINT Endpoints

### POST /osint/{engagement_id}/start
Start the OSINT phase.

### GET /osint/{engagement_id}/findings
Get OSINT findings (filterable by category).

### GET /osint/{engagement_id}/knowledge-graph
Get the dynamic knowledge graph.

---

## Attack Planning Endpoints

### POST /attack-planning/{engagement_id}/analyze
Start attack planning analysis.

### GET /attack-planning/{engagement_id}/paths
Get all identified attack paths.

### POST /attack-planning/{engagement_id}/approve
Approve attack plan and begin Red Team execution.

---

## Red Team Endpoints

### POST /red-team/{engagement_id}/start
Start Red Team execution.

### GET /red-team/{engagement_id}/status
Get execution status.

### GET /red-team/{engagement_id}/findings
Get confirmed vulnerabilities.

---

## Risk Assessment Endpoints

### POST /risk-assessment/{engagement_id}/start
Start risk assessment phase.

### GET /risk-assessment/{engagement_id}/summary
Get overall risk summary.

### POST /risk-assessment/{engagement_id}/validate
Run AI Decision Validation.

---

## Report Endpoints

### POST /reports/{engagement_id}/generate
Generate the final PDF report.

### GET /reports/{engagement_id}/download
Download report as PDF.

---

## Dashboard Endpoints

### GET /dashboard/overview
Get personalized dashboard overview.

### GET /dashboard/stats
Get animated dashboard statistics.

---

## Notification Endpoints

### GET /notifications
List user notifications.

### PUT /notifications/{id}/read
Mark notification as read.

---

## Error Response Format
```json
{
  "success": false,
  "error": {
    "code": 401,
    "message": "Invalid or expired token"
  }
}
```

## Rate Limits
- General: 60 requests/minute
- Login: 5 requests/minute
