# Data Flow

## User Registration Flow
User → Frontend → API /auth/register → Validate → Hash Password → Store IP/Device → Send OTP Email → Return masked email

## Email Verification Flow
User → Frontend → API /auth/verify-otp → Verify Hash → Check Expiry → Check Attempts → Activate Account → Redirect to Login

## Login Flow
User → Frontend → API /auth/login → Validate Credentials → Check Verification → Create JWT → Record Audit Log → Return tokens

## Assessment Flow
User → AI Chat → Collect Requirements → Generate Scope → Generate RoE → Digital Signature → Document Upload → Initialize Assessment → OSINT → Attack Planning → Red Team → Risk Assessment → Report Generation
