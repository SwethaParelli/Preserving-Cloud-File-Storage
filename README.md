# Privacy-Preserving Cloud File Storage

A full-stack secure web application designed to store users' files in cloud storage while guaranteeing absolute data confidentiality and integrity through client/server **AES-256-GCM authenticated encryption** and **SHA-256 checksum verification**.

---

## 📌 Problem Statement

In conventional cloud storage architectures, files are often stored in plaintext or encrypted with server-managed keys where the storage provider or malicious cloud administrators can inspect, leak, or tamper with sensitive user documents. 

**Privacy-Preserving Cloud File Storage** resolves this vulnerability by ensuring that:
1. **Zero Plaintext in Cloud**: Plaintext files are never stored on disk or transferred unencrypted to cloud providers like AWS S3.
2. **Authenticated Encryption (AEAD)**: Every file is encrypted using **AES-256-GCM** with a cryptographically fresh 96-bit nonce and an authentication tag that detects any unauthorized modification or bit-flipping.
3. **End-to-End File Integrity**: Pre-encryption SHA-256 hashes are calculated and compared against decrypted data upon retrieval using constant-time comparisons.
4. **Zero Plaintext Passwords**: User credentials are protected using salted **bcrypt** hashing.

---

## 🎯 Objectives

- **Confidentiality**: Protect data at rest in cloud storage using AES-256 in Galois/Counter Mode (GCM).
- **Integrity & Authenticity**: Guarantee that any tampering with ciphertext or metadata immediately causes decryption failure.
- **Granular Access Control**: Support direct user-to-user file sharing with fine-grained permission levels (*View Only* or *Download*).
- **Time-Limited Expiring Links**: Enable users to generate temporary, single-use or time-bounded public access links protected by high-entropy random tokens.
- **Comprehensive Audit Trail**: Maintain an immutable chronological security audit log tracking logins, uploads, downloads, sharing, revocations, and deletions.
- **Hybrid Storage Capability**: Seamlessly operate with AWS S3 in production or an offline encrypted local store for development and academic evaluation.

---

## 🏗️ System Architecture

```
                                  +---------------------------------------+
                                  |         Web Browser Frontend          |
                                  |   (HTML5 / Modern CSS / Vanilla JS)   |
                                  +-------------------+-------------------+
                                                      |
                                           HTTPS / JSON REST API
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |       Flask Application Server        |
                                  |    Authentication & Session Engine    |
                                  +-------------------+-------------------+
                                                      |
                     +--------------------------------+--------------------------------+
                     |                                |                                |
                     v                                v                                v
     +-------------------------------+ +-------------------------------+ +-------------------------------+
     |   Cryptographic Core Engine   | |     Database Engine (Mongo)   | |    Cloud Storage Manager      |
     | ----------------------------- | | ----------------------------- | | ----------------------------- |
     | • AES-256-GCM (256-bit AEAD)  | | • users                       | | • AWS S3 (Encrypted Objects)  |
     | • 96-bit Random Nonce/IV      | | • files (Metadata & SHA-256)  | | • Local Encrypted Storage     |
     | • SHA-256 Integrity Hashes    | | • file_shares                 | |   (Offline fallback)          |
     | • bcrypt Password Hashing     | | • expiring_links              | |                               |
     | • secrets URL-Safe Tokens     | | • audit_logs                  | |                               |
     +-------------------------------+ +-------------------------------+ +-------------------------------+
```

---

## 💻 Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | HTML5, Modern CSS (Glassmorphic Dark UI), JavaScript (ES6+) | User interface, drag-and-drop upload, pipeline visualizer, responsive modals |
| **Backend** | Python 3.9+, Flask | RESTful API, authentication sessions, storage abstraction, error handling |
| **Database** | MongoDB (`pymongo` / `mongomock` fallback) | File metadata, user accounts, sharing permissions, audit trail |
| **Cloud Storage** | AWS S3 (`boto3`) / Local Encrypted Store | Encrypted ciphertext blob persistence |
| **Encryption** | AES-256-GCM (`cryptography` library) | Authenticated Encryption with Associated Data (AEAD) |
| **Integrity** | SHA-256 (`hashlib`) | Cryptographic checksum verification pre/post encryption |
| **Auth Hashing**| bcrypt (`bcrypt` library) | Salted password hashing (12 rounds) |
| **Configuration**| `python-dotenv` | Environment variable management (`.env`) |

---

## 🗄️ Database Collections & Schemas

### 1. `users`
```json
{
  "_id": "ObjectId('...')",
  "name": "Alice Cryptographer",
  "email": "alice@college.edu",
  "password_hash": "$2b$12$e8x... (bcrypt salted hash)",
  "created_at": "2026-09-25T10:00:00Z"
}
```

### 2. `files`
```json
{
  "_id": "ObjectId('...')",
  "file_id": "fee31450-ba11-4b3c-85c6-c4baeda9ea17",
  "filename": "project_report.pdf",
  "file_size": 1048576,
  "encrypted_size": 1048604,
  "content_type": "application/pdf",
  "owner_id": "6ab5fd...",
  "owner_email": "alice@college.edu",
  "storage_path": "s3://privacy-preserving-file-storage-bucket/fee31450...pdf.enc",
  "storage_type": "s3",
  "s3_key": "alice_id/fee31450...pdf.enc",
  "nonce_hex": "d868a5a5df5850efb5303151",
  "sha256_hash": "61aa32ea4f82ffc7a83055b4b189d6abef9c6ac8034c03c1583fb7f6b71aaae7",
  "encryption_algo": "AES-256-GCM",
  "upload_date": "2026-09-25T10:15:00Z",
  "is_deleted": false
}
```

### 3. `file_shares`
```json
{
  "_id": "ObjectId('...')",
  "file_id": "fee31450-ba11-4b3c-85c6-c4baeda9ea17",
  "filename": "project_report.pdf",
  "shared_by_id": "6ab5fd...",
  "shared_by_email": "alice@college.edu",
  "shared_to_id": "6ab5fe...",
  "shared_to_email": "bob@college.edu",
  "permission": "download",
  "shared_at": "2026-09-25T10:20:00Z",
  "status": "active"
}
```

### 4. `expiring_links`
```json
{
  "_id": "ObjectId('...')",
  "token": "O6SSnsAxuTWSU2Pa_FRLM7RwQ_kRIuT61tX2Z5z7qM8",
  "file_id": "fee31450-ba11-4b3c-85c6-c4baeda9ea17",
  "filename": "project_report.pdf",
  "created_by_id": "6ab5fd...",
  "created_by_email": "alice@college.edu",
  "permission": "download",
  "expires_at": "2026-09-25T11:20:00Z",
  "duration_minutes": 60,
  "max_access_count": 5,
  "access_count": 1,
  "is_revoked": false,
  "created_at": "2026-09-25T10:20:00Z"
}
```

### 5. `audit_logs`
```json
{
  "_id": "ObjectId('...')",
  "timestamp": "2026-09-25T10:22:00Z",
  "action": "DOWNLOAD",
  "status": "SUCCESS",
  "user_id": "6ab5fe...",
  "user_email": "bob@college.edu",
  "file_id": "fee31450-ba11-4b3c-85c6-c4baeda9ea17",
  "filename": "project_report.pdf",
  "ip_address": "127.0.0.1",
  "user_agent": "Mozilla/5.0 ...",
  "details": "File retrieved, decrypted with AES-256-GCM, and SHA-256 verified."
}
```

---

## 🔐 Cryptographic Workflow & Security Specifications

### 1. AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Length**: 256 bits (32 bytes).
- **Nonce (Initialization Vector)**: 96 bits (12 bytes) generated using `os.urandom(12)`. A unique random nonce is generated for **every single encryption operation**.
- **Authentication Tag**: 128 bits (16 bytes) appended automatically by GCM mode. Decryption verifies the integrity of both the ciphertext and the associated metadata. Any tampering immediately raises an `InvalidTag` exception.

### 2. SHA-256 File Checksum Verification
- The SHA-256 digest is calculated on the raw plaintext bytes prior to encryption.
- After AES-256-GCM decryption, the plaintext digest is recalculated and verified using constant-time comparison (`hmac.compare_digest`).

---

## 🔄 Step-by-Step Workflows

### File Upload Workflow
```
[User Selects File]
        │
        ▼
[Read Bytes in Memory]
        │
        ▼
[Calculate SHA-256 Hash] ───► (Recorded in MongoDB Metadata)
        │
        ▼
[Generate 96-bit Nonce] ────► (Saved in Nonce Field)
        │
        ▼
[AES-256-GCM Encryption] ───► (Produces Ciphertext + 128-bit Auth Tag)
        │
        ▼
[Upload Ciphertext to AWS S3 / Local Encrypted Store]
        │
        ▼
[Record Metadata in MongoDB & Append to Audit Trail]
```

### Secure Download Workflow
```
[Authenticated User Requests File]
        │
        ▼
[Verify Permission: Owner OR Active Share OR Valid Expiring Link]
        │
        ├── (Unauthorized) ──► Log Security Alert & Return 403 Forbidden
        │
        ▼ (Authorized)
[Fetch Ciphertext from S3 / Local Storage]
        │
        ▼
[Execute AES-256-GCM Decryption using 96-bit Nonce & Master Key]
        │
        ├── (Invalid Tag / Tampered) ──► Decryption Fails & Return 500
        │
        ▼ (Tag Valid)
[Recalculate SHA-256 Hash on Decrypted Bytes]
        │
        ├── (Hash Mismatch) ──► Fail Integrity Check
        │
        ▼ (Integrity Verified)
[Stream Decrypted Original File to User & Log Audit Event]
```

---

## 🛡️ Security Features Summary

1. **Zero Cloud Plaintext Exposure**: Plaintext data is strictly processed in ephemeral memory and never committed to cloud buckets.
2. **Tamper Detection**: AES-GCM AEAD guarantees ciphertext cannot be altered in storage without detection.
3. **Password Security**: Passwords are salted and hashed using `bcrypt` (12 rounds).
4. **Environment Isolation**: All credentials, bucket names, and encryption keys are loaded strictly through `.env`.
5. **Expiring Link Expiration & Access Limits**: Links reject expired timestamps and track maximum downloads.
6. **Granular Access Revocation**: Owners can revoke direct user permissions or delete links instantly.
7. **Immutable Audit Logging**: Every critical action (Login, Upload, Download, Share, Revoke, Delete) is logged with timestamp, user identity, IP address, and status.

---

## 🚀 How to Run the Project

### Prerequisites
- Python 3.9 or higher
- (Optional) Local MongoDB server running on port `27017` or MongoDB Atlas URI *(The app includes automatic in-memory fallback if MongoDB is not running)*.
- (Optional) AWS S3 credentials for cloud mode *(Default configuration runs in secure local encrypted storage mode)*.

### 1. Clone or Navigate to the Project Directory
```bash
cd c:\Users\sweth\OneDrive\Desktop\CNS
```

### 2. Install Required Python Dependencies
```bash
pip install flask pymongo boto3 bcrypt mongomock cryptography python-dotenv
```

### 3. Configure Environment Variables (`.env`)
The project contains a pre-configured `.env` file:
```env
# Flask
SECRET_KEY=super-secret-flask-session-key-change-in-production-128bit!
FLASK_ENV=development
PORT=5000

# MongoDB (Local or Atlas)
MONGO_URI=mongodb://localhost:27017/privacy_storage_db
MONGO_DB_NAME=privacy_storage_db

# AES-256 Encryption Key (32-byte / 64-hex char key)
MASTER_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# AWS S3 Cloud Storage (Set USE_S3=true to enable S3)
USE_S3=false
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=privacy-preserving-file-storage-bucket
```

### 4. Run Automated Test Suites
Run unit and integration tests:
```bash
python -m unittest discover -s tests
```

### 5. Start the Application Server
```bash
python app.py
```
The server will start on: `http://localhost:5000`

### 6. Access the Application
Open your web browser and navigate to:
- **Main Vault Application**: `http://localhost:5000`
- **Demo Quick-Fill**: Click **⚡ Quick Demo Fill** on the login card to auto-populate test credentials, or click **Create Account** to register a new user.
- **Expiring Links**: Generated links can be opened by any recipient via `http://localhost:5000/share/<token>`.

---

## 🧪 Verification & Demonstration Scripts

To run a live automated 18-step verification of all features against the running server:
```bash
python tests/live_system_check.py
```

---

## 📚 Project Structure

```
CNS/
├── app.py                      # Flask Application Entry Point & Web Server
├── config.py                   # Centralized Configuration & Environment Loader
├── crypto_utils.py             # AES-256-GCM, SHA-256, bcrypt & Token Utilities
├── database.py                 # MongoDB Connector & Collection Index Initializer
├── storage_manager.py          # S3 Cloud & Local Encrypted Storage Abstraction
├── auth.py                     # Session Decorators & Immutable Audit Logger
├── .env                        # Environment Configuration
├── routes/
│   ├── auth_routes.py          # User Registration, Login, Logout, Profile APIs
│   ├── file_routes.py          # In-Memory Encryption, Upload, Decryption, Download, Delete
│   ├── share_routes.py         # User Sharing, Revocations, Expiring Link APIs
│   └── audit_routes.py         # Activity Logs & Dashboard Statistics APIs
├── static/
│   ├── css/
│   │   └── styles.css          # Glassmorphic Dark Design System & Animations
│   └── js/
│       └── app.js              # SPA Dashboard Controller & Encryption Pipeline
├── templates/
│   ├── index.html              # Main Single-Page Application Dashboard
│   └── shared_link.html        # Standalone Public Expiring Share Landing Page
└── tests/
    ├── test_crypto.py          # Unit Tests for AES-256-GCM, SHA-256 & bcrypt
    ├── test_app.py             # End-to-End Workflow & Access Control Tests
    └── live_system_check.py    # 18-Step Live HTTP Verification Suite
```

---

## 🎓 Academic Summary (For B.Tech CSE)

| Criterion | Implementation in PrivacyVault |
| :--- | :--- |
| **Confidentiality** | AES-256 in Galois/Counter Mode (GCM) with 256-bit key. |
| **Authenticity / Integrity** | 128-bit GCM AEAD authentication tag + SHA-256 pre/post cryptographic checksum comparison. |
| **Randomness & Nonce Replay Prevention** | 96-bit cryptographically secure random nonce (`os.urandom(12)`) generated per upload. |
| **Credential Protection** | bcrypt salted key derivation (12 rounds) preventing rainbow table & dictionary attacks. |
| **Access Control** | Ownership verification, shared permission levels, tokenized expiring links with access counters. |
| **Non-Repudiation & Auditing** | MongoDB-backed audit log capturing IP addresses, actors, timestamps, and status codes. |
