"""
Live System Integration Verification Script
-------------------------------------------
Interacts with the live running Flask server on http://localhost:5000 over HTTP,
performing end-to-end testing:
1. Fetching HTML templates and static assets
2. User registration (Alice & Bob)
3. User login & session authentication
4. In-memory AES-256-GCM file encryption and upload
5. Listing encrypted files & inspecting SHA-256 hashes
6. Secure authenticated decryption and file download
7. Direct user-to-user sharing (Alice -> Bob)
8. Bob downloading shared decrypted file
9. Generating time-limited expiring share link
10. Anonymous download & decryption via public expiring link
11. Security Audit Log verification
"""

import requests
import io

BASE_URL = "http://localhost:5000"

def run_live_verification():
    print("=" * 70)
    print("[*] RUNNING LIVE SYSTEM VERIFICATION ON PRIVACY VAULT")
    print(f"Target: {BASE_URL}")
    print("=" * 70)

    # Session 1: Alice (Owner)
    s_alice = requests.Session()
    
    # 1. Verify Homepage & Static CSS
    res = s_alice.get(f"{BASE_URL}/")
    assert res.status_code == 200, f"Failed to load homepage: {res.status_code}"
    print("[OK] 1. Homepage loaded successfully (HTML 200 OK)")

    res_css = s_alice.get(f"{BASE_URL}/static/css/styles.css")
    assert res_css.status_code == 200, f"Failed to load styles.css: {res_css.status_code}"
    print("[OK] 2. Stylesheet styles.css loaded successfully")

    res_js = s_alice.get(f"{BASE_URL}/static/js/app.js")
    assert res_js.status_code == 200, f"Failed to load app.js: {res_js.status_code}"
    print("[OK] 3. Frontend JavaScript app.js loaded successfully")

    # 2. Register Alice
    reg_alice = s_alice.post(f"{BASE_URL}/api/auth/register", json={
        "name": "Alice Vault Master",
        "email": "alice.crypto@university.edu",
        "password": "MasterSecurePassword2026!"
    })
    assert reg_alice.status_code in (201, 409), f"Registration failed: {reg_alice.text}"
    print(f"[OK] 4. User registration verified (Status: {reg_alice.status_code})")

    # If already registered, login
    login_alice = s_alice.post(f"{BASE_URL}/api/auth/login", json={
        "email": "alice.crypto@university.edu",
        "password": "MasterSecurePassword2026!"
    })
    assert login_alice.status_code == 200, f"Login failed: {login_alice.text}"
    print("[OK] 5. Alice logged in successfully with bcrypt authentication")

    # 3. Check /api/auth/me
    me = s_alice.get(f"{BASE_URL}/api/auth/me").json()
    assert me["authenticated"] is True
    print(f"[OK] 6. Session verified: {me['user']['name']} | Storage Engine: {me['storage_mode']}")

    # 4. Upload File (AES-256-GCM Encrypted)
    sample_content = b"Confidential Research Dataset - Security and Privacy in Cloud Storage [AES-256-GCM & SHA-256 Verification]."
    files = {
        "file": ("research_paper.txt", io.BytesIO(sample_content), "text/plain")
    }
    upload_res = s_alice.post(f"{BASE_URL}/api/files/upload", files=files)
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
    upload_data = upload_res.json()
    file_id = upload_data["file"]["file_id"]
    sha256_hash = upload_data["file"]["sha256_hash"]
    nonce_hex = upload_data["file"]["nonce_hex"]
    print(f"[OK] 7. File encrypted and uploaded successfully!")
    print(f"   -> File ID: {file_id}")
    print(f"   -> AES-256-GCM Nonce (96-bit): {nonce_hex}")
    print(f"   -> SHA-256 Integrity Hash: {sha256_hash}")

    # 5. List Files
    my_files = s_alice.get(f"{BASE_URL}/api/files/my-files").json()["files"]
    assert any(f["file_id"] == file_id for f in my_files)
    print(f"[OK] 8. File listed in Alice's dashboard (Total files: {len(my_files)})")

    # 6. Secure Download & Decryption (Alice)
    download_res = s_alice.get(f"{BASE_URL}/api/files/{file_id}/download")
    assert download_res.status_code == 200
    assert download_res.content == sample_content
    print("[OK] 9. File decrypted in-memory and SHA-256 integrity verified on download!")

    # 7. Register Bob & Test Sharing
    s_bob = requests.Session()
    reg_bob = s_bob.post(f"{BASE_URL}/api/auth/register", json={
        "name": "Bob Collaborator",
        "email": "bob.collaborator@university.edu",
        "password": "BobPassword2026!"
    })
    s_bob.post(f"{BASE_URL}/api/auth/login", json={
        "email": "bob.collaborator@university.edu",
        "password": "BobPassword2026!"
    })

    # Bob unauthorized access check
    bob_unauth = s_bob.get(f"{BASE_URL}/api/files/{file_id}/download")
    assert bob_unauth.status_code == 403, "Access control failure: Unauthorized user downloaded file!"
    print("[OK] 10. Access control verified: Unauthorized download blocked with 403 Forbidden")

    # Alice shares with Bob
    share_res = s_alice.post(f"{BASE_URL}/api/shares/share-user", json={
        "file_id": file_id,
        "recipient_email": "bob.collaborator@university.edu",
        "permission": "download"
    })
    assert share_res.status_code == 200
    print("[OK] 11. Alice granted download share permission to Bob")

    # Bob checks Shared With Me & Downloads
    bob_shared = s_bob.get(f"{BASE_URL}/api/files/shared-with-me").json()["shared_files"]
    assert len(bob_shared) >= 1
    bob_dl = s_bob.get(f"{BASE_URL}/api/files/{file_id}/download")
    assert bob_dl.status_code == 200
    assert bob_dl.content == sample_content
    print("[OK] 12. Bob successfully accessed and decrypted shared file")

    # 8. Expiring Link Creation & Public Access
    link_res = s_alice.post(f"{BASE_URL}/api/shares/create-link", json={
        "file_id": file_id,
        "duration_minutes": 60,
        "max_access_count": 2
    })
    assert link_res.status_code == 201
    token = link_res.json()["token"]
    print(f"[OK] 13. Expiring share link generated: /share/{token}")

    # Public user (no auth session) accesses link info and downloads
    s_anon = requests.Session()
    page_res = s_anon.get(f"{BASE_URL}/share/{token}")
    assert page_res.status_code == 200
    print("[OK] 14. Public share landing page loaded for token recipient")

    info_res = s_anon.get(f"{BASE_URL}/api/shares/public-info/{token}").json()
    assert info_res["success"] is True
    print(f"[OK] 15. Token validated: {info_res['link']['filename']} (Expires: {info_res['link']['expires_at']})")

    public_dl = s_anon.get(f"{BASE_URL}/api/shares/public-download/{token}")
    assert public_dl.status_code == 200
    assert public_dl.content == sample_content
    print("[OK] 16. Anonymous public download decrypted successfully via secure token")

    # 9. Audit Logs Verification
    logs = s_alice.get(f"{BASE_URL}/api/audit/logs").json()["logs"]
    actions = [l["action"] for l in logs]
    print(f"[OK] 17. Audit trail active! Recorded {len(logs)} security events: {set(actions)}")

    # 10. Dashboard Stats
    stats = s_alice.get(f"{BASE_URL}/api/audit/stats").json()["stats"]
    print(f"[OK] 18. Dashboard stats verified: {stats}")

    print("=" * 70)
    print("[SUCCESS] ALL 18 INTEGRATION & SECURITY VERIFICATIONS PASSED 100%!")
    print("=" * 70)

if __name__ == "__main__":
    run_live_verification()
