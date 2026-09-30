import unittest
import json
import io
from app import create_app
from database import get_database, get_users_collection, get_files_collection, get_shares_collection, get_links_collection, get_audit_logs_collection

class TestFullApplicationWorkflow(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        
        # Clear collections in mock/test db
        db = get_database()
        db.users.delete_many({})
        db.files.delete_many({})
        db.file_shares.delete_many({})
        db.expiring_links.delete_many({})
        db.audit_logs.delete_many({})

    def register_and_login(self, name="Alice User", email="alice@example.com", password="Password123!"):
        # Register
        res = self.client.post("/api/auth/register", json={
            "name": name,
            "email": email,
            "password": password
        })
        return res

    def test_registration_and_login(self):
        # 1. Register User
        res = self.register_and_login()
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], "alice@example.com")
        
        # 2. Check /api/auth/me
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertTrue(me_res.get_json()["authenticated"])
        
        # 3. Logout
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)
        
        # 4. Login with correct password
        login_res = self.client.post("/api/auth/login", json={
            "email": "alice@example.com",
            "password": "Password123!"
        })
        self.assertEqual(login_res.status_code, 200)
        
        # 5. Login with incorrect password
        bad_login = self.client.post("/api/auth/login", json={
            "email": "alice@example.com",
            "password": "WrongPassword!"
        })
        self.assertEqual(bad_login.status_code, 401)

    def test_file_upload_and_download(self):
        self.register_and_login()
        
        # Prepare sample file
        content = b"This is a confidential student assignment encrypted with AES-256-GCM."
        data = {
            "file": (io.BytesIO(content), "sample_document.txt")
        }
        
        # Upload
        upload_res = self.client.post("/api/files/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(upload_res.status_code, 201)
        upload_data = upload_res.get_json()
        self.assertTrue(upload_data["success"])
        file_id = upload_data["file"]["file_id"]
        
        # List My Files
        list_res = self.client.get("/api/files/my-files")
        self.assertEqual(list_res.status_code, 200)
        files = list_res.get_json()["files"]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["filename"], "sample_document.txt")
        self.assertEqual(files[0]["encryption_algo"], "AES-256-GCM")
        
        # Download and verify decryption
        dl_res = self.client.get(f"/api/files/{file_id}/download")
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, content)

    def test_file_sharing_workflow(self):
        # Register Alice (Owner)
        self.register_and_login("Alice", "alice@example.com", "Password123!")
        
        # Upload file as Alice
        content = b"Shared secret research project notes."
        upload_res = self.client.post("/api/files/upload", data={
            "file": (io.BytesIO(content), "notes.txt")
        }, content_type="multipart/form-data")
        file_id = upload_res.get_json()["file"]["file_id"]
        
        # Register Bob
        bob_client = self.app.test_client()
        bob_client.post("/api/auth/register", json={
            "name": "Bob",
            "email": "bob@example.com",
            "password": "Password123!"
        })
        
        # Bob tries to download before being shared -> 403 Access Denied
        bob_dl_unauthorized = bob_client.get(f"/api/files/{file_id}/download")
        self.assertEqual(bob_dl_unauthorized.status_code, 403)
        
        # Alice shares file with Bob
        share_res = self.client.post("/api/shares/share-user", json={
            "file_id": file_id,
            "recipient_email": "bob@example.com",
            "permission": "download"
        })
        self.assertEqual(share_res.status_code, 200)
        
        # Bob checks Shared With Me
        bob_shared = bob_client.get("/api/files/shared-with-me")
        self.assertEqual(bob_shared.status_code, 200)
        shared_list = bob_shared.get_json()["shared_files"]
        self.assertEqual(len(shared_list), 1)
        self.assertEqual(shared_list[0]["filename"], "notes.txt")
        
        # Bob downloads successfully
        bob_dl_authorized = bob_client.get(f"/api/files/{file_id}/download")
        self.assertEqual(bob_dl_authorized.status_code, 200)
        self.assertEqual(bob_dl_authorized.data, content)
        
        # Alice revokes Bob's access
        revoke_res = self.client.post("/api/shares/revoke-user", json={
            "file_id": file_id
        })
        self.assertEqual(revoke_res.status_code, 200)
        
        # Bob downloads again -> 403 Access Denied
        bob_dl_after_revoke = bob_client.get(f"/api/files/{file_id}/download")
        self.assertEqual(bob_dl_after_revoke.status_code, 403)

    def test_expiring_share_link(self):
        self.register_and_login()
        content = b"Publicly shared document with time-limited link."
        upload_res = self.client.post("/api/files/upload", data={
            "file": (io.BytesIO(content), "public_doc.txt")
        }, content_type="multipart/form-data")
        file_id = upload_res.get_json()["file"]["file_id"]
        
        # Create expiring link (60 mins, max 2 downloads)
        link_res = self.client.post("/api/shares/create-link", json={
            "file_id": file_id,
            "duration_minutes": 60,
            "max_access_count": 2
        })
        self.assertEqual(link_res.status_code, 201)
        token = link_res.get_json()["token"]
        
        # Anonymous client accesses info
        anon_client = self.app.test_client()
        info_res = anon_client.get(f"/api/shares/public-info/{token}")
        self.assertEqual(info_res.status_code, 200)
        self.assertEqual(info_res.get_json()["link"]["filename"], "public_doc.txt")
        
        # Anonymous client downloads (1st download)
        dl1 = anon_client.get(f"/api/shares/public-download/{token}")
        self.assertEqual(dl1.status_code, 200)
        self.assertEqual(dl1.data, content)
        
        # 2nd download
        dl2 = anon_client.get(f"/api/shares/public-download/{token}")
        self.assertEqual(dl2.status_code, 200)
        
        # 3rd download (exceeds max_access_count of 2) -> 410 Gone / Expired
        dl3 = anon_client.get(f"/api/shares/public-download/{token}")
        self.assertEqual(dl3.status_code, 410)

    def test_audit_logs(self):
        self.register_and_login()
        # Upload a file
        self.client.post("/api/files/upload", data={
            "file": (io.BytesIO(b"Audit test content"), "audit_test.txt")
        }, content_type="multipart/form-data")
        
        # Fetch audit logs
        logs_res = self.client.get("/api/audit/logs")
        self.assertEqual(logs_res.status_code, 200)
        logs = logs_res.get_json()["logs"]
        
        actions = [l["action"] for l in logs]
        self.assertIn("REGISTER", actions)
        self.assertIn("UPLOAD", actions)

if __name__ == "__main__":
    unittest.main()
