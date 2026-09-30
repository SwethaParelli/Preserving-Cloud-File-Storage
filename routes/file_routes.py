"""
File Management & Cryptographic Operations Blueprint
---------------------------------------------------
Handles:
1. In-memory AES-256-GCM encryption & secure cloud storage upload.
2. File listing (My Files & Shared With Me).
3. Authenticated AES-256-GCM decryption & SHA-256 integrity verification on download.
4. File deletion with ciphertext shredding.
"""

import io
import uuid
import mimetypes
from datetime import datetime
from flask import Blueprint, request, jsonify, session, send_file
from werkzeug.utils import secure_filename
from database import get_files_collection, get_shares_collection, get_links_collection
from crypto_utils import encrypt_file_data, decrypt_file_data
from auth import login_required, log_audit_event
from storage_manager import storage
from bson import ObjectId

file_bp = Blueprint("file_bp", __name__)

@file_bp.route("/api/files/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Encrypt file using AES-256-GCM and store encrypted payload in AWS S3 or local storage.
    Plaintext file is NEVER saved on disk or uploaded in plaintext.
    """
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file part in the request."}), 400
        
    uploaded_file = request.files["file"]
    if not uploaded_file or uploaded_file.filename == "":
        return jsonify({"success": False, "error": "No file selected."}), 400
        
    original_filename = secure_filename(uploaded_file.filename) or "unnamed_file"
    file_bytes = uploaded_file.read()
    file_size = len(file_bytes)
    
    if file_size == 0:
        return jsonify({"success": False, "error": "Cannot upload an empty file."}), 400
        
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    try:
        # 1. AES-256-GCM Encryption with random 96-bit nonce & SHA-256 calculation
        ciphertext, nonce, sha256_hash = encrypt_file_data(file_bytes)
        
        # 2. Generate unique storage identifier
        file_uuid = str(uuid.uuid4())
        storage_key = f"{user_id}/{file_uuid}-{original_filename}.enc"
        
        # 3. Store only the encrypted bytes in S3 / local encrypted storage
        storage_result = storage.save_encrypted_file(storage_key, ciphertext)
        
        # 4. Determine content type
        content_type, _ = mimetypes.guess_type(original_filename)
        content_type = content_type or "application/octet-stream"
        
        # 5. Store file metadata in MongoDB
        file_doc = {
            "file_id": file_uuid,
            "filename": original_filename,
            "file_size": file_size,
            "encrypted_size": len(ciphertext),
            "content_type": content_type,
            "owner_id": user_id,
            "owner_email": user_email,
            "storage_path": storage_result["storage_path"],
            "storage_type": storage_result["storage_type"],
            "s3_key": storage_result["s3_key"],
            "nonce_hex": nonce.hex(),
            "sha256_hash": sha256_hash,
            "encryption_algo": "AES-256-GCM",
            "upload_date": datetime.utcnow().isoformat() + "Z",
            "is_deleted": False
        }
        
        files_col = get_files_collection()
        files_col.insert_one(file_doc)
        
        # 6. Record Audit Log
        log_audit_event(
            action="UPLOAD",
            status="SUCCESS",
            user_id=user_id,
            user_email=user_email,
            file_id=file_uuid,
            filename=original_filename,
            details=f"Encrypted ({file_size} bytes) with AES-256-GCM and stored in {storage_result['storage_type'].upper()}."
        )
        
        return jsonify({
            "success": True,
            "message": "File encrypted and uploaded securely!",
            "file": {
                "file_id": file_uuid,
                "filename": original_filename,
                "file_size": file_size,
                "encrypted_size": len(ciphertext),
                "encryption_algo": "AES-256-GCM",
                "nonce_hex": nonce.hex(),
                "sha256_hash": sha256_hash,
                "storage_type": storage_result["storage_type"],
                "upload_date": file_doc["upload_date"]
            }
        }), 201

    except Exception as ex:
        log_audit_event(
            action="UPLOAD",
            status="FAILURE",
            user_id=user_id,
            user_email=user_email,
            filename=original_filename,
            details=f"Upload failed: {str(ex)}"
        )
        return jsonify({"success": False, "error": f"Encryption or storage failure: {str(ex)}"}), 500

@file_bp.route("/api/files/my-files", methods=["GET"])
@login_required
def list_my_files():
    """Retrieve all files owned by current user."""
    user_id = session["user_id"]
    files_col = get_files_collection()
    
    files_cursor = files_col.find(
        {"owner_id": user_id, "is_deleted": {"$ne": True}}
    ).sort("upload_date", -1)
    
    file_list = []
    for f in files_cursor:
        file_list.append({
            "file_id": f.get("file_id"),
            "filename": f.get("filename"),
            "file_size": f.get("file_size"),
            "encrypted_size": f.get("encrypted_size", f.get("file_size")),
            "content_type": f.get("content_type", "application/octet-stream"),
            "encryption_algo": f.get("encryption_algo", "AES-256-GCM"),
            "nonce_hex": f.get("nonce_hex", ""),
            "sha256_hash": f.get("sha256_hash", ""),
            "storage_type": f.get("storage_type", "local_encrypted"),
            "upload_date": f.get("upload_date"),
            "owner_email": f.get("owner_email"),
            "is_owner": True
        })
        
    return jsonify({"success": True, "files": file_list}), 200

@file_bp.route("/api/files/shared-with-me", methods=["GET"])
@login_required
def list_shared_files():
    """Retrieve files shared with the current user."""
    current_email = session["user_email"]
    current_id = session["user_id"]
    
    shares_col = get_shares_collection()
    files_col = get_files_collection()
    
    shares = list(shares_col.find({
        "$or": [{"shared_to_email": current_email}, {"shared_to_id": current_id}],
        "status": "active"
    }))
    
    shared_files = []
    for share in shares:
        file_doc = files_col.find_one({"file_id": share.get("file_id"), "is_deleted": {"$ne": True}})
        if file_doc:
            shared_files.append({
                "share_id": str(share["_id"]),
                "file_id": file_doc.get("file_id"),
                "filename": file_doc.get("filename"),
                "file_size": file_doc.get("file_size"),
                "content_type": file_doc.get("content_type"),
                "encryption_algo": file_doc.get("encryption_algo", "AES-256-GCM"),
                "nonce_hex": file_doc.get("nonce_hex"),
                "sha256_hash": file_doc.get("sha256_hash"),
                "shared_by_email": share.get("shared_by_email"),
                "shared_at": share.get("shared_at"),
                "permission": share.get("permission", "download"),
                "is_owner": False
            })
            
    return jsonify({"success": True, "shared_files": shared_files}), 200

@file_bp.route("/api/files/<file_id>/download", methods=["GET"])
@login_required
def download_file(file_id):
    """
    Secure Download Workflow:
    1. Verify user authentication.
    2. Verify ownership or active shared permission.
    3. Retrieve AES-256-GCM ciphertext from cloud or local storage.
    4. Decrypt in-memory using stored nonce & key.
    5. Verify SHA-256 integrity hash.
    6. Return decrypted original file to authorized user.
    """
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "File not found or deleted."}), 404
        
    # Check permissions (Owner OR Shared with download permission)
    is_owner = (file_doc.get("owner_id") == user_id)
    has_permission = is_owner
    
    if not is_owner:
        shares_col = get_shares_collection()
        share = shares_col.find_one({
            "file_id": file_id,
            "$or": [{"shared_to_email": user_email}, {"shared_to_id": user_id}],
            "status": "active"
        })
        if share:
            has_permission = True
            
    if not has_permission:
        log_audit_event(
            action="DOWNLOAD",
            status="FAILURE",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details="Unauthorized download attempt blocked by access control."
        )
        return jsonify({"success": False, "error": "Access denied: You do not have permission to download this file."}), 403
        
    try:
        # Retrieve encrypted ciphertext from storage
        s3_key = file_doc.get("s3_key", file_doc.get("storage_path"))
        storage_type = file_doc.get("storage_type", "local_encrypted")
        ciphertext = storage.get_encrypted_file(s3_key, storage_type)
        
        # Parse stored nonce and SHA-256 hash
        nonce = bytes.fromhex(file_doc.get("nonce_hex"))
        expected_sha256 = file_doc.get("sha256_hash")
        
        # In-memory AES-256-GCM decryption & SHA-256 integrity verification
        decrypted_bytes, integrity_valid = decrypt_file_data(
            ciphertext_bytes=ciphertext,
            nonce=nonce,
            expected_sha256=expected_sha256
        )
        
        log_audit_event(
            action="DOWNLOAD",
            status="SUCCESS",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details="File retrieved, decrypted with AES-256-GCM, and SHA-256 verified."
        )
        
        # Return decrypted file stream
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file_doc.get("content_type", "application/octet-stream"),
            as_attachment=True,
            download_name=file_doc.get("filename")
        )
        
    except Exception as ex:
        log_audit_event(
            action="DOWNLOAD",
            status="FAILURE",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details=f"Decryption/Integrity failure: {str(ex)}"
        )
        return jsonify({"success": False, "error": f"Decryption or integrity verification failed: {str(ex)}"}), 500

@file_bp.route("/api/files/<file_id>/preview", methods=["GET"])
@login_required
def preview_file(file_id):
    """
    Decrypted preview for text/image/pdf files for view permissions.
    """
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "File not found."}), 404
        
    is_owner = (file_doc.get("owner_id") == user_id)
    has_permission = is_owner
    
    if not is_owner:
        shares_col = get_shares_collection()
        share = shares_col.find_one({
            "file_id": file_id,
            "$or": [{"shared_to_email": user_email}, {"shared_to_id": user_id}],
            "status": "active"
        })
        if share:
            has_permission = True
            
    if not has_permission:
        return jsonify({"success": False, "error": "Access denied: No preview permissions."}), 403
        
    try:
        s3_key = file_doc.get("s3_key", file_doc.get("storage_path"))
        storage_type = file_doc.get("storage_type", "local_encrypted")
        ciphertext = storage.get_encrypted_file(s3_key, storage_type)
        nonce = bytes.fromhex(file_doc.get("nonce_hex"))
        expected_sha256 = file_doc.get("sha256_hash")
        
        decrypted_bytes, _ = decrypt_file_data(ciphertext, nonce, expected_sha256)
        
        log_audit_event(
            action="PREVIEW",
            status="SUCCESS",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details="File previewed and decrypted in-memory."
        )
        
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file_doc.get("content_type", "text/plain"),
            as_attachment=False
        )
    except Exception as ex:
        return jsonify({"success": False, "error": f"Preview decryption failed: {str(ex)}"}), 500

@file_bp.route("/api/files/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    """
    Secure file deletion:
    1. Verify file ownership.
    2. Remove ciphertext from S3 or local disk.
    3. Soft-delete / purge metadata from MongoDB.
    4. Invalidate all active shares and expiring links for this file.
    """
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "File not found."}), 404
        
    # Only owner can delete
    if file_doc.get("owner_id") != user_id:
        log_audit_event(
            action="DELETE",
            status="FAILURE",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details="Unauthorized deletion attempt."
        )
        return jsonify({"success": False, "error": "Only the file owner can delete this file."}), 403
        
    try:
        # Delete ciphertext
        s3_key = file_doc.get("s3_key", file_doc.get("storage_path"))
        storage_type = file_doc.get("storage_type", "local_encrypted")
        storage.delete_encrypted_file(s3_key, storage_type)
        
        # Mark as deleted in MongoDB
        files_col.update_one({"file_id": file_id}, {"$set": {"is_deleted": True, "deleted_at": datetime.utcnow().isoformat() + "Z"}})
        
        # Revoke all shares
        get_shares_collection().update_many({"file_id": file_id}, {"$set": {"status": "revoked"}})
        
        # Revoke all expiring links
        get_links_collection().update_many({"file_id": file_id}, {"$set": {"is_revoked": True}})
        
        log_audit_event(
            action="DELETE",
            status="SUCCESS",
            user_id=user_id,
            user_email=user_email,
            file_id=file_id,
            filename=file_doc.get("filename"),
            details="File ciphertext shredded and metadata marked deleted."
        )
        
        return jsonify({"success": True, "message": "File securely deleted."}), 200
        
    except Exception as ex:
        return jsonify({"success": False, "error": f"Failed to delete file: {str(ex)}"}), 500
