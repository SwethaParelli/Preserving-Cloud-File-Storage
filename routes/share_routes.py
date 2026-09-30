"""
File Sharing & Expiring Links Blueprint
---------------------------------------
Manages:
1. Direct user-to-user sharing with fine-grained permissions (view/download) & revocation.
2. Expiring share links with cryptographically secure tokens, expiration countdowns,
   access count limits, and public decryption workflows.
"""

import io
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, session, send_file
from database import get_files_collection, get_shares_collection, get_links_collection, get_users_collection
from crypto_utils import generate_share_token, decrypt_file_data
from auth import login_required, log_audit_event
from storage_manager import storage
from bson import ObjectId

share_bp = Blueprint("share_bp", __name__)

@share_bp.route("/api/shares/share-user", methods=["POST"])
@login_required
def share_with_user():
    """Share a file with another registered user by email."""
    data = request.get_json() or {}
    file_id = data.get("file_id")
    recipient_email = data.get("recipient_email", "").strip().lower()
    permission = data.get("permission", "download").lower()
    
    if permission not in ("view", "download"):
        permission = "download"
        
    if not file_id or not recipient_email:
        return jsonify({"success": False, "error": "File ID and recipient email are required."}), 400
        
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    if recipient_email == user_email:
        return jsonify({"success": False, "error": "You cannot share a file with yourself."}), 400
        
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "File not found."}), 404
        
    if file_doc.get("owner_id") != user_id:
        return jsonify({"success": False, "error": "Only the file owner can grant sharing access."}), 403
        
    users_col = get_users_collection()
    recipient = users_col.find_one({"email": recipient_email})
    recipient_id = str(recipient["_id"]) if recipient else None
    
    shares_col = get_shares_collection()
    
    # Check if existing share exists for this recipient
    existing_share = shares_col.find_one({"file_id": file_id, "shared_to_email": recipient_email})
    
    if existing_share:
        shares_col.update_one(
            {"_id": existing_share["_id"]},
            {"$set": {
                "permission": permission,
                "status": "active",
                "shared_to_id": recipient_id,
                "updated_at": datetime.utcnow().isoformat() + "Z"
            }}
        )
    else:
        new_share = {
            "file_id": file_id,
            "filename": file_doc.get("filename"),
            "shared_by_id": user_id,
            "shared_by_email": user_email,
            "shared_to_id": recipient_id,
            "shared_to_email": recipient_email,
            "permission": permission,
            "shared_at": datetime.utcnow().isoformat() + "Z",
            "status": "active"
        }
        shares_col.insert_one(new_share)
        
    log_audit_event(
        action="SHARE",
        status="SUCCESS",
        user_id=user_id,
        user_email=user_email,
        file_id=file_id,
        filename=file_doc.get("filename"),
        details=f"Shared with {recipient_email} (Permission: {permission.upper()})."
    )
    
    return jsonify({
        "success": True,
        "message": f"File successfully shared with {recipient_email}!"
    }), 200

@share_bp.route("/api/shares/revoke-user", methods=["POST"])
@login_required
def revoke_user_share():
    """Revoke a user's sharing access."""
    data = request.get_json() or {}
    share_id = data.get("share_id")
    file_id = data.get("file_id")
    
    if not share_id and not file_id:
        return jsonify({"success": False, "error": "Share ID or File ID is required."}), 400
        
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    shares_col = get_shares_collection()
    files_col = get_files_collection()
    
    query = {}
    if share_id:
        try:
            query["_id"] = ObjectId(share_id)
        except Exception:
            return jsonify({"success": False, "error": "Invalid share ID format."}), 400
    else:
        query["file_id"] = file_id
        
    share_doc = shares_col.find_one(query)
    if not share_doc:
        return jsonify({"success": False, "error": "Share record not found."}), 404
        
    # Check ownership
    file_doc = files_col.find_one({"file_id": share_doc["file_id"]})
    if not file_doc or file_doc.get("owner_id") != user_id:
        return jsonify({"success": False, "error": "Only the file owner can revoke access."}), 403
        
    shares_col.update_one({"_id": share_doc["_id"]}, {"$set": {"status": "revoked"}})
    
    log_audit_event(
        action="REVOKE_SHARE",
        status="SUCCESS",
        user_id=user_id,
        user_email=user_email,
        file_id=share_doc["file_id"],
        filename=share_doc.get("filename"),
        details=f"Revoked access from {share_doc.get('shared_to_email')}."
    )
    
    return jsonify({"success": True, "message": "Access revoked successfully."}), 200

@share_bp.route("/api/shares/file/<file_id>/manage", methods=["GET"])
@login_required
def get_file_shares_and_links(file_id):
    """Retrieve all direct user shares and active expiring links for a specific file."""
    user_id = session["user_id"]
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc or file_doc.get("owner_id") != user_id:
        return jsonify({"success": False, "error": "File not found or access denied."}), 403
        
    shares_col = get_shares_collection()
    links_col = get_links_collection()
    
    user_shares = list(shares_col.find({"file_id": file_id, "status": "active"}))
    for s in user_shares:
        s["_id"] = str(s["_id"])
        
    expiring_links = list(links_col.find({"file_id": file_id, "is_revoked": {"$ne": True}}).sort("created_at", -1))
    now = datetime.utcnow()
    
    formatted_links = []
    for link in expiring_links:
        link["_id"] = str(link["_id"])
        expires_at_dt = datetime.fromisoformat(link["expires_at"].replace("Z", ""))
        is_expired = now > expires_at_dt
        link["is_expired"] = is_expired
        formatted_links.append(link)
        
    return jsonify({
        "success": True,
        "shares": user_shares,
        "links": formatted_links
    }), 200

@share_bp.route("/api/shares/create-link", methods=["POST"])
@login_required
def create_expiring_link():
    """
    Generate an expiring public sharing link protected by a secure random token.
    Duration options: minutes (e.g. 30, 60, 1440, 10080).
    Max downloads limit: optional integer.
    """
    data = request.get_json() or {}
    file_id = data.get("file_id")
    duration_minutes = int(data.get("duration_minutes", 60))
    max_access_count = int(data.get("max_access_count", 0)) # 0 means unlimited
    permission = data.get("permission", "download")
    
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": file_id, "is_deleted": {"$ne": True}})
    
    if not file_doc or file_doc.get("owner_id") != user_id:
        return jsonify({"success": False, "error": "File not found or permission denied."}), 403
        
    token = generate_share_token()
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=duration_minutes)
    
    link_doc = {
        "token": token,
        "file_id": file_id,
        "filename": file_doc.get("filename"),
        "created_by_id": user_id,
        "created_by_email": user_email,
        "permission": permission,
        "created_at": now.isoformat() + "Z",
        "expires_at": expires_at.isoformat() + "Z",
        "duration_minutes": duration_minutes,
        "max_access_count": max_access_count,
        "access_count": 0,
        "is_revoked": False
    }
    
    links_col = get_links_collection()
    links_col.insert_one(link_doc)
    
    log_audit_event(
        action="CREATE_LINK",
        status="SUCCESS",
        user_id=user_id,
        user_email=user_email,
        file_id=file_id,
        filename=file_doc.get("filename"),
        details=f"Created expiring share link ({duration_minutes}m expiry, limit: {max_access_count or 'Unlimited'})."
    )
    
    return jsonify({
        "success": True,
        "message": "Expiring share link generated!",
        "token": token,
        "expires_at": link_doc["expires_at"],
        "share_url": f"/share/{token}"
    }), 201

@share_bp.route("/api/shares/revoke-link", methods=["POST"])
@login_required
def revoke_expiring_link():
    """Revoke an expiring share link."""
    data = request.get_json() or {}
    token = data.get("token")
    
    if not token:
        return jsonify({"success": False, "error": "Token is required."}), 400
        
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    links_col = get_links_collection()
    link_doc = links_col.find_one({"token": token})
    
    if not link_doc:
        return jsonify({"success": False, "error": "Share link not found."}), 404
        
    if link_doc.get("created_by_id") != user_id:
        return jsonify({"success": False, "error": "Permission denied."}), 403
        
    links_col.update_one({"token": token}, {"$set": {"is_revoked": True}})
    
    log_audit_event(
        action="REVOKE_LINK",
        status="SUCCESS",
        user_id=user_id,
        user_email=user_email,
        file_id=link_doc.get("file_id"),
        filename=link_doc.get("filename"),
        details=f"Revoked expiring share link (Token: {token[:8]}...)."
    )
    
    return jsonify({"success": True, "message": "Share link revoked successfully."}), 200

# Public Access Endpoints (No login required for recipient using secure token)

@share_bp.route("/api/shares/public-info/<token>", methods=["GET"])
def get_public_link_info(token):
    """Retrieve metadata of a file via secure expiring token with validation."""
    links_col = get_links_collection()
    link_doc = links_col.find_one({"token": token})
    
    if not link_doc:
        return jsonify({"success": False, "error": "Invalid or expired share link."}), 404
        
    if link_doc.get("is_revoked"):
        return jsonify({"success": False, "error": "This share link has been revoked by the owner."}), 410
        
    # Check expiration time
    now = datetime.utcnow()
    expires_at_dt = datetime.fromisoformat(link_doc["expires_at"].replace("Z", ""))
    if now > expires_at_dt:
        return jsonify({"success": False, "error": "This share link has expired."}), 410
        
    # Check max access limit
    max_access = link_doc.get("max_access_count", 0)
    current_access = link_doc.get("access_count", 0)
    if max_access > 0 and current_access >= max_access:
        return jsonify({"success": False, "error": "This share link has reached its maximum download limit."}), 410
        
    # Fetch file info
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": link_doc["file_id"], "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "The shared file was deleted."}), 404
        
    return jsonify({
        "success": True,
        "link": {
            "token": token,
            "filename": file_doc.get("filename"),
            "file_size": file_doc.get("file_size"),
            "content_type": file_doc.get("content_type"),
            "encryption_algo": file_doc.get("encryption_algo", "AES-256-GCM"),
            "sha256_hash": file_doc.get("sha256_hash"),
            "owner_email": file_doc.get("owner_email"),
            "permission": link_doc.get("permission", "download"),
            "expires_at": link_doc.get("expires_at"),
            "access_count": current_access,
            "max_access_count": max_access
        }
    }), 200

@share_bp.route("/api/shares/public-download/<token>", methods=["GET"])
def public_download_via_link(token):
    """
    Public decryption & download via expiring link:
    1. Validate token, expiry, and max download counts.
    2. Retrieve ciphertext from cloud/local storage.
    3. In-memory AES-256-GCM decryption & SHA-256 integrity validation.
    4. Increment access count.
    5. Log public access audit entry.
    6. Deliver decrypted file stream.
    """
    links_col = get_links_collection()
    link_doc = links_col.find_one({"token": token})
    
    if not link_doc:
        return jsonify({"success": False, "error": "Invalid share link."}), 404
        
    if link_doc.get("is_revoked"):
        return jsonify({"success": False, "error": "Share link has been revoked."}), 410
        
    now = datetime.utcnow()
    expires_at_dt = datetime.fromisoformat(link_doc["expires_at"].replace("Z", ""))
    if now > expires_at_dt:
        return jsonify({"success": False, "error": "Share link has expired."}), 410
        
    max_access = link_doc.get("max_access_count", 0)
    current_access = link_doc.get("access_count", 0)
    if max_access > 0 and current_access >= max_access:
        return jsonify({"success": False, "error": "Download limit exceeded for this link."}), 410
        
    files_col = get_files_collection()
    file_doc = files_col.find_one({"file_id": link_doc["file_id"], "is_deleted": {"$ne": True}})
    
    if not file_doc:
        return jsonify({"success": False, "error": "File not found."}), 404
        
    try:
        s3_key = file_doc.get("s3_key", file_doc.get("storage_path"))
        storage_type = file_doc.get("storage_type", "local_encrypted")
        ciphertext = storage.get_encrypted_file(s3_key, storage_type)
        
        nonce = bytes.fromhex(file_doc.get("nonce_hex"))
        expected_sha256 = file_doc.get("sha256_hash")
        
        # AES-256-GCM Decryption & SHA-256 verification
        decrypted_bytes, _ = decrypt_file_data(ciphertext, nonce, expected_sha256)
        
        # Increment access count
        links_col.update_one({"token": token}, {"$inc": {"access_count": 1}})
        
        log_audit_event(
            action="ACCESS_LINK",
            status="SUCCESS",
            user_id="anonymous_link_recipient",
            user_email="Public Token Access",
            file_id=link_doc["file_id"],
            filename=file_doc.get("filename"),
            details=f"Public access via token (Remaining: {max_access - current_access - 1 if max_access > 0 else 'Unlimited'})."
        )
        
        return send_file(
            io.BytesIO(decrypted_bytes),
            mimetype=file_doc.get("content_type", "application/octet-stream"),
            as_attachment=True,
            download_name=file_doc.get("filename")
        )
        
    except Exception as ex:
        log_audit_event(
            action="ACCESS_LINK",
            status="FAILURE",
            user_id="anonymous_link_recipient",
            user_email="Public Token Access",
            file_id=link_doc["file_id"],
            filename=file_doc.get("filename"),
            details=f"Decryption failed during public link download: {str(ex)}"
        )
        return jsonify({"success": False, "error": f"Decryption failed: {str(ex)}"}), 500
