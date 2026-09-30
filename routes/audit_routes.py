"""
Audit & Activity Logs Blueprint
-------------------------------
Provides real-time activity tracking, security event auditing,
and system statistics for the user dashboard.
"""

from flask import Blueprint, request, jsonify, session
from database import get_audit_logs_collection, get_files_collection, get_shares_collection, get_links_collection
from auth import login_required
from storage_manager import storage

audit_bp = Blueprint("audit_bp", __name__)

@audit_bp.route("/api/audit/logs", methods=["GET"])
@login_required
def get_audit_logs():
    """Retrieve security audit logs for the current user."""
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    action_filter = request.args.get("action", "").strip().upper()
    limit = min(int(request.args.get("limit", 50)), 200)
    
    audit_col = get_audit_logs_collection()
    
    # Query for logs initiated by this user or targeting this user's email
    query = {
        "$or": [
            {"user_id": user_id},
            {"user_email": user_email},
            {"details": {"$regex": user_email, "$options": "i"}}
        ]
    }
    
    if action_filter:
        query["action"] = action_filter
        
    logs_cursor = audit_col.find(query).sort("timestamp", -1).limit(limit)
    
    log_list = []
    for log in logs_cursor:
        log_list.append({
            "id": str(log["_id"]),
            "timestamp": log.get("timestamp"),
            "action": log.get("action"),
            "status": log.get("status"),
            "user_email": log.get("user_email"),
            "filename": log.get("filename"),
            "file_id": log.get("file_id"),
            "ip_address": log.get("ip_address"),
            "details": log.get("details")
        })
        
    return jsonify({
        "success": True,
        "count": len(log_list),
        "logs": log_list
    }), 200

@audit_bp.route("/api/audit/stats", methods=["GET"])
@login_required
def get_user_stats():
    """Compute summary statistics for user dashboard counters."""
    user_id = session["user_id"]
    user_email = session["user_email"]
    
    files_col = get_files_collection()
    shares_col = get_shares_collection()
    links_col = get_links_collection()
    audit_col = get_audit_logs_collection()
    
    # User's files
    user_files = list(files_col.find({"owner_id": user_id, "is_deleted": {"$ne": True}}))
    total_files = len(user_files)
    total_bytes = sum(f.get("file_size", 0) for f in user_files)
    total_encrypted_bytes = sum(f.get("encrypted_size", f.get("file_size", 0)) for f in user_files)
    
    # Shared files count
    shared_with_me = shares_col.count_documents({
        "$or": [{"shared_to_email": user_email}, {"shared_to_id": user_id}],
        "status": "active"
    })
    
    # Active expiring links count
    active_links = links_col.count_documents({
        "created_by_id": user_id,
        "is_revoked": {"$ne": True}
    })
    
    # Total activity events
    total_events = audit_col.count_documents({
        "$or": [{"user_id": user_id}, {"user_email": user_email}]
    })
    
    return jsonify({
        "success": True,
        "stats": {
            "total_files": total_files,
            "total_bytes": total_bytes,
            "total_encrypted_bytes": total_encrypted_bytes,
            "shared_with_me": shared_with_me,
            "active_links": active_links,
            "total_events": total_events,
            "storage_engine": storage.get_storage_mode(),
            "encryption_standard": "AES-256-GCM (256-bit Key, 96-bit Nonce, 128-bit Auth Tag)"
        }
    }), 200
