"""
Authentication & Audit Helpers Module
------------------------------------
Handles session-based authentication decorators, password validation,
and centralized audit event logging.
"""

from functools import wraps
from datetime import datetime
from flask import session, jsonify, request
from database import get_users_collection, get_audit_logs_collection
from bson import ObjectId

def login_required(f):
    """Decorator to enforce user authentication on protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "success": False,
                "error": "Authentication required. Please log in to proceed.",
                "code": "AUTH_REQUIRED"
            }), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Retrieve current logged-in user dict from DB."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    users = get_users_collection()
    try:
        user = users.find_one({"_id": ObjectId(user_id)})
        if user:
            user["_id"] = str(user["_id"])
            user.pop("password_hash", None)
            return user
    except Exception:
        pass
    return None

def log_audit_event(action: str, status: str = "SUCCESS", user_id: str = None, user_email: str = None, file_id: str = None, filename: str = None, details: str = None):
    """
    Record an immutable audit log entry in MongoDB.
    
    :param action: Action name (e.g. LOGIN, LOGOUT, REGISTER, UPLOAD, DOWNLOAD, DELETE, SHARE, REVOKE_SHARE, CREATE_LINK, ACCESS_LINK)
    :param status: SUCCESS or FAILURE
    :param user_id: ID of actor
    :param user_email: Email of actor
    :param file_id: Target file ID if applicable
    :param filename: Target filename if applicable
    :param details: Additional contextual info
    """
    try:
        # Determine actor info from session if not explicitly provided
        if not user_id and "user_id" in session:
            user_id = session.get("user_id")
        if not user_email and "user_email" in session:
            user_email = session.get("user_email")
            
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        if "," in ip_address:
            ip_address = ip_address.split(",")[0].strip()
            
        user_agent = request.headers.get("User-Agent", "Unknown")
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "status": status,
            "user_id": str(user_id) if user_id else "anonymous",
            "user_email": user_email or "anonymous",
            "file_id": file_id or "-",
            "filename": filename or "-",
            "ip_address": ip_address,
            "user_agent": user_agent[:250],  # truncated for clean storage
            "details": details or ""
        }
        
        audit_col = get_audit_logs_collection()
        audit_col.insert_one(audit_entry)
    except Exception as ex:
        # Never crash the main request if logging encounters an issue
        print(f"Failed to record audit log: {ex}")
