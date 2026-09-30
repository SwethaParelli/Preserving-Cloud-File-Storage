"""
Authentication Routes Module
----------------------------
Handles User Registration (bcrypt salted hash), User Login, Session management,
User Profile, and User Listing for secure file sharing.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, session
from database import get_users_collection, is_database_mock
from crypto_utils import hash_password, check_password
from auth import login_required, get_current_user, log_audit_event
from storage_manager import storage

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user with bcrypt password hashing."""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    # Input validation
    if not name or len(name) < 2:
        return jsonify({"success": False, "error": "Full name is required (at least 2 characters)."}), 400
    if not email or "@" not in email or "." not in email:
        return jsonify({"success": False, "error": "A valid email address is required."}), 400
    if not password or len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters long."}), 400
        
    users_col = get_users_collection()
    
    # Check if email is already registered
    existing = users_col.find_one({"email": email})
    if existing:
        log_audit_event(
            action="REGISTER",
            status="FAILURE",
            user_email=email,
            details="Registration failed: Email already exists."
        )
        return jsonify({"success": False, "error": "An account with this email already exists."}), 409
        
    # Hash password using bcrypt
    password_hash = hash_password(password)
    
    # Create user document
    new_user = {
        "name": name,
        "email": email,
        "password_hash": password_hash,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    
    result = users_col.insert_one(new_user)
    user_id = str(result.inserted_id)
    
    # Auto-login the user into session
    session["user_id"] = user_id
    session["user_email"] = email
    session["user_name"] = name
    session.permanent = True
    
    log_audit_event(
        action="REGISTER",
        status="SUCCESS",
        user_id=user_id,
        user_email=email,
        details=f"User {name} registered successfully."
    )
    
    return jsonify({
        "success": True,
        "message": "Account registered successfully!",
        "user": {
            "id": user_id,
            "name": name,
            "email": email
        }
    }), 201

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate user credentials and establish session."""
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required."}), 400
        
    users_col = get_users_collection()
    user = users_col.find_one({"email": email})
    
    if not user or not check_password(password, user.get("password_hash", "")):
        log_audit_event(
            action="LOGIN",
            status="FAILURE",
            user_email=email,
            details="Invalid email or password attempt."
        )
        return jsonify({"success": False, "error": "Invalid email or password."}), 401
        
    user_id = str(user["_id"])
    session["user_id"] = user_id
    session["user_email"] = user["email"]
    session["user_name"] = user["name"]
    session.permanent = True
    
    log_audit_event(
        action="LOGIN",
        status="SUCCESS",
        user_id=user_id,
        user_email=user["email"],
        details="User logged in successfully."
    )
    
    return jsonify({
        "success": True,
        "message": "Login successful!",
        "user": {
            "id": user_id,
            "name": user["name"],
            "email": user["email"]
        }
    }), 200

@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    """Clear user session."""
    user_id = session.get("user_id")
    user_email = session.get("user_email")
    
    if user_id:
        log_audit_event(
            action="LOGOUT",
            status="SUCCESS",
            user_id=user_id,
            user_email=user_email,
            details="User logged out."
        )
    
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully."}), 200

@auth_bp.route("/api/auth/me", methods=["GET"])
def me():
    """Return currently authenticated user and system status."""
    user = get_current_user()
    if not user:
        return jsonify({
            "authenticated": False,
            "storage_mode": storage.get_storage_mode(),
            "database_mode": "Mock In-Memory DB" if is_database_mock() else "MongoDB Live"
        }), 200
        
    return jsonify({
        "authenticated": True,
        "user": user,
        "storage_mode": storage.get_storage_mode(),
        "database_mode": "Mock In-Memory DB" if is_database_mock() else "MongoDB Live"
    }), 200

@auth_bp.route("/api/users", methods=["GET"])
@login_required
def list_users():
    """List other registered users to enable easy file sharing autocomplete."""
    users_col = get_users_collection()
    current_email = session.get("user_email")
    
    all_users = users_col.find(
        {"email": {"$ne": current_email}},
        {"password_hash": 0}
    )
    
    user_list = []
    for u in all_users:
        user_list.append({
            "id": str(u["_id"]),
            "name": u.get("name", "Unknown"),
            "email": u.get("email", "")
        })
        
    return jsonify({
        "success": True,
        "users": user_list
    }), 200
