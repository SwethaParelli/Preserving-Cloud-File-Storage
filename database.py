"""
Database Module for MongoDB Integration
---------------------------------------
Manages database connectivity, collection references, and indexes.
Includes automatic fallback to mongomock if local MongoDB is not running.
"""

import sys
import logging
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config

logger = logging.getLogger(__name__)

# Global database instances
_client = None
_db = None
_is_mock = False

def get_database():
    """
    Get or initialize the MongoDB database connection.
    Attempts connection to Config.MONGO_URI. If unreachable, falls back to mongomock.
    """
    global _client, _db, _is_mock
    
    if _db is not None:
        return _db
    
    try:
        # Attempt real MongoDB connection with short server selection timeout
        _client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=2000)
        # Force a call to verify connection
        _client.admin.command('ping')
        _db = _client[Config.MONGO_DB_NAME]
        _is_mock = False
        logger.info(f"Connected successfully to MongoDB at {Config.MONGO_URI}")
    except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
        logger.warning(f"MongoDB connection to {Config.MONGO_URI} failed: {e}")
        logger.info("Initializing in-memory mongomock database for seamless execution...")
        import mongomock
        _client = mongomock.MongoClient()
        _db = _client[Config.MONGO_DB_NAME]
        _is_mock = True
    
    # Initialize indexes
    _init_indexes(_db)
    return _db

def is_database_mock() -> bool:
    """Return True if using mock MongoDB, False if real MongoDB."""
    global _is_mock
    if _db is None:
        get_database()
    return _is_mock

def _init_indexes(db):
    """Ensure necessary indexes are created on collections."""
    try:
        # Users collection
        db.users.create_index([("email", ASCENDING)], unique=True)
        
        # Files collection
        db.files.create_index([("file_id", ASCENDING)], unique=True)
        db.files.create_index([("owner_id", ASCENDING)])
        db.files.create_index([("upload_date", DESCENDING)])
        
        # File shares collection
        db.file_shares.create_index([("file_id", ASCENDING), ("shared_to_email", ASCENDING)])
        db.file_shares.create_index([("shared_to_id", ASCENDING)])
        db.file_shares.create_index([("shared_by_id", ASCENDING)])
        
        # Expiring links collection
        db.expiring_links.create_index([("token", ASCENDING)], unique=True)
        db.expiring_links.create_index([("file_id", ASCENDING)])
        
        # Audit logs collection
        db.audit_logs.create_index([("timestamp", DESCENDING)])
        db.audit_logs.create_index([("user_id", ASCENDING)])
        db.audit_logs.create_index([("file_id", ASCENDING)])
    except Exception as ex:
        logger.debug(f"Index creation note: {ex}")

# Helper collection accessors
def get_users_collection():
    return get_database().users

def get_files_collection():
    return get_database().files

def get_shares_collection():
    return get_database().file_shares

def get_links_collection():
    return get_database().expiring_links

def get_audit_logs_collection():
    return get_database().audit_logs
