from pymongo import MongoClient
import os
from dotenv import load_dotenv
from datetime import datetime
import pandas as pd
import pickle
import base64

load_dotenv()

def get_db():
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB_NAME", "log_analysis")
    client = MongoClient(mongo_uri)
    return client[db_name]

# Khởi tạo các collection dùng chung
db = get_db()
baseline_col = db["baselines"]
user_stats_col = db["user_stats"]
device_stats_col = db["device_stats"]
group_stats_col = db["group_stats"]
global_stats_col = db["global_stats"]

# Member/Membership collections
group_members_col = db["group_members"]      # Lưu: {group_name: {users: [...], source_ips: [...], hosts: [...]}}
user_to_group_col = db["user_to_group"]      # Lưu: {username: group_name}
device_to_group_col = db["device_to_group"]  # Lưu: {device_id: group_name}

# Model collections (Isolation Forest)
user_models_col = db["user_models"]
device_models_col = db["device_models"]
group_models_col = db["group_models"]


# ===================== BASELINE OPERATIONS =====================

def save_user_stats(user_stats: pd.DataFrame, log_type: str = "generic"):
    """
    Lưu user stats vào MongoDB (append/merge theo username).
    """
    if user_stats is None or user_stats.empty:
        return
    
    records = user_stats.to_dict(orient="records")
    for record in records:
        record["log_type"] = log_type
        record["updated_at"] = datetime.utcnow()
        
        username = record.get("username")
        if username:
            # Merge: update hoặc insert nếu chưa có
            user_stats_col.update_one(
                {"username": username, "log_type": log_type},
                {"$set": record},
                upsert=True
            )


def save_device_stats(device_stats: pd.DataFrame, log_type: str = "generic"):
    """
    Lưu device stats vào MongoDB (append/merge theo host/source_ip).
    """
    if device_stats is None or device_stats.empty:
        return
    
    # Xác định device key (host hoặc source_ip)
    device_key = "host" if "host" in device_stats.columns else (
        "source_ip" if "source_ip" in device_stats.columns else None
    )
    
    if not device_key:
        return
    
    records = device_stats.to_dict(orient="records")
    for record in records:
        record["log_type"] = log_type
        record["updated_at"] = datetime.utcnow()
        
        device_id = record.get(device_key)
        if device_id:
            device_stats_col.update_one(
                {device_key: device_id, "log_type": log_type},
                {"$set": record},
                upsert=True
            )


def save_group_stats(group_stats: pd.DataFrame, log_type: str = "generic"):
    """
    Lưu group stats vào MongoDB (append/merge theo group name).
    """
    if group_stats is None or group_stats.empty:
        return
    
    records = group_stats.to_dict(orient="records")
    for record in records:
        record["log_type"] = log_type
        record["updated_at"] = datetime.utcnow()
        
        group_name = record.get("group")
        if group_name:
            group_stats_col.update_one(
                {"group": group_name, "log_type": log_type},
                {"$set": record},
                upsert=True
            )


def save_global_stats(global_stats: dict, log_type: str = "generic"):
    """
    Lưu global stats vào MongoDB (append/merge theo log_type).
    """
    if not global_stats or not isinstance(global_stats, dict):
        return
    
    record = {
        "log_type": log_type,
        "updated_at": datetime.utcnow(),
        **global_stats
    }
    
    global_stats_col.update_one(
        {"log_type": log_type},
        {"$set": record},
        upsert=True
    )


def load_user_stats(log_type: str = "generic") -> pd.DataFrame:
    """
    Lấy user stats từ MongoDB theo log_type.
    """
    try:
        records = list(user_stats_col.find({"log_type": log_type}))
        if not records:
            return pd.DataFrame()
        # Loại bỏ _id field
        for r in records:
            r.pop("_id", None)
        return pd.DataFrame(records)
    except Exception:
        return pd.DataFrame()


def load_device_stats(log_type: str = "generic") -> pd.DataFrame:
    """
    Lấy device stats từ MongoDB theo log_type.
    """
    try:
        records = list(device_stats_col.find({"log_type": log_type}))
        if not records:
            return pd.DataFrame()
        # Loại bỏ _id field
        for r in records:
            r.pop("_id", None)
        return pd.DataFrame(records)
    except Exception:
        return pd.DataFrame()


def load_group_stats(log_type: str = "generic") -> pd.DataFrame:
    """
    Lấy group stats từ MongoDB theo log_type.
    """
    try:
        records = list(group_stats_col.find({"log_type": log_type}))
        if not records:
            return pd.DataFrame()
        # Loại bỏ _id field
        for r in records:
            r.pop("_id", None)
        return pd.DataFrame(records)
    except Exception:
        return pd.DataFrame()


def load_global_stats(log_type: str = "generic") -> dict:
    """
    Lấy global stats từ MongoDB theo log_type.
    """
    try:
        record = global_stats_col.find_one({"log_type": log_type})
        if not record:
            return {}
        # Loại bỏ _id và log_type/updated_at fields
        record.pop("_id", None)
        record.pop("log_type", None)
        record.pop("updated_at", None)
        return record
    except Exception:
        return {}


# ===================== MEMBER/GROUP OPERATIONS =====================

def save_group_members(group_members: dict, log_type: str = "generic"):
    """
    Lưu group membership vào MongoDB.
    Format: {group_name: {users: [...], source_ips: [...], hosts: [...]}}
    """
    if not group_members or not isinstance(group_members, dict):
        return
    
    for group_name, members_info in group_members.items():
        record = {
            "group": group_name,
            "log_type": log_type,
            "updated_at": datetime.utcnow(),
            **members_info  # Chứa users, source_ips, hosts
        }
        
        group_members_col.update_one(
            {"group": group_name, "log_type": log_type},
            {"$set": record},
            upsert=True
        )


def save_user_to_group(user_to_group: dict, log_type: str = "generic"):
    """
    Lưu user → group mapping vào MongoDB.
    Format: {username: group_name}
    """
    if not user_to_group or not isinstance(user_to_group, dict):
        return
    
    for username, group_name in user_to_group.items():
        record = {
            "username": username,
            "group": group_name,
            "log_type": log_type,
            "updated_at": datetime.utcnow()
        }
        
        user_to_group_col.update_one(
            {"username": username, "log_type": log_type},
            {"$set": record},
            upsert=True
        )


def save_device_to_group(device_to_group: dict, log_type: str = "generic"):
    """
    Lưu device → group mapping vào MongoDB.
    Format: {device_id: group_name}
    """
    if not device_to_group or not isinstance(device_to_group, dict):
        return
    
    for device_id, group_name in device_to_group.items():
        record = {
            "device": device_id,
            "group": group_name,
            "log_type": log_type,
            "updated_at": datetime.utcnow()
        }
        
        device_to_group_col.update_one(
            {"device": device_id, "log_type": log_type},
            {"$set": record},
            upsert=True
        )


def load_group_members(log_type: str = "generic") -> dict:
    """
    Lấy group members từ MongoDB theo log_type.
    Returns: {group_name: {users: [...], source_ips: [...], hosts: [...]}}
    """
    try:
        records = list(group_members_col.find({"log_type": log_type}))
        if not records:
            return {}
        
        result = {}
        for r in records:
            group_name = r.get("group")
            if group_name:
                # Loại bỏ metadata fields
                members_info = {k: v for k, v in r.items() 
                               if k not in ["_id", "group", "log_type", "updated_at"]}
                result[group_name] = members_info
        return result
    except Exception:
        return {}


def load_user_to_group(log_type: str = "generic") -> dict:
    """
    Lấy user → group mapping từ MongoDB theo log_type.
    Returns: {username: group_name}
    """
    try:
        records = list(user_to_group_col.find({"log_type": log_type}))
        if not records:
            return {}
        
        return {r.get("username"): r.get("group") for r in records if r.get("username")}
    except Exception:
        return {}


def load_device_to_group(log_type: str = "generic") -> dict:
    """
    Lấy device → group mapping từ MongoDB theo log_type.
    Returns: {device_id: group_name}
    """
    try:
        records = list(device_to_group_col.find({"log_type": log_type}))
        if not records:
            return {}
        
        return {r.get("device"): r.get("group") for r in records if r.get("device")}
    except Exception:
        return {}


# ===================== MODEL OPERATIONS (Isolation Forest) =====================

def save_user_models(user_models: dict, log_type: str = "generic"):
    """
    Lưu user models (EntityModel dict) vào MongoDB dưới dạng binary.
    Format: {entity_name: EntityModel}
    """
    if not user_models or not isinstance(user_models, dict):
        return
    
    try:
        # Serialize models to base64
        models_bytes = pickle.dumps(user_models)
        models_b64 = base64.b64encode(models_bytes).decode('utf-8')
        
        record = {
            "log_type": log_type,
            "updated_at": datetime.utcnow(),
            "models": models_b64,
            "count": len(user_models)
        }
        
        user_models_col.update_one(
            {"log_type": log_type},
            {"$set": record},
            upsert=True
        )
    except Exception as e:
        print(f"[MONGO] Error saving user models: {e}")


def save_device_models(device_models: dict, log_type: str = "generic"):
    """
    Lưu device models vào MongoDB dưới dạng binary.
    """
    if not device_models or not isinstance(device_models, dict):
        return
    
    try:
        models_bytes = pickle.dumps(device_models)
        models_b64 = base64.b64encode(models_bytes).decode('utf-8')
        
        record = {
            "log_type": log_type,
            "updated_at": datetime.utcnow(),
            "models": models_b64,
            "count": len(device_models)
        }
        
        device_models_col.update_one(
            {"log_type": log_type},
            {"$set": record},
            upsert=True
        )
    except Exception as e:
        print(f"[MONGO] Error saving device models: {e}")


def save_group_models(group_models: dict, log_type: str = "generic"):
    """
    Lưu group models vào MongoDB dưới dạng binary.
    """
    if not group_models or not isinstance(group_models, dict):
        return
    
    try:
        models_bytes = pickle.dumps(group_models)
        models_b64 = base64.b64encode(models_bytes).decode('utf-8')
        
        record = {
            "log_type": log_type,
            "updated_at": datetime.utcnow(),
            "models": models_b64,
            "count": len(group_models)
        }
        
        group_models_col.update_one(
            {"log_type": log_type},
            {"$set": record},
            upsert=True
        )
    except Exception as e:
        print(f"[MONGO] Error saving group models: {e}")


def load_user_models(log_type: str = "generic") -> dict:
    """
    Lấy user models từ MongoDB theo log_type.
    Returns: {entity_name: EntityModel} hoặc {} nếu không tìm thấy
    """
    try:
        record = user_models_col.find_one({"log_type": log_type})
        if not record:
            return {}
        
        models_b64 = record.get("models")
        if not models_b64:
            return {}
        
        models_bytes = base64.b64decode(models_b64)
        return pickle.loads(models_bytes)
    except Exception as e:
        print(f"[MONGO] Error loading user models: {e}")
        return {}


def load_device_models(log_type: str = "generic") -> dict:
    """
    Lấy device models từ MongoDB theo log_type.
    """
    try:
        record = device_models_col.find_one({"log_type": log_type})
        if not record:
            return {}
        
        models_b64 = record.get("models")
        if not models_b64:
            return {}
        
        models_bytes = base64.b64decode(models_b64)
        return pickle.loads(models_bytes)
    except Exception as e:
        print(f"[MONGO] Error loading device models: {e}")
        return {}


def load_group_models(log_type: str = "generic") -> dict:
    """
    Lấy group models từ MongoDB theo log_type.
    """
    try:
        record = group_models_col.find_one({"log_type": log_type})
        if not record:
            return {}
        
        models_b64 = record.get("models")
        if not models_b64:
            return {}
        
        models_bytes = base64.b64decode(models_b64)
        return pickle.loads(models_bytes)
    except Exception as e:
        print(f"[MONGO] Error loading group models: {e}")
        return {}