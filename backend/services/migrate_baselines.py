"""
Helper script để migrate old baselines từ file system sang MongoDB.
Chạy script này một lần sau khi update MongoDB integration.

Usage:
  python -c "from services.migrate_baselines import migrate_all; migrate_all()"
"""

import os
import json
import pandas as pd
from pathlib import Path
from services.database import (
    save_user_stats, save_device_stats, save_group_stats, save_global_stats
)


def migrate_all(baselines_dir: str = None):
    """
    Migrate all baselines từ file system sang MongoDB.
    """
    if baselines_dir is None:
        baselines_dir = os.path.join(os.path.dirname(__file__), "..", "config", "baselines")
    
    if not os.path.exists(baselines_dir):
        print(f"⚠️  Baselines directory not found: {baselines_dir}")
        return
    
    print(f"📂 Migrating baselines from: {baselines_dir}")
    
    # Migrate user_stats.json
    user_stats_path = os.path.join(baselines_dir, "user_stats.json")
    if os.path.exists(user_stats_path):
        try:
            with open(user_stats_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                df = pd.DataFrame(data)
                save_user_stats(df, log_type="generic")
                print(f"Migrated user_stats: {len(df)} records")
            else:
                print(f"user_stats.json format not recognized (expected list)")
        except Exception as e:
            print(f"Error migrating user_stats: {e}")
    
    # Migrate device_stats.json
    device_stats_path = os.path.join(baselines_dir, "device_stats.json")
    if os.path.exists(device_stats_path):
        try:
            with open(device_stats_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                df = pd.DataFrame(data)
                save_device_stats(df, log_type="generic")
                print(f"Migrated device_stats: {len(df)} records")
            else:
                print(f"⚠️  device_stats.json format not recognized (expected list)")
        except Exception as e:
            print(f"Error migrating device_stats: {e}")
    
    # Migrate group_stats.json
    group_stats_path = os.path.join(baselines_dir, "group_stats.json")
    if os.path.exists(group_stats_path):
        try:
            with open(group_stats_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                df = pd.DataFrame(data)
                save_group_stats(df, log_type="generic")
                print(f"Migrated group_stats: {len(df)} records")
            else:
                print(f"⚠️  group_stats.json format not recognized (expected list)")
        except Exception as e:
            print(f"Error migrating group_stats: {e}")
    
    # Migrate global_baseline.json
    global_baseline_path = os.path.join(baselines_dir, "global_baseline.json")
    if os.path.exists(global_baseline_path):
        try:
            with open(global_baseline_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list) and len(data) > 0:
                # Take the last (most recent) snapshot
                latest = data[-1]
                save_global_stats(latest, log_type="generic")
                print(f"Migrated global_baseline: 1 record (latest snapshot)")
            elif isinstance(data, dict):
                save_global_stats(data, log_type="generic")
                print(f"Migrated global_baseline: 1 record")
            else:
                print(f"global_baseline.json format not recognized")
        except Exception as e:
            print(f"Error migrating global_baseline: {e}")
    
    print("\nMigration complete!")


if __name__ == "__main__":
    migrate_all()






