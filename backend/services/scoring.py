"""
Unified Scoring System for Security Alerts

This module provides centralized scoring and severity calculation
for all alert types (Apache, DNS, Firewall, etc.)

Score Ranges:
- CRITICAL: 8.0 - 10.0 (Confirmed attacks, active compromises)
- WARNING:  4.0 - 7.9  (Suspicious activity, potential threats)
- INFO:     1.0 - 3.9  (Anomalies, baseline deviations)
"""

import json
import os
from typing import List, Dict, Any, Optional

# Global config cache
_scoring_config = None


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load scoring configuration from JSON file."""
    global _scoring_config
    
    if _scoring_config is not None:
        return _scoring_config
    
    if config_path is None:
        # Default path relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "..", "config", "scoring.json")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            _scoring_config = json.load(f)
        return _scoring_config
    except Exception as e:
        print(f"[WARN] Failed to load scoring config: {e}, using defaults")
        # Fallback defaults
        return {
            "severity_thresholds": {"CRITICAL": 8.0, "WARNING": 4.0, "INFO": 1.0},
            "attack_type_scores": {},
            "score_modifiers": {}
        }


def reload_config(config_path: str = None):
    """Reload scoring configuration (useful for runtime updates)."""
    global _scoring_config
    _scoring_config = None
    return load_config(config_path)


def get_base_score(attack_type: str) -> float:
    """
    Get base score for an attack type.
    
    Args:
        attack_type: Type of attack (e.g., 'account_takeover', 'dns_tunneling')
    
    Returns:
        Base score (1.0-10.0), defaults to 5.0 if not found
    """
    config = load_config()
    return config.get("attack_type_scores", {}).get(attack_type, 5.0)


def calculate_score(attack_type: str, modifiers: List[str] = None) -> float:
    """
    Calculate final score with modifiers.
    
    Args:
        attack_type: Type of attack
        modifiers: List of modifier names to apply (e.g., ['public_ip', 'high_volume'])
    
    Returns:
        Final score clamped to 1.0-10.0 range
    
    Example:
        >>> calculate_score('account_takeover', ['public_ip', 'confirmed_success'])
        10.0
        >>> calculate_score('internal_movement', ['internal_ip'])
        5.0
    """
    config = load_config()
    score = get_base_score(attack_type)
    
    if modifiers:
        modifier_values = config.get("score_modifiers", {})
        for modifier in modifiers:
            score += modifier_values.get(modifier, 0.0)
    
    # Clamp to 1.0-10.0 range
    return max(1.0, min(10.0, score))


def get_severity(score: float) -> str:
    """
    Map score to severity level.
    
    Args:
        score: Alert score (1.0-10.0)
    
    Returns:
        Severity level: 'CRITICAL', 'WARNING', or 'INFO'
    """
    config = load_config()
    thresholds = config.get("severity_thresholds", {})
    
    if score >= thresholds.get("CRITICAL", 8.0):
        return "CRITICAL"
    elif score >= thresholds.get("WARNING", 4.0):
        return "WARNING"
    else:
        return "INFO"


def get_alert_metadata(attack_type: str, modifiers: List[str] = None) -> Dict[str, Any]:
    """
    Get complete alert metadata (score + severity).
    
    Args:
        attack_type: Type of attack
        modifiers: List of modifier names
    
    Returns:
        Dict with 'score' and 'severity' keys
    
    Example:
        >>> get_alert_metadata('dns_tunneling', ['public_ip'])
        {'score': 10.0, 'severity': 'CRITICAL'}
    """
    score = calculate_score(attack_type, modifiers)
    severity = get_severity(score)
    
    return {
        "score": score,
        "severity": severity
    }


def get_all_attack_types() -> List[str]:
    """Get list of all configured attack types."""
    config = load_config()
    return list(config.get("attack_type_scores", {}).keys())


def get_all_modifiers() -> List[str]:
    """Get list of all configured modifiers."""
    config = load_config()
    return list(config.get("score_modifiers", {}).keys())


# Convenience function for backward compatibility
def score_alert(alert_type: str, **kwargs) -> Dict[str, Any]:
    """
    Score an alert with optional context.
    
    Args:
        alert_type: Type of alert
        **kwargs: Context flags (is_public_ip=True, high_volume=True, etc.)
    
    Returns:
        Dict with score and severity
    """
    modifiers = []
    
    # Map common kwargs to modifiers
    if kwargs.get('is_public_ip') or kwargs.get('from_public_ip'):
        modifiers.append('public_ip')
    if kwargs.get('is_internal_ip') or kwargs.get('from_internal_ip'):
        modifiers.append('internal_ip')
    if kwargs.get('is_blacklisted'):
        modifiers.append('blacklisted_ip')
    if kwargs.get('high_volume'):
        modifiers.append('high_volume')
    if kwargs.get('medium_volume'):
        modifiers.append('medium_volume')
    if kwargs.get('confirmed_success'):
        modifiers.append('confirmed_success')
    if kwargs.get('failed_attempt'):
        modifiers.append('failed_attempt')
    if kwargs.get('sensitive_data'):
        modifiers.append('sensitive_data')
    
    return get_alert_metadata(alert_type, modifiers)
