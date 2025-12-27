from androguard.core.bytecodes.apk import APK
from analyzer.permission_engine import check_permissions
from analyzer.risk_engine import calculate_risk

def analyze_apk(apk_path):
    try:
        # ⚡ FAST & SAFE: Manifest-only parsing
        a = APK(apk_path)
    except Exception as e:
        raise Exception(f"APK parse failed: {e}")

    permissions = a.get_permissions() or []
    dangerous = check_permissions(permissions)
    score, level = calculate_risk(dangerous)

    return {
        "package_name": a.get_package(),
        "total_permissions": len(permissions),
        "dangerous_permissions": dangerous,
        "risk_score": score,
        "risk_level": level
    }
