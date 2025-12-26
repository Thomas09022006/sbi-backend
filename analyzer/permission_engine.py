DANGEROUS_PERMISSIONS = {
    "READ_SMS": "Reads OTP & banking messages",
    "SEND_SMS": "Can send SMS without consent",
    "READ_CONTACTS": "Steals contact list",
    "RECORD_AUDIO": "Records audio secretly",
    "ACCESS_FINE_LOCATION": "Tracks real-time location",
    "READ_CALL_LOG": "Reads call history",
    "CAMERA": "Captures photos/videos"
}

def check_permissions(all_permissions):
    dangerous = []
    for perm in all_permissions:
        for key in DANGEROUS_PERMISSIONS:
            if key in perm:
                dangerous.append({
                    "permission": key,
                    "risk": DANGEROUS_PERMISSIONS[key]
                })
    return dangerous
