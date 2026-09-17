# Detector layer: the actual "is this a scan" decision logic.

def is_scan(port_count: int, threshold: int) -> bool:

    if port_count >= threshold:
        return True

    else:
        return False


def classify_severity(port_count: int, window_seconds: float) -> str:
    
    rate = port_count / window_seconds

    if rate >= 3.0:
        return f"aggressive - {rate} ports/sec"
    
    elif rate >= 0.5:
        return f"moderate - {rate} ports/sec"

    else:
        return f"slow - {rate} ports/sec"