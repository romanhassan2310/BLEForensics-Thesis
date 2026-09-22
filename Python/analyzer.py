import json
import sys
from bluetooth_parser import analyze_bluetooth_capture

if len(sys.argv) < 2:
    print(json.dumps({"error": "No capture file provided"}))
    sys.exit(1)

capture_file = sys.argv[1]

try:
    result = analyze_bluetooth_capture(capture_file)
    print(json.dumps(result, indent=2))

except Exception as ex:
    print(json.dumps({
        "error": str(ex)
    }))