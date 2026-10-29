import asyncio
import json
import sys
import pyshark
from datetime import datetime, timezone


def ensure_event_loop():
    """
    Ensure that PyShark has an asyncio event loop.
    Required for newer Python versions.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


def normalize_address(address):
    """
    Normalize a Bluetooth MAC address.
    Ignore invalid/zero Bluetooth addresses.
    """
    if not address:
        return None

    address = str(address).strip().upper()
    parts = address.split(":")

    if len(parts) != 6:
        return None

    if not all(len(part) == 2 for part in parts):
        return None

    if not all(
        all(
            character in "0123456789ABCDEF"
            for character in part
        )
        for part in parts
    ):
        return None

    # Ignore Bluetooth null/zero address
    if address == "00:00:00:00:00:00":
        return None

    return address


def get_field(layer, field_name):
    """
    Safely retrieve a field from a PyShark layer.
    """
    try:
        if hasattr(layer, field_name):
            value = getattr(
                layer,
                field_name
            )
            if value is not None:
                return str(value)
    except Exception:
        pass

    return None


def get_packet_timestamp(packet):
    """
    Retrieve the original timestamp from the PCAP packet.
    """
    try:
        if not hasattr(packet, "sniff_time"):
            return None

        sniff_time = packet.sniff_time

        if sniff_time is None:
            return None

        if sniff_time.tzinfo is None:
            sniff_time = sniff_time.replace(
                tzinfo=timezone.utc
            )
        else:
            sniff_time = sniff_time.astimezone(
                timezone.utc
            )

        return sniff_time.isoformat()

    except Exception:
        return None


def parse_timestamp(timestamp):
    """
    Convert ISO timestamp string into a timezone-aware datetime.
    """
    if not timestamp:
        return None

    try:
        value = datetime.fromisoformat(
            timestamp
        )

        if value.tzinfo is None:
            value = value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )

    except Exception:
        return None


def get_packet_protocol(layers_lower):
    """
    Determine the primary Bluetooth protocol
    represented by the packet.
    """
    if "bthci_cmd" in layers_lower:
        return "HCI_Command"

    if "bthci_evt" in layers_lower:
        return "HCI_Event"

    if "bthci_acl" in layers_lower:
        return "HCI_ACL"

    if "btl2cap" in layers_lower:
        return "L2CAP"

    if "btrfcomm" in layers_lower:
        return "RFCOMM"

    if "obex" in layers_lower:
        return "OBEX"

    if "btsdp" in layers_lower:
        return "SDP"

    return "Unknown"


def extract_bluetooth_addresses(packet):
    src = None
    dst = None

    try:
        for layer in packet.layers:
            layer_fields = layer.field_names if hasattr(layer, 'field_names') else []
            
            for field_name in layer_fields:
                field_lower = field_name.lower()
                
                if src is None and ('src' in field_lower or 'bd_addr' in field_lower or 'source' in field_lower):
                    if 'dst' not in field_lower and 'destination' not in field_lower:
                        val = get_field(layer, field_name)
                        norm = normalize_address(val)
                        if norm:
                            src = norm

                if dst is None and ('dst' in field_lower or 'destination' in field_lower):
                    val = get_field(layer, field_name)
                    norm = normalize_address(val)
                    if norm:
                        dst = norm

            if src is not None and dst is not None:
                break
    except Exception:
        pass

    if not src or not dst:
        try:
            for layer in packet.layers:
                if src is None:
                    for f in ["src_bd_addr", "bd_addr_s", "source", "src"]:
                        val = get_field(layer, f)
                        norm = normalize_address(val)
                        if norm:
                            src = norm
                            break
                if dst is None:
                    for f in ["dst_bd_addr", "bd_addr_d", "destination", "dst"]:
                        val = get_field(layer, f)
                        norm = normalize_address(val)
                        if norm:
                            dst = norm
                            break
        except Exception:
            pass

    return src, dst


def analyze_bluetooth_capture(capture_file):
    ensure_event_loop()

    protocol_counts = {
        "HCI_Command": 0,
        "HCI_Event": 0,
        "HCI_ACL": 0,
        "L2CAP": 0,
        "RFCOMM": 0,
        "OBEX": 0,
        "SDP": 0,
        "Unknown": 0
    }

    suspicious_events = []
    suspicious_packets = []
    layer_frequency = {}
    discovered_devices = set()
    communication_edges = {}
    total_packets = 0

    capture_start_time = None
    capture_end_time = None
    capture = None

    try:
        capture = pyshark.FileCapture(
            capture_file,
            keep_packets=False
        )

        for packet in capture:
            total_packets += 1
            packet_number = total_packets

            packet_timestamp = get_packet_timestamp(packet)
            packet_datetime = parse_timestamp(packet_timestamp)

            if packet_datetime is not None:
                if capture_start_time is None:
                    capture_start_time = packet_datetime
                capture_end_time = packet_datetime

            try:
                layers = [layer.layer_name for layer in packet.layers]
                layers_lower = [layer.layer_name.lower() for layer in packet.layers]
            except Exception:
                layers = []
                layers_lower = []

            for layer_name in layers:
                layer_frequency[layer_name] = layer_frequency.get(layer_name, 0) + 1

            detected_protocol = False
            if "bthci_cmd" in layers_lower:
                protocol_counts["HCI_Command"] += 1
                detected_protocol = True
            if "bthci_evt" in layers_lower:
                protocol_counts["HCI_Event"] += 1
                detected_protocol = True
            if "bthci_acl" in layers_lower:
                protocol_counts["HCI_ACL"] += 1
                detected_protocol = True
            if "btl2cap" in layers_lower:
                protocol_counts["L2CAP"] += 1
                detected_protocol = True
            if "btrfcomm" in layers_lower:
                protocol_counts["RFCOMM"] += 1
                detected_protocol = True
            if "obex" in layers_lower:
                protocol_counts["OBEX"] += 1
                detected_protocol = True
            if "btsdp" in layers_lower:
                protocol_counts["SDP"] += 1
                detected_protocol = True

            if not detected_protocol:
                protocol_counts["Unknown"] += 1

            try:
                packet_length = len(packet)
            except Exception:
                packet_length = 0

            src, dst = extract_bluetooth_addresses(packet)

            if src:
                discovered_devices.add(src)
            if dst:
                discovered_devices.add(dst)

            if src and dst and src != dst:
                key = (src, dst)
                communication_edges[key] = communication_edges.get(key, 0) + 1

            if "bthci_cmd" in layers_lower:
                suspicious_packets.append({
                    "packetNumber": packet_number,
                    "timestamp": packet_timestamp,
                    "protocol": "HCI_Command",
                    "source": src if src else "Unknown",
                    "destination": dst if dst else "Unknown",
                    "packetLength": packet_length,
                    "severity": "Medium",
                    "reason": "Packet belongs to excessive HCI command activity."
                })

        communications = []
        for (src, dst), count in communication_edges.items():
            communications.append({
                "source": src,
                "destination": dst,
                "count": count
            })

        # --- MEDIUM SEVERITY LOGIC ---
        HCI_COMMAND_THRESHOLD = 50
        hci_command_count = protocol_counts["HCI_Command"]

        if hci_command_count > HCI_COMMAND_THRESHOLD:
            threshold_packet = suspicious_packets[HCI_COMMAND_THRESHOLD] if len(suspicious_packets) > HCI_COMMAND_THRESHOLD else None
            event_timestamp = threshold_packet.get("timestamp") if threshold_packet else (capture_start_time.isoformat() if capture_start_time else None)
            event_packet_number = threshold_packet.get("packetNumber") if threshold_packet else 1

            suspicious_events.append({
                "attackType": "Excessive HCI Command Activity",
                "severity": "Medium",
                "source": threshold_packet.get("source") if threshold_packet else "Unknown",
                "destination": threshold_packet.get("destination") if threshold_packet else "Unknown",
                "description": f"Observed {hci_command_count} HCI command packets, exceeding threshold ({HCI_COMMAND_THRESHOLD}).",
                "timestamp": event_timestamp,
                "packetNumber": event_packet_number,
                "endTimestamp": suspicious_packets[-1].get("timestamp") if suspicious_packets else None,
                "endPacketNumber": suspicious_packets[-1].get("packetNumber") if suspicious_packets else 0
            })

        # --- HIGH SEVERITY LOGIC ---
        if total_packets > 1000:
            suspicious_events.append({
                "attackType": "High Volume Traffic Flooding",
                "severity": "High",
                "source": "Unknown",
                "destination": "Unknown",
                "description": f"High volume traffic anomaly detected with {total_packets} total packets.",
                "timestamp": capture_start_time.isoformat() if capture_start_time else None,
                "packetNumber": 1,
                "endTimestamp": capture_end_time.isoformat() if capture_end_time else None,
                "endPacketNumber": total_packets
            })

        # --- LOW SEVERITY LOGIC ---
        if protocol_counts["Unknown"] > 50:
            suspicious_events.append({
                "attackType": "Protocol Minor Anomalies",
                "severity": "Low",
                "source": "Unknown",
                "destination": "Unknown",
                "description": f"Detected {protocol_counts['Unknown']} unknown protocol packets.",
                "timestamp": capture_start_time.isoformat() if capture_start_time else None,
                "packetNumber": 1,
                "endTimestamp": None,
                "endPacketNumber": 0
            })

        layer_frequency = dict(
            sorted(
                layer_frequency.items(),
                key=lambda item: item[1],
                reverse=True
            )
        )

        capture_start_iso = capture_start_time.isoformat() if capture_start_time else None
        capture_end_iso = capture_end_time.isoformat() if capture_end_time else None

        return {
            "captureType": "Bluetooth HCI",
            "totalPackets": total_packets,
            "captureStartTime": capture_start_iso,
            "captureEndTime": capture_end_iso,
            "protocols": protocol_counts,
            "devices": sorted(list(discovered_devices)),
            "communications": communications,
            "layerFrequency": layer_frequency,
            "suspiciousPackets": suspicious_packets,
            "suspiciousEvents": suspicious_events
        }

    except Exception as ex:
        return {
            "error": str(ex)
        }

    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No PCAP file provided"}))
        sys.exit(1)

    capture_file = sys.argv[1]
    result = analyze_bluetooth_capture(capture_file)
    print(json.dumps(result, indent=2))