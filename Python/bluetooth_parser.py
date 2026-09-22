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

    IMPORTANT:
    This function never generates a new timestamp.

    If the PCAP packet does not contain a usable timestamp,
    None is returned rather than using datetime.now().
    """

    try:

        if not hasattr(packet, "sniff_time"):
            return None

        sniff_time = packet.sniff_time

        if sniff_time is None:
            return None

        # PyShark normally returns an aware datetime.
        # If it is naive, interpret it as UTC.
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
    """
    Extract Bluetooth source and destination addresses
    from the packet using fields supported by the capture.

    Address extraction follows this priority:

    1. HCI Event
    2. HCI ACL
    3. Generic Bluetooth layers

    If an address is not actually present in the packet,
    None is returned instead of fabricating an endpoint.
    """

    src = None
    dst = None

    # =========================================================
    # HCI Event
    # =========================================================

    try:

        if hasattr(packet, "bthci_evt"):

            evt = packet.bthci_evt

            source_fields = [
                "src_bd_addr",
                "src"
            ]

            destination_fields = [
                "dst_bd_addr",
                "dst"
            ]

            for field_name in source_fields:

                value = get_field(
                    evt,
                    field_name
                )

                address = normalize_address(value)

                if address:

                    src = address
                    break

            for field_name in destination_fields:

                value = get_field(
                    evt,
                    field_name
                )

                address = normalize_address(value)

                if address:

                    dst = address
                    break

    except Exception:
        pass

    # =========================================================
    # HCI ACL
    # =========================================================

    try:

        if hasattr(packet, "bthci_acl"):

            acl = packet.bthci_acl

            # IMPORTANT:
            #
            # Do NOT use:
            #     bthci_acl.bd_addr
            #
            # The capture/TShark version does not expose
            # that field.
            #
            # Prefer the explicit ACL endpoint fields.

            source_fields = [
                "src_bd_addr",
                "src"
            ]

            destination_fields = [
                "dst_bd_addr",
                "dst"
            ]

            for field_name in source_fields:

                value = get_field(
                    acl,
                    field_name
                )

                address = normalize_address(value)

                if address:

                    src = address
                    break

            for field_name in destination_fields:

                value = get_field(
                    acl,
                    field_name
                )

                address = normalize_address(value)

                if address:

                    dst = address
                    break

    except Exception:
        pass

    # =========================================================
    # Generic Bluetooth layer fallback
    # =========================================================

    try:

        for layer in packet.layers:

            if src is None:

                for field_name in [
                    "src_bd_addr",
                    "src"
                ]:

                    value = get_field(
                        layer,
                        field_name
                    )

                    address = normalize_address(value)

                    if address:

                        src = address
                        break

            if dst is None:

                for field_name in [
                    "dst_bd_addr",
                    "dst"
                ]:

                    value = get_field(
                        layer,
                        field_name
                    )

                    address = normalize_address(value)

                    if address:

                        dst = address
                        break

            if src is not None and dst is not None:
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

        # =====================================================
        # Process packets
        # =====================================================

        for packet in capture:

            total_packets += 1

            packet_number = total_packets

            # =================================================
            # Packet timestamp
            # =================================================

            packet_timestamp = get_packet_timestamp(
                packet
            )

            packet_datetime = parse_timestamp(
                packet_timestamp
            )

            # -------------------------------------------------
            # Capture start/end
            # -------------------------------------------------

            if packet_datetime is not None:

                if capture_start_time is None:

                    capture_start_time = packet_datetime

                capture_end_time = packet_datetime

            # =================================================
            # Get packet layers
            # =================================================

            try:

                layers = [
                    layer.layer_name
                    for layer in packet.layers
                ]

                layers_lower = [
                    layer.layer_name.lower()
                    for layer in packet.layers
                ]

            except Exception:

                layers = []

                layers_lower = []

            # =================================================
            # Layer frequency
            # =================================================

            for layer_name in layers:

                layer_frequency[layer_name] = (
                    layer_frequency.get(
                        layer_name,
                        0
                    ) + 1
                )

            # =================================================
            # Protocol counting
            #
            # Independent checks are intentional because
            # one packet can contain multiple protocol layers.
            # =================================================

            detected_protocol = False

            if "bthci_cmd" in layers_lower:

                protocol_counts[
                    "HCI_Command"
                ] += 1

                detected_protocol = True

            if "bthci_evt" in layers_lower:

                protocol_counts[
                    "HCI_Event"
                ] += 1

                detected_protocol = True

            if "bthci_acl" in layers_lower:

                protocol_counts[
                    "HCI_ACL"
                ] += 1

                detected_protocol = True

            if "btl2cap" in layers_lower:

                protocol_counts[
                    "L2CAP"
                ] += 1

                detected_protocol = True

            if "btrfcomm" in layers_lower:

                protocol_counts[
                    "RFCOMM"
                ] += 1

                detected_protocol = True

            if "obex" in layers_lower:

                protocol_counts[
                    "OBEX"
                ] += 1

                detected_protocol = True

            if "btsdp" in layers_lower:

                protocol_counts[
                    "SDP"
                ] += 1

                detected_protocol = True

            if not detected_protocol:

                protocol_counts[
                    "Unknown"
                ] += 1

            # =================================================
            # Determine primary protocol
            # =================================================

            detected_protocol_name = get_packet_protocol(
                layers_lower
            )

            # =================================================
            # Packet length
            # =================================================

            try:

                packet_length = len(packet)

            except Exception:

                packet_length = 0

            # =================================================
            # Extract Bluetooth addresses
            # =================================================

            src, dst = extract_bluetooth_addresses(
                packet
            )

            if src:

                discovered_devices.add(src)

            if dst:

                discovered_devices.add(dst)

            # =================================================
            # Communication relationship
            # =================================================

            if (
                src
                and dst
                and src != dst
            ):

                key = (
                    src,
                    dst
                )

                communication_edges[key] = (
                    communication_edges.get(
                        key,
                        0
                    ) + 1
                )

            # =================================================
            # Store HCI command candidates
            # =================================================

            if "bthci_cmd" in layers_lower:

                suspicious_packets.append({

                    "packetNumber":
                        packet_number,

                    "timestamp":
                        packet_timestamp,

                    "protocol":
                        "HCI_Command",

                    "source":
                        src if src else "Unknown",

                    "destination":
                        dst if dst else "Unknown",

                    "packetLength":
                        packet_length,

                    "severity":
                        "Pending",

                    "reason":
                        "Pending excessive HCI command activity analysis."

                })

        # =====================================================
        # Build communication list
        # =====================================================

        communications = []

        for (
            src,
            dst
        ), count in communication_edges.items():

            communications.append({

                "source":
                    src,

                "destination":
                    dst,

                "count":
                    count

            })

        # =====================================================
        # Suspicious Activity Detection
        # =====================================================

        HCI_COMMAND_THRESHOLD = 50

        hci_command_count = protocol_counts[
            "HCI_Command"
        ]

        if hci_command_count > HCI_COMMAND_THRESHOLD:

            # -------------------------------------------------
            # The 51st HCI command is the point at which
            # excessive activity becomes detectable.
            # -------------------------------------------------

            threshold_packet = (
                suspicious_packets[
                    HCI_COMMAND_THRESHOLD
                ]
                if len(suspicious_packets)
                > HCI_COMMAND_THRESHOLD
                else None
            )

            if threshold_packet:

                event_timestamp = (
                    threshold_packet.get(
                        "timestamp"
                    )
                )

                event_packet_number = (
                    threshold_packet.get(
                        "packetNumber"
                    )
                )

                event_source = (
                    threshold_packet.get(
                        "source"
                    )
                )

                event_destination = (
                    threshold_packet.get(
                        "destination"
                    )
                )

            else:

                event_timestamp = None

                event_packet_number = 0

                event_source = "Unknown"

                event_destination = "Unknown"

            # -------------------------------------------------
            # Create forensic event
            # -------------------------------------------------

# =========================================================
# Determine event end boundary
# =========================================================

event_end_timestamp = None
event_end_packet_number = None

if suspicious_packets:

    last_suspicious_packet = suspicious_packets[-1]

    event_end_timestamp = (
        last_suspicious_packet.get(
            "timestamp"
        )
    )

    event_end_packet_number = (
        last_suspicious_packet.get(
            "packetNumber"
        )
    )


# =========================================================
# Create forensic event
# =========================================================

suspicious_event = {

    "attackType":
        "Excessive HCI Command Activity",

    "severity":
        "Medium",

    "source":
        event_source,

    "destination":
        event_destination,

    # -----------------------------------------------------
    # Observed evidence + analytical interpretation
    # -----------------------------------------------------

    "description":
        (
            f"Observed evidence: "
            f"{hci_command_count} HCI command packets "
            f"were identified in the PCAP capture. "
            f"The configured threshold is "
            f"{HCI_COMMAND_THRESHOLD}. "
            f"The threshold was first crossed at "
            f"packet {event_packet_number}. "
            f"Analytical interpretation: the observed "
            f"command volume is classified as excessive "
            f"HCI command activity and requires "
            f"investigation for possible abnormal or "
            f"automated Bluetooth controller activity."
        ),

    # -----------------------------------------------------
    # Event start
    # -----------------------------------------------------

    "timestamp":
        event_timestamp,

    "packetNumber":
        event_packet_number,

    # -----------------------------------------------------
    # Event end
    # -----------------------------------------------------

    "endTimestamp":
        event_end_timestamp,

    "endPacketNumber":
        event_end_packet_number
}

            # -------------------------------------------------
            # Only create the event if a real packet timestamp
            # exists. Never fabricate a forensic timestamp.
            # -------------------------------------------------

            if event_timestamp:

                suspicious_events.append(
                    suspicious_event
                )

            # -------------------------------------------------
            # Mark collected HCI command packets
            # -------------------------------------------------

            for suspicious_packet in suspicious_packets:

                suspicious_packet[
                    "severity"
                ] = "Medium"

                suspicious_packet[
                    "reason"
                ] = (
                    "Packet belongs to excessive "
                    "HCI command activity."
                )

        else:

            # -------------------------------------------------
            # Threshold not reached.
            # -------------------------------------------------

            suspicious_packets = []

        # =====================================================
        # Sort Layer Frequency
        # =====================================================

        layer_frequency = dict(
            sorted(
                layer_frequency.items(),
                key=lambda item: item[1],
                reverse=True
            )
        )

        # =====================================================
        # Convert capture times to ISO strings
        # =====================================================

        capture_start_iso = (
            capture_start_time.isoformat()
            if capture_start_time
            else None
        )

        capture_end_iso = (
            capture_end_time.isoformat()
            if capture_end_time
            else None
        )

        # =====================================================
        # Final Result
        # =====================================================

        return {

            "captureType":
                "Bluetooth HCI",

            "totalPackets":
                total_packets,

            "captureStartTime":
                capture_start_iso,

            "captureEndTime":
                capture_end_iso,

            "protocols":
                protocol_counts,

            "devices":
                sorted(
                    list(
                        discovered_devices
                    )
                ),

            "communications":
                communications,

            "layerFrequency":
                layer_frequency,

            "suspiciousPackets":
                suspicious_packets,

            "suspiciousEvents":
                suspicious_events
        }

    except Exception as ex:

        return {

            "error":
                str(ex)

        }

    finally:

        if capture is not None:

            try:
                capture.close()

            except Exception:
                pass


# ============================================================
# Command-line entry point
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            json.dumps({
                "error":
                    "No PCAP file provided"
            })
        )

        sys.exit(1)

    capture_file = sys.argv[1]

    result = analyze_bluetooth_capture(
        capture_file
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )