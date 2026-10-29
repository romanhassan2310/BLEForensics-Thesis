import subprocess

# Wireshark ইন্সটলেশন পাথ
TSHARK_EXECUTABLE = r'E:\Thesis\Wireshark\tshark.exe'

# Evidence ফোল্ডারের অন্য একটি বড় ক্যাপচার ফাইলের নাম এখানে দিন (যেমন আপনার ফোল্ডারের যেকোনো একটি বড় ফাইলের নাম)
pcap_file = "Evidence/cddda334-300d-4bb8-81fc-0948e74fa37c_Bluetooth_HCI_and_OBEX_Transaction_over_USB.pcap"
# অথবা এক্সটেনশন .cap হলে সেটি দেবেন

print(f"Parsing capture file directly using TShark from: {TSHARK_EXECUTABLE}")

try:
    cmd = [TSHARK_EXECUTABLE, '-r', pcap_file, '-T', 'fields', '-e', '_ws.col.Protocol']
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    packet_count = 0
    protocols = {}

    for line in process.stdout:
        proto = line.strip()
        if proto:
            packet_count += 1
            protocols[proto] = protocols.get(proto, 0) + 1

    process.wait()

    print(f"\n================ VALIDATION RESULTS ================")
    print(f"Total Packets         : {packet_count}")
    print(f"Protocol Breakdown    : {protocols}")
    print(f"====================================================\n")

except Exception as e:
    print(f"\nAn error occurred during parsing: {e}")