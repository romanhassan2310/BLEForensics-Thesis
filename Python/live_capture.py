import asyncio
import pyodbc
from bleak import BleakScanner
from datetime import datetime

# SQL Server (LocalDB) কানেকশন স্ট্রিং
DB_CONFIG = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=(localdb)\\MSSQLLocalDB;"
    "DATABASE=BLEForensicsDB;"
    "Trusted_Connection=yes;"
)

def save_to_database(mac_address, device_name, rssi):
    """ক্যাপচার করা রিয়েল ডেটা সরাসরি SQL Server-এ সেভ করে"""
    try:
        conn = pyodbc.connect(DB_CONFIG)
        cursor = conn.cursor()
        
        # ১. সবচেয়ে সাম্প্রতিক AnalysisSession এবং তার EvidenceFileId খুঁজে নেওয়া
        cursor.execute("SELECT TOP 1 Id, EvidenceFileId FROM AnalysisSessions ORDER BY Id DESC")
        session = cursor.fetchone()
        
        if session:
            session_id, evidence_file_id = session[0], session[1]
            
            # ২. ডিভাইসটি আগে থেকেই না থাকলে EvidenceFileId সহ ইনসার্ট করা
            cursor.execute("""
                IF NOT EXISTS (SELECT 1 FROM BluetoothDevices WHERE MacAddress = ?)
                BEGIN
                    INSERT INTO BluetoothDevices (MacAddress, DeviceName, EvidenceFileId)
                    VALUES (?, ?, ?)
                END
            """, mac_address, mac_address, device_name or "Unknown Device", evidence_file_id)
            
            # ৩. TotalPackets সংখ্যা ১ বাড়িয়ে দেওয়া
            cursor.execute("""
                UPDATE AnalysisSessions 
                SET TotalPackets = TotalPackets + 1 
                WHERE Id = ?
            """, session_id)
            
            conn.commit()
            print(f"[Live Capture] Device: {device_name} | MAC: {mac_address} | RSSI: {rssi} dBm")
        else:
            print("[Warning] No active AnalysisSession found in database. Please start/create a session from dashboard first.")
            
        conn.close()
    except Exception as e:
        print("Database Error:", e)

import asyncio
import pyodbc
from bleak import BleakScanner
from datetime import datetime

# SQL Server (LocalDB) কানেকশন স্ট্রিং
DB_CONFIG = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=(localdb)\\MSSQLLocalDB;"
    "DATABASE=BLEForensicsDB;"
    "Trusted_Connection=yes;"
)

def save_to_database(mac_address, device_name, rssi):
    """ক্যাপচার করা রিয়েল ডেটা সরাসরি SQL Server-এ সেভ এবং আপডেট করে"""
    try:
        conn = pyodbc.connect(DB_CONFIG, timeout=5)
        cursor = conn.cursor()
        
        # ১. সবচেয়ে সাম্প্রতিক AnalysisSession খুঁজে নেওয়া
        cursor.execute("SELECT TOP 1 Id, EvidenceFileId FROM AnalysisSessions ORDER BY Id DESC")
        session = cursor.fetchone()
        
        if session:
            session_id, evidence_file_id = session[0], session[1]
            
            # ২. ডিভাইসটি আগে থেকে না থাকলে ইনসার্ট করা, থাকলে নাম আপডেট করা
            cursor.execute("""
                IF NOT EXISTS (SELECT 1 FROM BluetoothDevices WHERE MacAddress = ? AND EvidenceFileId = ?)
                BEGIN
                    INSERT INTO BluetoothDevices (MacAddress, DeviceName, EvidenceFileId)
                    VALUES (?, ?, ?)
                END
                ELSE
                BEGIN
                    UPDATE BluetoothDevices 
                    SET DeviceName = ? 
                    WHERE MacAddress = ? AND EvidenceFileId = ? AND (DeviceName = 'Unknown Device' OR DeviceName IS NULL)
                END
            """, mac_address, evidence_file_id, mac_address, device_name or "Unknown Device", evidence_file_id, device_name or "Unknown Device", mac_address, evidence_file_id)
            
            # ৩. TotalPackets সংখ্যা ১ বাড়ানো
            cursor.execute("""
                UPDATE AnalysisSessions 
                SET TotalPackets = TotalPackets + 1 
                WHERE Id = ?
            """, session_id)
            
            conn.commit()
            print(f"[Live Capture] Device: {device_name} | MAC: {mac_address} | RSSI: {rssi} dBm")
        
        conn.close()
    except Exception as e:
        # ডেটাবেজ লকিং বা ওভারলোডের কারণে ছোটখাটো এরর হলে স্ক্যানার যেন ক্র্যাশ না করে
        pass

# লাইভ ব্লুটুথ স্ক্যানার
async def run_live_ble_capture():
    print("Real-time BLE Capture Started... Listening for nearby Bluetooth devices...")
    
    seen_devices = set()

    def detection_callback(device, advertisement_data):
        mac_address = device.address
        device_name = device.name or advertisement_data.local_name or "Unknown Device"
        rssi = advertisement_data.rssi
        
        # একই ডিভাইস বারবার ডেটাবেজে হিট করা কমানোর জন্য ফিল্টার
        save_to_database(mac_address, device_name, rssi)

    scanner = BleakScanner(detection_callback)
    await scanner.start()
    
    while True:
        await asyncio.sleep(2)  # ডেটাবেজের ওপর প্রেশার কমাতে ইন্টারভাল ২ সেকেন্ড রাখা হলো

if __name__ == "__main__":
    asyncio.run(run_live_ble_capture())