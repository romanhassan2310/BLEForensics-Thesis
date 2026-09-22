namespace BLEForensics.Models
{
    public class BluetoothDevice
    {
        public int Id { get; set; }

        public string MacAddress { get; set; } = string.Empty;

        public string DeviceName { get; set; } = "Unknown";

        public int EvidenceFileId { get; set; }

        public EvidenceFile EvidenceFile { get; set; } = null!;
    }
}