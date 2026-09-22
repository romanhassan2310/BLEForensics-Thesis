namespace BLEForensics.Models
{
    public class BluetoothCommunication
    {
        public int Id { get; set; }

        public string Source { get; set; } = string.Empty;

        public string Destination { get; set; } = string.Empty;

        public int Count { get; set; }

        public int EvidenceFileId { get; set; }

        public EvidenceFile EvidenceFile { get; set; } = null!;
    }
}
