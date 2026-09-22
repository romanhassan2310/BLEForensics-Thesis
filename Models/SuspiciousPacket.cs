namespace BLEForensics.Models
{
    public class SuspiciousPacket
    {
        public int Id { get; set; }

        public int PacketNumber { get; set; }

        public DateTime Timestamp { get; set; }

        public string Protocol { get; set; } = string.Empty;

        public string Source { get; set; } = "Unknown";

        public string Destination { get; set; } = "Unknown";

        public int PacketLength { get; set; }

        public string Severity { get; set; } = string.Empty;

        public string Reason { get; set; } = string.Empty;

        public int EvidenceFileId { get; set; }

        public EvidenceFile EvidenceFile { get; set; } = null!;
    }
}