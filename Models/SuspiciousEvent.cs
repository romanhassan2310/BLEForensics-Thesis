namespace BLEForensics.Models
{
    public class SuspiciousEvent
    {
        public string AttackType { get; set; } = string.Empty;

        public string Severity { get; set; } = string.Empty;

        public string Source { get; set; } = string.Empty;

        public string Destination { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public int PacketNumber { get; set; }
        public DateTime? EndTimestamp { get; set; }
        public int? EndPacketNumber { get; set; }
    }
}
