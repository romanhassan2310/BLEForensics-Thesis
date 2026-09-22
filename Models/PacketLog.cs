namespace BLEForensics.Models
{
    public class PacketLog
    {
        public int Id { get; set; }

        public DateTime Timestamp { get; set; }

        public string Protocol { get; set; } = string.Empty;

        public string Source { get; set; } = string.Empty;

        public string Destination { get; set; } = string.Empty;

        public int PacketLength { get; set; }

        public string Summary { get; set; } = string.Empty;
    }
}