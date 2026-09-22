namespace BLEForensics.Models
{
    public class Device
    {
        public int Id { get; set; }

        public string MacAddress { get; set; } = string.Empty;

        public string DeviceName { get; set; } = string.Empty;

        public ICollection<PacketLog>? PacketLogs { get; set; }
    }
}