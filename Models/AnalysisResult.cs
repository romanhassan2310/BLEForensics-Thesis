namespace BLEForensics.Models
{
    public class AnalysisResult
    {
        public string CaptureType { get; set; } = string.Empty;

        public int TotalPackets { get; set; }

        public Dictionary<string, int> Protocols { get; set; } = new();

        public List<string> Devices { get; set; } = new();

        public List<BluetoothCommunication> Communications { get; set; } = new();
        public Dictionary<string, int> LayerFrequency { get; set; } = new();
        public List<SuspiciousPacketResult> SuspiciousPackets { get; set; }
    = new();
        public List<SuspiciousEvent> SuspiciousEvents { get; set; }
            = new();

        public DateTime? CaptureStartTime { get; set; }
        public DateTime? CaptureEndTime { get; set; }
    }
}