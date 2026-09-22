using BLEForensics.Models;

namespace BLEForensics.ViewModels
{
    public class EvidenceDetailsViewModel
    {
        public EvidenceFile Evidence { get; set; } = null!;

        public AnalysisSession? AnalysisSession { get; set; }

        public List<AttackEvent> AttackEvents { get; set; }
            = new();

        public List<BluetoothDevice> BluetoothDevices { get; set; }
            = new();

        public BluetoothProtocolStatistic? ProtocolStatistics
        {
            get;
            set;
        }

        public List<BluetoothCommunication> Communications
        {
            get;
            set;
        } = new();

        public Dictionary<string, int> LayerFrequency { get; set; }
            = new();

        public List<SuspiciousPacket> SuspiciousPackets { get; set; } = new();

        // =========================================================
        // Evidence Correlation
        // =========================================================

        public int CorrelatedPacketCount { get; set; }

        public int CorrelatedDeviceCount { get; set; }

        public int CorrelatedCommunicationCount { get; set; }

        public int CorrelatedEventCount { get; set; }

        public List<string> CorrelatedProtocols { get; set; }
            = new();
    }
}