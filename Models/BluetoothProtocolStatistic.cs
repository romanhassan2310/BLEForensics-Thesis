namespace BLEForensics.Models
{
    public class BluetoothProtocolStatistic
    {
        public int Id { get; set; }

        public int HCICommandCount { get; set; }

        public int HCIEventCount { get; set; }

        public int HCIACLCount { get; set; }

        public int L2CAPCount { get; set; }

        public int RFCOMMCount { get; set; }

        public int OBEXCount { get; set; }

        public int SDPCount { get; set; }
        public string LayerFrequencyJson { get; set; } = "{}";

        public int EvidenceFileId { get; set; }

        public EvidenceFile EvidenceFile { get; set; } = null!;
    }

}