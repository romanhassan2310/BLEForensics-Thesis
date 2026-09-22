namespace BLEForensics.Models
{
    public class AnalysisSession
    {
        public int Id { get; set; }

        public int EvidenceFileId { get; set; }

        public int TotalPackets { get; set; }

        public int SuspiciousEventCount { get; set; }

        public DateTime AnalysisDate { get; set; }

        public EvidenceFile? EvidenceFile { get; set; }
        public DateTime? CaptureStartTime { get; set; }
        public DateTime? CaptureEndTime { get; set; }
    }
}