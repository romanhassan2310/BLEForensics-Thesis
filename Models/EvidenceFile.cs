namespace BLEForensics.Models
{
    public class EvidenceFile
    {
        public int Id { get; set; }

        public string FileName { get; set; } = string.Empty;

        public string FilePath { get; set; } = string.Empty;

        public string SHA256Hash { get; set; } = string.Empty;

        public DateTime UploadDate { get; set; }
    }
}