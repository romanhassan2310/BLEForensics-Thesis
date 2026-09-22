using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace BLEForensics.ViewModels
{
    public class EvidenceUploadViewModel
    {
        [Required]
        public IFormFile EvidenceFile { get; set; } = null!;
    }
}