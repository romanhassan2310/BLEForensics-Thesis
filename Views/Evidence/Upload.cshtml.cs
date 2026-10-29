using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.IO;

namespace BLEForensics.Views.Evidence
{
    public class UploadModel : PageModel
    {
        private readonly IWebHostEnvironment _env;

        public UploadModel(IWebHostEnvironment env)
        {
            _env = env;
        }

        [BindProperty]
        public IFormFile UploadedFile { get; set; }

        public string Message { get; set; }
        public string PythonOutput { get; set; }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (UploadedFile == null || UploadedFile.Length == 0)
            {
                Message = "দয়া করে একটি বৈধ ফাইল সিলেক্ট করুন।";
                return Page();
            }

            // ১. প্রজেক্টের ভেতরে uploads ফোল্ডারে ফাইল সেভ করা
            string uploadsFolder = Path.Combine(_env.WebRootPath ?? _env.ContentRootPath, "uploads");
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            string filePath = Path.Combine(uploadsFolder, UploadedFile.FileName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await UploadedFile.CopyToAsync(fileStream);
            }

            // ২. পাইথন অ্যানালাইজার স্ক্রিপ্ট রান করা
            string pythonScriptPath = Path.Combine(_env.ContentRootPath, "Python", "analyzer.py");

            var psi = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = $"\"{pythonScriptPath}\" \"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                PythonOutput = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrEmpty(error))
                {
                    Message = $"Python Error: {error}";
                    return Page();
                }
            }

            Message = "ফাইল সফলভাবে আপলোড এবং অ্যানালাইজ হয়েছে!";
            return Page();
        }
    }
}