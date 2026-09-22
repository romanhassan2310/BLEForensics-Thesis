using System.Diagnostics;

namespace BLEForensics.Services
{
    public class PythonAnalysisService
    {
        private readonly IWebHostEnvironment _environment;

        public PythonAnalysisService(IWebHostEnvironment environment)
        {
            _environment = environment;
        }

        public async Task<string> AnalyzeAsync(string pcapFilePath)
        {
            var pythonFile =
                Path.Combine(
                    _environment.ContentRootPath,
                    "Python",
                    "analyzer.py");

            var process = new Process();

            process.StartInfo.FileName = "python";

            process.StartInfo.Arguments =
                $"\"{pythonFile}\" \"{pcapFilePath}\"";

            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();

            string output =
                await process.StandardOutput.ReadToEndAsync();

            process.WaitForExit();

            return output;
        }
    }
}