using BLEForensics.Services;
using Microsoft.AspNetCore.Mvc;

namespace BLEForensics.Controllers
{
    public class AnalysisController : Controller
    {
        private readonly PythonAnalysisService _pythonService;

        public AnalysisController(
            PythonAnalysisService pythonService)
        {
            _pythonService = pythonService;
        }

        public async Task<IActionResult> Test()
        {
            var pcapFile =
                Path.Combine(
                    Directory.GetCurrentDirectory(),
                    "Evidence",
                    "test.pcapng");

            var result =
                await _pythonService.AnalyzeAsync(pcapFile);

            return Content(
                result,
                "application/json");
        }
    }
}