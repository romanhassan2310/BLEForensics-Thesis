using BLEForensics.Data;
using BLEForensics.Models;
using BLEForensics.ViewModels;
using BLEForensics.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text.Json;

namespace BLEForensics.Controllers
{
    public class EvidenceController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _environment;
        private readonly PythonAnalysisService _pythonService;

        public EvidenceController(
            ApplicationDbContext context,
            IWebHostEnvironment environment,
            PythonAnalysisService pythonService)
        {
            _context = context;
            _environment = environment;
            _pythonService = pythonService;
        }

        // =========================================================
        // GET: Evidence/Upload
        // =========================================================

        [HttpGet]
        public IActionResult Upload()
        {
            return View();
        }

        // =========================================================
        // GET: Evidence/List
        // =========================================================

        public IActionResult List()
        {
            var evidenceFiles = _context.EvidenceFiles
                .OrderByDescending(x => x.UploadDate)
                .Select(x => new EvidenceListViewModel
                {
                    Id = x.Id,
                    FileName = x.FileName,
                    SHA256Hash = x.SHA256Hash,
                    UploadDate = x.UploadDate
                })
                .ToList();

            return View(evidenceFiles);
        }

        // =========================================================
        // GET: Evidence/Details/5
        // =========================================================

        public IActionResult Details(int id)
        {
            var evidence = _context.EvidenceFiles
                .FirstOrDefault(x => x.Id == id);

            if (evidence == null)
            {
                return NotFound();
            }

            var analysisSession = _context.AnalysisSessions
                .FirstOrDefault(x => x.EvidenceFileId == id);

            var attackEvents = _context.AttackEvents
                .Where(x => x.EvidenceFileId == id)
                .OrderBy(x => x.Timestamp)
                .ThenBy(x => x.PacketNumber)
                .ToList();

            var bluetoothDevices = _context.BluetoothDevices
                .Where(x => x.EvidenceFileId == id)
                .OrderBy(x => x.MacAddress)
                .ToList();

            var protocolStatistics =
                _context.BluetoothProtocolStatistics
                    .FirstOrDefault(x => x.EvidenceFileId == id);

            var layerFrequency =
                new Dictionary<string, int>();

            if (protocolStatistics != null &&
                !string.IsNullOrWhiteSpace(
                    protocolStatistics.LayerFrequencyJson))
            {
                try
                {
                    layerFrequency =
                        JsonSerializer.Deserialize<
                            Dictionary<string, int>
                        >(
                            protocolStatistics.LayerFrequencyJson
                        )
                        ?? new Dictionary<string, int>();
                }
                catch
                {
                    layerFrequency =
                        new Dictionary<string, int>();
                }
            }

            var communications =
                _context.BluetoothCommunications
                    .Where(x => x.EvidenceFileId == id)
                    .OrderByDescending(x => x.Count)
                    .ToList();

            var suspiciousPackets =
                _context.SuspiciousPackets
                    .Where(x => x.EvidenceFileId == id)
                    .OrderBy(x => x.PacketNumber)
                    .ToList();

            var model = new EvidenceDetailsViewModel
            {
                Evidence = evidence,
                AnalysisSession = analysisSession,
                AttackEvents = attackEvents,
                BluetoothDevices = bluetoothDevices,
                ProtocolStatistics = protocolStatistics,
                Communications = communications,
                LayerFrequency = layerFrequency,
                SuspiciousPackets = suspiciousPackets,
                CorrelatedPacketCount = suspiciousPackets.Count,
                CorrelatedDeviceCount = bluetoothDevices.Count,
                CorrelatedCommunicationCount = communications.Count,
                CorrelatedEventCount = attackEvents.Count,
                CorrelatedProtocols = suspiciousPackets
                    .Where(x => !string.IsNullOrWhiteSpace(x.Protocol))
                    .Select(x => x.Protocol)
                    .Distinct()
                    .OrderBy(x => x)
                    .ToList()
            };

            return View(model);
        }

        // =========================================================
        // POST: Evidence/Upload
        // =========================================================

        [HttpPost]
        public async Task<IActionResult> Upload(
            EvidenceUploadViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var evidenceFolder = Path.Combine(
                _environment.ContentRootPath,
                "Evidence");

            if (!Directory.Exists(evidenceFolder))
            {
                Directory.CreateDirectory(evidenceFolder);
            }

            var fileName =
                Guid.NewGuid() + "_" +
                model.EvidenceFile.FileName;

            var filePath = Path.Combine(
                evidenceFolder,
                fileName);

            using (var stream = new FileStream(
                filePath,
                FileMode.Create))
            {
                await model.EvidenceFile.CopyToAsync(stream);
            }

            string hash;

            using (var sha256 = SHA256.Create())
            using (var stream =
                    System.IO.File.OpenRead(filePath))
            {
                var hashBytes =
                    sha256.ComputeHash(stream);

                hash =
                    Convert.ToHexString(hashBytes);
            }

            var evidence = new EvidenceFile
            {
                FileName =
                    model.EvidenceFile.FileName,

                FilePath =
                    filePath,

                SHA256Hash =
                    hash,

                UploadDate =
                    DateTime.UtcNow
            };

            _context.EvidenceFiles.Add(evidence);

            // ১. সবার আগে EvidenceFile সেভ করুন যাতে সুনির্দিষ্ট ID জেনারেট হয়
            await _context.SaveChangesAsync();

            // ২. Python Analysis সার্ভিসে evidence.Id পাস করুন
            await _pythonService.AnalyzeAsync(filePath, evidence.Id);

            TempData["Success"] =
                "Evidence uploaded and analyzed successfully.";

            return RedirectToAction(
                nameof(Upload));
        }
    }
}