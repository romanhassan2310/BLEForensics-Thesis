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

            // =====================================================
            // Analysis Session
            // =====================================================

            var analysisSession = _context.AnalysisSessions
                .FirstOrDefault(x => x.EvidenceFileId == id);

            // =====================================================
            // Attack Events
            // =====================================================

            var attackEvents = _context.AttackEvents
                .Where(x => x.EvidenceFileId == id)
                .OrderBy(x => x.Timestamp)
                .ThenBy(x => x.PacketNumber)
                .ToList();

            // =====================================================
            // Bluetooth Devices
            // =====================================================

            var bluetoothDevices = _context.BluetoothDevices
                .Where(x => x.EvidenceFileId == id)
                .OrderBy(x => x.MacAddress)
                .ToList();

            // =====================================================
            // Bluetooth Protocol Statistics
            // =====================================================

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

            // =====================================================
            // Bluetooth Communications
            // =====================================================

            var communications =
                _context.BluetoothCommunications
                    .Where(x => x.EvidenceFileId == id)
                    .OrderByDescending(x => x.Count)
                    .ToList();

            // =====================================================
            // Suspicious Packets
            // =====================================================

            var suspiciousPackets =
                _context.SuspiciousPackets
                    .Where(x => x.EvidenceFileId == id)
                    .OrderBy(x => x.PacketNumber)
                    .ToList();

            // =====================================================
            // Evidence Correlation
            // =====================================================

            var correlatedPacketCount =
                suspiciousPackets.Count;

            var correlatedDeviceCount =
                bluetoothDevices.Count;

            var correlatedCommunicationCount =
                communications.Count;

            var correlatedEventCount =
                attackEvents.Count;

            var correlatedProtocols =
                suspiciousPackets
                    .Where(x => !string.IsNullOrWhiteSpace(x.Protocol))
                    .Select(x => x.Protocol)
                    .Distinct()
                    .OrderBy(x => x)
                    .ToList();

            // =====================================================
            // Create ViewModel
            // =====================================================

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

                // =====================================================
                // Evidence Correlation
                // =====================================================

                CorrelatedPacketCount = correlatedPacketCount,

                CorrelatedDeviceCount = correlatedDeviceCount,

                CorrelatedCommunicationCount = correlatedCommunicationCount,

                CorrelatedEventCount = correlatedEventCount,

                CorrelatedProtocols = correlatedProtocols
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

            // =====================================================
            // 1. Create Evidence folder
            // =====================================================

            var evidenceFolder = Path.Combine(
                _environment.ContentRootPath,
                "Evidence");

            if (!Directory.Exists(evidenceFolder))
            {
                Directory.CreateDirectory(evidenceFolder);
            }

            // =====================================================
            // 2. Generate unique file name
            // =====================================================

            var fileName =
                Guid.NewGuid() + "_" +
                model.EvidenceFile.FileName;

            var filePath = Path.Combine(
                evidenceFolder,
                fileName);

            // =====================================================
            // 3. Save uploaded PCAP file
            // =====================================================

            using (var stream = new FileStream(
                filePath,
                FileMode.Create))
            {
                await model.EvidenceFile.CopyToAsync(stream);
            }

            // =====================================================
            // 4. Calculate SHA-256 hash
            // =====================================================

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

            // =====================================================
            // 5. Create EvidenceFile
            //
            // UploadDate represents the actual system upload time.
            // It is NOT a PCAP packet timestamp.
            // =====================================================

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

            // Save first so EvidenceFile.Id is generated
            await _context.SaveChangesAsync();

            // =====================================================
            // 6. Run Python / PyShark analysis
            // =====================================================

            var jsonResult =
                await _pythonService.AnalyzeAsync(
                    filePath);

            var analysis =
                JsonSerializer.Deserialize<AnalysisResult>(
                    jsonResult,
                    new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

            // =====================================================
            // 7. Save analysis results
            // =====================================================

            if (analysis != null)
            {
                // =================================================
                // 7.1 Analysis Session
                // =================================================

                var analysisSession =
                    new AnalysisSession
                    {
                        EvidenceFileId =
                            evidence.Id,

                        TotalPackets =
                            analysis.TotalPackets,

                        SuspiciousEventCount =
                            analysis.SuspiciousEvents.Count,

                        // System analysis time.
                        // This is intentionally different from
                        // the PCAP capture timestamps.
                        AnalysisDate =
                            DateTime.UtcNow,

                        // Original PCAP timeline
                        CaptureStartTime =
                            analysis.CaptureStartTime,

                        CaptureEndTime =
                            analysis.CaptureEndTime
                    };

                _context.AnalysisSessions.Add(
                    analysisSession);

                // =================================================
                // 7.2 Bluetooth Devices
                // =================================================

                foreach (var deviceAddress
                    in analysis.Devices)
                {
                    if (string.IsNullOrWhiteSpace(
                        deviceAddress))
                    {
                        continue;
                    }

                    var deviceExists =
                        _context.BluetoothDevices.Any(
                            x =>
                                x.MacAddress ==
                                    deviceAddress
                                &&
                                x.EvidenceFileId ==
                                    evidence.Id);

                    if (!deviceExists)
                    {
                        _context.BluetoothDevices.Add(
                            new BluetoothDevice
                            {
                                MacAddress =
                                    deviceAddress,

                                DeviceName =
                                    "Unknown",

                                EvidenceFileId =
                                    evidence.Id
                            });
                    }
                }

                // =================================================
                // 7.3 Bluetooth Protocol Statistics
                // =================================================

                var protocolStatistics =
                    new BluetoothProtocolStatistic
                    {
                        HCICommandCount =
                            analysis.Protocols.TryGetValue(
                                "HCI_Command",
                                out var hciCommand)
                                ? hciCommand
                                : 0,

                        HCIEventCount =
                            analysis.Protocols.TryGetValue(
                                "HCI_Event",
                                out var hciEvent)
                                ? hciEvent
                                : 0,

                        HCIACLCount =
                            analysis.Protocols.TryGetValue(
                                "HCI_ACL",
                                out var hciAcl)
                                ? hciAcl
                                : 0,

                        L2CAPCount =
                            analysis.Protocols.TryGetValue(
                                "L2CAP",
                                out var l2cap)
                                ? l2cap
                                : 0,

                        RFCOMMCount =
                            analysis.Protocols.TryGetValue(
                                "RFCOMM",
                                out var rfcomm)
                                ? rfcomm
                                : 0,

                        OBEXCount =
                            analysis.Protocols.TryGetValue(
                                "OBEX",
                                out var obex)
                                ? obex
                                : 0,

                        SDPCount =
                            analysis.Protocols.TryGetValue(
                                "SDP",
                                out var sdp)
                                ? sdp
                                : 0,

                        LayerFrequencyJson =
                            JsonSerializer.Serialize(
                                analysis.LayerFrequency),

                        EvidenceFileId =
                            evidence.Id
                    };

                _context.BluetoothProtocolStatistics.Add(
                    protocolStatistics);

                // =================================================
                // 7.4 Bluetooth Communications
                // =================================================

                foreach (var communication
                    in analysis.Communications)
                {
                    if (
                        string.IsNullOrWhiteSpace(
                            communication.Source)
                        ||
                        string.IsNullOrWhiteSpace(
                            communication.Destination))
                    {
                        continue;
                    }

                    _context.BluetoothCommunications.Add(
                        new BluetoothCommunication
                        {
                            Source =
                                communication.Source,

                            Destination =
                                communication.Destination,

                            Count =
                                communication.Count,

                            EvidenceFileId =
                                evidence.Id
                        });
                }

                // =================================================
                // 7.5 Suspicious / Attack Events
                //
                // IMPORTANT:
                // Timestamp comes directly from the PCAP.
                // No DateTime.UtcNow is used here.
                // =================================================

                foreach (var evt
                    in analysis.SuspiciousEvents)
                {
                    _context.AttackEvents.Add(
                        new AttackEvent
                        {
                            AttackType = evt.AttackType,

                            Severity = evt.Severity,

                            Source = evt.Source,

                            Destination = evt.Destination,

                            Description = evt.Description,

                            Timestamp = evt.Timestamp,

                            PacketNumber = evt.PacketNumber,

                            EndTimestamp = evt.EndTimestamp,

                            EndPacketNumber = evt.EndPacketNumber,

                            EvidenceFileId = evidence.Id
                        });
                }

                // =================================================
                // 7.6 Suspicious Packets
                //
                // Timestamp is the original PCAP packet time.
                // =================================================

                foreach (var packet
                    in analysis.SuspiciousPackets)
                {
                    _context.SuspiciousPackets.Add(
                        new SuspiciousPacket
                        {
                            PacketNumber =
                                packet.PacketNumber,

                            Timestamp =
                                packet.Timestamp,

                            Protocol =
                                packet.Protocol,

                            Source =
                                packet.Source,

                            Destination =
                                packet.Destination,

                            PacketLength =
                                packet.PacketLength,

                            Severity =
                                packet.Severity,

                            Reason =
                                packet.Reason,

                            EvidenceFileId =
                                evidence.Id
                        });
                }

                // =================================================
                // 7.7 Save all analysis data
                // =================================================

                await _context.SaveChangesAsync();
            }

            // =====================================================
            // 8. Success message
            // =====================================================

            TempData["Success"] =
                "Evidence uploaded and analyzed successfully.";

            return RedirectToAction(
                nameof(Upload));
        }
    }
}