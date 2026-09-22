using BLEForensics.Data;
using Microsoft.AspNetCore.Mvc;

namespace BLEForensics.Controllers
{
    public class DashboardController : Controller
    {
        private readonly ApplicationDbContext _context;

        public DashboardController(ApplicationDbContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            // =========================================================
            // Summary Statistics
            // =========================================================

            ViewBag.TotalEvidence =
                _context.EvidenceFiles.Count();

            ViewBag.TotalSessions =
                _context.AnalysisSessions.Count();

            ViewBag.TotalPackets =
                _context.AnalysisSessions.Any()
                    ? _context.AnalysisSessions.Sum(x => x.TotalPackets)
                    : 0;

            ViewBag.TotalBluetoothDevices =
                _context.BluetoothDevices.Count();


            // =========================================================
            // Threat Statistics
            // =========================================================

            ViewBag.TotalThreats =
                _context.AttackEvents.Count();

            ViewBag.HighSeverity =
                _context.AttackEvents.Count(
                    x => x.Severity == "High"
                );

            ViewBag.MediumSeverity =
                _context.AttackEvents.Count(
                    x => x.Severity == "Medium"
                );

            ViewBag.LowSeverity =
                _context.AttackEvents.Count(
                    x => x.Severity == "Low"
                );


            // =========================================================
            // Threat Type Distribution
            // =========================================================

            var threatTypeData =
                _context.AttackEvents
                    .GroupBy(x => x.AttackType)
                    .Select(g => new
                    {
                        AttackType = g.Key,
                        Count = g.Count()
                    })
                    .OrderByDescending(x => x.Count)
                    .ToList();

            ViewBag.ThreatTypeLabels =
                threatTypeData
                    .Select(x => x.AttackType)
                    .ToList();

            ViewBag.ThreatTypeCounts =
                threatTypeData
                    .Select(x => x.Count)
                    .ToList();


            // =========================================================
            // Recent Threats
            // =========================================================

            ViewBag.RecentThreats =
                _context.AttackEvents
                    .OrderByDescending(x => x.Timestamp)
                    .Take(10)
                    .ToList();


            // =========================================================
            // Recent Evidence
            // =========================================================

            ViewBag.RecentEvidence =
                _context.EvidenceFiles
                    .OrderByDescending(x => x.UploadDate)
                    .Take(10)
                    .ToList();


            // =========================================================
            // Bluetooth Protocol Statistics
            // =========================================================

            var protocolStats =
                _context.BluetoothProtocolStatistics
                    .ToList();

            ViewBag.HCICommands =
                protocolStats.Sum(x => x.HCICommandCount);

            ViewBag.HCIEvents =
                protocolStats.Sum(x => x.HCIEventCount);

            ViewBag.HCIACL =
                protocolStats.Sum(x => x.HCIACLCount);

            ViewBag.L2CAP =
                protocolStats.Sum(x => x.L2CAPCount);

            ViewBag.RFCOMM =
                protocolStats.Sum(x => x.RFCOMMCount);

            ViewBag.OBEX =
                protocolStats.Sum(x => x.OBEXCount);

            ViewBag.SDP =
                protocolStats.Sum(x => x.SDPCount);


            return View();
        }
    }
}