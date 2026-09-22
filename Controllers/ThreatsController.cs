using BLEForensics.Data;
using Microsoft.AspNetCore.Mvc;

namespace BLEForensics.Controllers
{
    public class ThreatsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public ThreatsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // =========================================================
        // GET: Threats
        // =========================================================

        public IActionResult Index(
            string? severity,
            string? attackType)
        {
            var query = _context.AttackEvents
                .AsQueryable();

            // =====================================================
            // Severity Filter
            // =====================================================

            if (!string.IsNullOrWhiteSpace(severity))
            {
                query = query.Where(
                    x => x.Severity == severity);
            }

            // =====================================================
            // Attack Type Filter
            // =====================================================

            if (!string.IsNullOrWhiteSpace(attackType))
            {
                query = query.Where(
                    x => x.AttackType == attackType);
            }

            // =====================================================
            // Threat List
            // =====================================================

            var threats = query
                .OrderByDescending(x => x.Timestamp)
                .ToList();

            // =====================================================
            // Filter Options
            // =====================================================

            ViewBag.Severities = _context.AttackEvents
                .Where(x => !string.IsNullOrWhiteSpace(x.Severity))
                .Select(x => x.Severity)
                .Distinct()
                .OrderBy(x => x)
                .ToList();

            ViewBag.AttackTypes = _context.AttackEvents
                .Where(x => !string.IsNullOrWhiteSpace(x.AttackType))
                .Select(x => x.AttackType)
                .Distinct()
                .OrderBy(x => x)
                .ToList();

            // =====================================================
            // Current Filters
            // =====================================================

            ViewBag.SelectedSeverity = severity;
            ViewBag.SelectedAttackType = attackType;

            // =====================================================
            // Statistics
            // =====================================================

            ViewBag.TotalThreats =
                _context.AttackEvents.Count();

            ViewBag.HighThreats =
                _context.AttackEvents.Count(
                    x => x.Severity == "High");

            ViewBag.MediumThreats =
                _context.AttackEvents.Count(
                    x => x.Severity == "Medium");

            ViewBag.LowThreats =
                _context.AttackEvents.Count(
                    x => x.Severity == "Low");

            return View(threats);
        }
    }
}