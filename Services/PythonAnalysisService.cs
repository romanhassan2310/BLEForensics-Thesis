using System.Diagnostics;
using System.Text.Json;
using BLEForensics.Data;
using BLEForensics.Models;
using Microsoft.AspNetCore.Hosting;

namespace BLEForensics.Services
{
    public class PythonAnalysisService
    {
        private readonly IWebHostEnvironment _environment;
        private readonly ApplicationDbContext _context;

        public PythonAnalysisService(IWebHostEnvironment environment, ApplicationDbContext context)
        {
            _environment = environment;
            _context = context;
        }

        public async Task<string> AnalyzeAsync(string pcapFilePath, int evidenceFileId = 0)
        {
            var pythonFile = Path.Combine(
                _environment.ContentRootPath,
                "Python",
                "analyzer.py");

            var process = new Process();
            process.StartInfo.FileName = "python";
            process.StartInfo.Arguments = $"\"{pythonFile}\" \"{pcapFilePath}\"";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();

            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            if (string.IsNullOrEmpty(error) && !string.IsNullOrEmpty(output))
            {
                try
                {
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    };

                    var analysis = JsonSerializer.Deserialize<AnalysisResult>(output, options);

                    if (analysis != null)
                    {
                        // ১. Analysis Session সেভ করা
                        var analysisSession = new AnalysisSession
                        {
                            EvidenceFileId = evidenceFileId,
                            TotalPackets = analysis.TotalPackets,
                            SuspiciousEventCount = analysis.SuspiciousEvents?.Count ?? 0,
                            AnalysisDate = DateTime.UtcNow,
                            CaptureStartTime = analysis.CaptureStartTime,
                            CaptureEndTime = analysis.CaptureEndTime
                        };
                        _context.AnalysisSessions.Add(analysisSession);

                        // ২. Bluetooth Devices সেভ করা
                        if (analysis.Devices != null)
                        {
                            foreach (var deviceAddress in analysis.Devices)
                            {
                                if (string.IsNullOrWhiteSpace(deviceAddress)) continue;

                                bool exists = _context.BluetoothDevices.Any(d => d.MacAddress == deviceAddress && d.EvidenceFileId == evidenceFileId);
                                if (!exists)
                                {
                                    _context.BluetoothDevices.Add(new BluetoothDevice
                                    {
                                        MacAddress = deviceAddress,
                                        DeviceName = "Unknown Device",
                                        EvidenceFileId = evidenceFileId
                                    });
                                }
                            }
                        }

                        // ৩. Protocol Statistics সেভ করা
                        var protocolStatistics = new BluetoothProtocolStatistic
                        {
                            HCICommandCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("HCI_Command", out var hciCommand) ? hciCommand : 0,
                            HCIEventCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("HCI_Event", out var hciEvent) ? hciEvent : 0,
                            HCIACLCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("HCI_ACL", out var hciAcl) ? hciAcl : 0,
                            L2CAPCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("L2CAP", out var l2cap) ? l2cap : 0,
                            RFCOMMCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("RFCOMM", out var rfcomm) ? rfcomm : 0,
                            OBEXCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("OBEX", out var obex) ? obex : 0,
                            SDPCount = analysis.Protocols != null && analysis.Protocols.TryGetValue("SDP", out var sdp) ? sdp : 0,
                            LayerFrequencyJson = analysis.LayerFrequency != null ? JsonSerializer.Serialize(analysis.LayerFrequency) : "{}",
                            EvidenceFileId = evidenceFileId
                        };
                        _context.BluetoothProtocolStatistics.Add(protocolStatistics);

                        // ৪. Communications সেভ করা
                        if (analysis.Communications != null)
                        {
                            foreach (var comm in analysis.Communications)
                            {
                                comm.EvidenceFileId = evidenceFileId;
                                _context.BluetoothCommunications.Add(comm);
                            }
                        }

                        

                        // ৬. Suspicious Packets সেভ করা
                           if (analysis.SuspiciousPackets != null)
                        {
                         foreach (var packet in analysis.SuspiciousPackets)
                        {
                              _context.SuspiciousPackets.Add(new SuspiciousPacket
                              {
                                     PacketNumber = packet.PacketNumber,
                                        Timestamp = packet.Timestamp,
                                      Protocol = packet.Protocol ?? string.Empty,
            Source = packet.Source ?? string.Empty,
                          Destination = packet.Destination ?? string.Empty,
            PacketLength = packet.PacketLength,
            Severity = packet.Severity ?? string.Empty,
            Reason = packet.Reason ?? string.Empty,
            EvidenceFileId = evidenceFileId
        });
    }
}

                        // ডেটাবেজে সম্পূর্ণ পরিবর্তনগুলো পার্মানেন্টলি সেভ করা
                        await _context.SaveChangesAsync();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"JSON Deserialization or DB Save Error: {ex.Message}");
                }
            }

            return output;
        }
    }
}