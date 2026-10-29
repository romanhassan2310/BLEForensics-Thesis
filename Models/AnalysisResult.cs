using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using BLEForensics.Models;

namespace BLEForensics.Models
{
    public class AnalysisResult
    {
        [JsonPropertyName("devices")]
        public List<string>? Devices { get; set; }

        [JsonPropertyName("communications")]
        public List<BluetoothCommunication>? Communications { get; set; }

        [JsonPropertyName("total_packets")]
        public int TotalPackets { get; set; }

        [JsonPropertyName("suspicious_events")]
        public List<SuspiciousEventDto>? SuspiciousEvents { get; set; }

        [JsonPropertyName("capture_start_time")]
        public DateTime? CaptureStartTime { get; set; }

        [JsonPropertyName("capture_end_time")]
        public DateTime? CaptureEndTime { get; set; }

        [JsonPropertyName("protocols")]
        public Dictionary<string, int>? Protocols { get; set; }

        [JsonPropertyName("layer_frequency")]
        public Dictionary<string, int>? LayerFrequency { get; set; }

        [JsonPropertyName("suspicious_packets")]
        public List<SuspiciousPacketDto>? SuspiciousPackets { get; set; }
    }

    public class SuspiciousEventDto
    {
        [JsonPropertyName("attack_type")]
        public string? AttackType { get; set; }

        [JsonPropertyName("severity")]
        public string? Severity { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("destination")]
        public string? Destination { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        // কন্ট্রোলারের চাহিদা অনুযায়ী DateTime রাখা হলো
        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("packet_number")]
        public int PacketNumber { get; set; }

        [JsonPropertyName("end_timestamp")]
        public DateTime? EndTimestamp { get; set; }

        [JsonPropertyName("end_packet_number")]
        public int EndPacketNumber { get; set; }
    }

    public class SuspiciousPacketDto
    {
        [JsonPropertyName("packet_number")]
        public int PacketNumber { get; set; }

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("destination")]
        public string? Destination { get; set; }

        [JsonPropertyName("packet_length")]
        public int PacketLength { get; set; }

        [JsonPropertyName("severity")]
        public string? Severity { get; set; }

        [JsonPropertyName("reason")]
        public string? Reason { get; set; }
    }
}