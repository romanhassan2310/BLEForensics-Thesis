using BLEForensics.Models;
using Microsoft.EntityFrameworkCore;

namespace BLEForensics.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(
            DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<EvidenceFile> EvidenceFiles
            => Set<EvidenceFile>();

        public DbSet<Device> Devices
            => Set<Device>();

        public DbSet<PacketLog> PacketLogs
            => Set<PacketLog>();

        public DbSet<AttackEvent> AttackEvents
            => Set<AttackEvent>();

        public DbSet<AnalysisSession> AnalysisSessions
            => Set<AnalysisSession>();

        public DbSet<BluetoothDevice> BluetoothDevices
            => Set<BluetoothDevice>();

        public DbSet<BluetoothProtocolStatistic> BluetoothProtocolStatistics
            => Set<BluetoothProtocolStatistic>();

        public DbSet<SuspiciousPacket> SuspiciousPackets
    => Set<SuspiciousPacket>();
        public DbSet<BluetoothCommunication> BluetoothCommunications
            => Set<BluetoothCommunication>();

        protected override void OnModelCreating(
            ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<BluetoothCommunication>()
                .HasOne(x => x.EvidenceFile)
                .WithMany()
                .HasForeignKey(x => x.EvidenceFileId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}