using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddAnalysisSession : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AnalysisSessions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EvidenceFileId = table.Column<int>(type: "int", nullable: false),
                    TotalPackets = table.Column<int>(type: "int", nullable: false),
                    SuspiciousEventCount = table.Column<int>(type: "int", nullable: false),
                    AnalysisDate = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnalysisSessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AnalysisSessions_EvidenceFiles_EvidenceFileId",
                        column: x => x.EvidenceFileId,
                        principalTable: "EvidenceFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AnalysisSessions_EvidenceFileId",
                table: "AnalysisSessions",
                column: "EvidenceFileId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AnalysisSessions");
        }
    }
}
