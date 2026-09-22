using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddForensicTimelineData : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "CaptureEndTime",
                table: "AnalysisSessions",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CaptureStartTime",
                table: "AnalysisSessions",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CaptureEndTime",
                table: "AnalysisSessions");

            migrationBuilder.DropColumn(
                name: "CaptureStartTime",
                table: "AnalysisSessions");
        }
    }
}
