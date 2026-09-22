using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddAttackEventTimeline : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "EndPacketNumber",
                table: "AttackEvents",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "EndTimestamp",
                table: "AttackEvents",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EndPacketNumber",
                table: "AttackEvents");

            migrationBuilder.DropColumn(
                name: "EndTimestamp",
                table: "AttackEvents");
        }
    }
}
