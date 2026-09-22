using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddForensicEventTimestamp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PacketNumber",
                table: "AttackEvents",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PacketNumber",
                table: "AttackEvents");
        }
    }
}
