using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddLayerFrequency : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "LayerFrequencyJson",
                table: "BluetoothProtocolStatistics",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LayerFrequencyJson",
                table: "BluetoothProtocolStatistics");
        }
    }
}
