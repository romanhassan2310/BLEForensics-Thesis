using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class AddBluetoothProtocolStatistics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BluetoothProtocolStatistics",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HCICommandCount = table.Column<int>(type: "int", nullable: false),
                    HCIEventCount = table.Column<int>(type: "int", nullable: false),
                    HCIACLCount = table.Column<int>(type: "int", nullable: false),
                    L2CAPCount = table.Column<int>(type: "int", nullable: false),
                    RFCOMMCount = table.Column<int>(type: "int", nullable: false),
                    OBEXCount = table.Column<int>(type: "int", nullable: false),
                    SDPCount = table.Column<int>(type: "int", nullable: false),
                    EvidenceFileId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BluetoothProtocolStatistics", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BluetoothProtocolStatistics_EvidenceFiles_EvidenceFileId",
                        column: x => x.EvidenceFileId,
                        principalTable: "EvidenceFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BluetoothProtocolStatistics_EvidenceFileId",
                table: "BluetoothProtocolStatistics",
                column: "EvidenceFileId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BluetoothProtocolStatistics");
        }
    }
}
