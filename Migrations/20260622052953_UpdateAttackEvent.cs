using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BLEForensics.Migrations
{
    /// <inheritdoc />
    public partial class UpdateAttackEvent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PacketLogs_Devices_DeviceId",
                table: "PacketLogs");

            migrationBuilder.RenameColumn(
                name: "PayloadLength",
                table: "PacketLogs",
                newName: "PacketLength");

            migrationBuilder.RenameColumn(
                name: "PacketType",
                table: "PacketLogs",
                newName: "Summary");

            migrationBuilder.AlterColumn<int>(
                name: "DeviceId",
                table: "PacketLogs",
                type: "int",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AddColumn<string>(
                name: "Destination",
                table: "PacketLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Protocol",
                table: "PacketLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "PacketLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Destination",
                table: "AttackEvents",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "EvidenceFileId",
                table: "AttackEvents",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "AttackEvents",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_AttackEvents_EvidenceFileId",
                table: "AttackEvents",
                column: "EvidenceFileId");

            migrationBuilder.AddForeignKey(
                name: "FK_AttackEvents_EvidenceFiles_EvidenceFileId",
                table: "AttackEvents",
                column: "EvidenceFileId",
                principalTable: "EvidenceFiles",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_PacketLogs_Devices_DeviceId",
                table: "PacketLogs",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AttackEvents_EvidenceFiles_EvidenceFileId",
                table: "AttackEvents");

            migrationBuilder.DropForeignKey(
                name: "FK_PacketLogs_Devices_DeviceId",
                table: "PacketLogs");

            migrationBuilder.DropIndex(
                name: "IX_AttackEvents_EvidenceFileId",
                table: "AttackEvents");

            migrationBuilder.DropColumn(
                name: "Destination",
                table: "PacketLogs");

            migrationBuilder.DropColumn(
                name: "Protocol",
                table: "PacketLogs");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "PacketLogs");

            migrationBuilder.DropColumn(
                name: "Destination",
                table: "AttackEvents");

            migrationBuilder.DropColumn(
                name: "EvidenceFileId",
                table: "AttackEvents");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "AttackEvents");

            migrationBuilder.RenameColumn(
                name: "Summary",
                table: "PacketLogs",
                newName: "PacketType");

            migrationBuilder.RenameColumn(
                name: "PacketLength",
                table: "PacketLogs",
                newName: "PayloadLength");

            migrationBuilder.AlterColumn<int>(
                name: "DeviceId",
                table: "PacketLogs",
                type: "int",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "int",
                oldNullable: true);

            migrationBuilder.AddForeignKey(
                name: "FK_PacketLogs_Devices_DeviceId",
                table: "PacketLogs",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
