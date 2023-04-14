using Identity.Models;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.DataAccess.Migrations
{
    
    public partial class AddRoles : Migration
    {
    
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Crear roles por defecto
            var roles = Enum.GetNames(typeof(Roles)); 

            foreach (var roleName in roles)
            {
                migrationBuilder.InsertData(
                    table: "AspNetRoles",
                    columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
                    values: new object[] { Guid.NewGuid().ToString(), roleName, roleName.ToUpper(), Guid.NewGuid().ToString() });
            }
        }

      
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            
            var roles = Enum.GetNames(typeof(Roles)); 

            foreach (var roleName in roles)
            {
                migrationBuilder.DeleteData(
                    table: "AspNetRoles",
                    keyColumn: "Name",
                    keyValue: roleName);
            }
        }
    }
}
