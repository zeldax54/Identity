using Identity.Bussiness;
using Identity.DataAccess.Contexts;
using Identity.Models;
using Identity.TokenHandler;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSelfOrigins", c =>
    {
        c.WithOrigins(builder.Configuration["AdminAppOrigin"]);
        c.AllowAnyHeader();
        c.AllowAnyMethod();
        c.AllowCredentials();
    });
});

// Add services to the container.

var keySecret = builder.Configuration["JwtSigningKey"];
var symmetricKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keySecret));

builder.Services.AddTransient<IJwtSignInHandler>(provider => {
    return new JwtSignInHandler(symmetricKey, provider.GetRequiredService<IConfiguration>());
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
    options.TokenValidationParameters.IssuerSigningKey = symmetricKey;
    options.TokenValidationParameters.ValidAudiences = builder.Configuration["ValidTokenAudiences"].Split(',').ToList();
    options.TokenValidationParameters.ValidIssuer = builder.Configuration["TokenIssuer"];
});

builder.Services.AddAuthorization(auth =>
{
    auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser().Build());  
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddDbContext<ApplicationDBContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("IdentityDB")));
/*Identity*/
builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDBContext>().AddDefaultTokenProviders();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<IIdentityUserManager, IdentityUserManager>();

var app = builder.Build();
/*Migration*/
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetService<ApplicationDBContext>();
#pragma warning disable CS8602 // Dereference of a possibly null reference.
    dbContext.Database.Migrate();
#pragma warning restore CS8602 // Dereference of a possibly null reference.
}
/*Migration End*/

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors("AllowSelfOrigins");

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
