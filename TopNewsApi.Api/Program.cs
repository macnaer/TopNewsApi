using TopNewsApi.Infrastructure;
using TopNewsApi.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TopNewsApi.Infrastructure.Initializers;

var builder = WebApplication.CreateBuilder(args);


// Create JWT Token Configuration
var key = Encoding.UTF8.GetBytes(builder.Configuration["JwtConfig:Secret"]);
var tokenValidationParemeters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero,
    ValidIssuer = builder.Configuration["JwtConfig:Issuer"],
    ValidAudience = builder.Configuration["JwtConfig:Audience"]
};

builder.Services.AddSingleton(tokenValidationParemeters);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(jwt =>
{
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParemeters;
    jwt.RequireHttpsMetadata = false;
});

// Create connection sting
string connStr = builder.Configuration.GetConnectionString("DefaultConnection");


// Database context
builder.Services.AddDbContext(connStr);

// Add Core services
builder.Services.AddCoreServices();

// Add Infrastructure Service
builder.Services.AddInfrastructureService();

// Add Repositories
builder.Services.AddRepositories();

// Add Mapping
builder.Services.AddMapping();

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();


await UsersAndRolesInitializer.SeedUsersAndRoles(app);

app.Run();
