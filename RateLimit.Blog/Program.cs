using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

var configuration = new ConfigurationBuilder()
    .AddJsonFile($"appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.Development.json", optional: false, reloadOnChange: true)
    .Build();
// Add services to the container
builder.Services.AddControllers();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Set TokenValidationParameters directly on options
        options.Authority = configuration["Authentication:ValidIssuer"];
        options.Audience = configuration["Authentication:Audience"];
        options.MetadataAddress = configuration["Authentication:MetadataUrl"];
        options.RequireHttpsMetadata = bool.Parse(configuration["Authentication:RequireHttpsMetadata"]);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["Authentication:ValidIssuer"],
            ValidAudience = configuration["Authentication:Audience"]
        };
        options.Events = new JwtBearerEvents()
        {
            OnTokenValidated = (context) =>
            {
                var userClaims = context.Principal?.Claims;
                var userNameClaim = userClaims?.FirstOrDefault(c => c.Type == "name")?.Value
                            ?? userClaims?.FirstOrDefault(c => c.Type == "sub")?.Value;

                if (context.Principal?.HasClaim(claim => claim.Type == "realm_access") == true)
                {
                    string? realmAccessClaimValue = context.Principal.Claims
                        .FirstOrDefault(claim => claim.Type == "realm_access")?.Value;

                    if (!string.IsNullOrEmpty(realmAccessClaimValue))
                    {
                        Dictionary<string, object>? values =
                            JsonConvert.DeserializeObject<Dictionary<string, object>>(realmAccessClaimValue);
                        if (values != null && values.TryGetValue("roles", out object? roles))
                        {
                            var rolesArray = JArray.FromObject(roles);
                            JToken? result =
                                rolesArray?.FirstOrDefault(val => val.Value<string>() == "dev-docs-admin");
                            if (result != null)
                            {

                                var claims = new List<Claim>
                                    {
                                        new(ClaimTypes.Role, "admin"),
                                        new(ClaimTypes.Name, userNameClaim)
                                    };
                                var appIdentity = new ClaimsIdentity(claims);
                                context.Principal?.AddIdentity(appIdentity);
                            }
                        }
                    }
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(limiterOptions =>
{
    limiterOptions.AddPolicy("jwt", partitioner: httpContext =>
    {
        var accessToken = httpContext.Features.Get<IAuthenticateResultFeature>()?
                              .AuthenticateResult?.Properties?.GetTokenValue("access_token")
                          ?? string.Empty;

        if (!StringValues.IsNullOrEmpty(accessToken))
        {
            return RateLimitPartition.GetTokenBucketLimiter(accessToken, _ =>
                new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 10,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(60),
                    TokensPerPeriod = 10,
                    AutoReplenishment = true,
                });
        }

        return RateLimitPartition.GetTokenBucketLimiter("Anon", _ =>
            new TokenBucketRateLimiterOptions
            {
                TokenLimit = 5,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                ReplenishmentPeriod = TimeSpan.FromSeconds(60),
                TokensPerPeriod = 5,
                AutoReplenishment = true
            });
    });
    limiterOptions.OnRejected = (context, cancellationToken) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter = retryAfter.TotalSeconds.ToString(CultureInfo.InvariantCulture);
        }

        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.WriteAsync("Too many requests. Please try again later.", cancellationToken: cancellationToken);

        return new ValueTask();
    };
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Please enter JWT with Bearer into field. Example: Bearer {your token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

WebApplication app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthorization();

app.MapControllers();

app.Run();