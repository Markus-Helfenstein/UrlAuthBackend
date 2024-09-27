using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.StaticFiles.Infrastructure;
using Microsoft.Extensions.FileProviders;
using Microsoft.Net.Http.Headers;

internal class Program
{
    const string CORS_POLICY = "CorsPolicy";

    private static void AddApplicationServices(WebApplicationBuilder builder)
    {
        if (builder.Environment.IsDevelopment())
        {
            builder.Services.AddLogging(loggingBuilder => loggingBuilder.AddDebug());
        }
        else
        {
            builder.Services.AddLogging(loggingBuilder => loggingBuilder.AddAzureWebAppDiagnostics());
        }
        
        builder.Services.AddControllers();
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddCors(opt => 
        {
            opt.AddPolicy(CORS_POLICY, policy =>
            {
                // CORS whitelisting only for dev when client-app uses different port
                if (builder.Environment.IsDevelopment())
                {
                    policy
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .WithExposedHeaders(HeaderNames.WWWAuthenticate)
                        .AllowCredentials()
                        .WithOrigins("https://localhost:5173", "https://localhost:7095");
                }
            });
        });

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.Cookie.Name = "auth";
                options.ExpireTimeSpan = TimeSpan.FromDays(366); // access duration for particular cookie (persistence in browser is enabled as prop in SignInAsync)
                options.LoginPath = "/access";
                options.SlidingExpiration = true;
            });

        // Require all users to be authenticated except for endpoints with [AllowAnonymous]
        builder.Services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
    }    
    
    private static void AddSecurityHeaders(WebApplication app)
    {
        app.UseXContentTypeOptions(); // prevents mime-sniffing
        app.UseReferrerPolicy(opt => opt.NoReferrer());
        app.UseXfo(opt => opt.Deny()); // disallow usage of app inside an iframe, prevents clickjacking
        // TODO revert back report only
        app.UseCspReportOnly(opt => opt // whitelist content against XSS
            .StyleSources(s => s.Self().CustomSources("https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"))
            .FontSources(s => s.Self())
            .FormActions(s => s.Self())
            .FrameAncestors(s => s.Self())
            .ImageSources(s => s.Self().CustomSources("data:"))
            .ScriptSources(s => s.Self())
            .ConnectSources(s => s.Self())
        );

        app.Use(async (context, next) =>
        {
            context.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000");
            await next?.Invoke();
        });

        app.UseCors(CORS_POLICY);
    }

    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        AddApplicationServices(builder);

        var app = builder.Build();
        
        AddSecurityHeaders(app);

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        // By calling UseStaticFiles (with custom folder!) after UseAuthentication, RequireAuthenticatedUser policy is applied
        // By omitting RequestPath, default routing path "/" is used for files in PrivateWwwRoot
        var sharedOptions = new SharedOptions
        {
            FileProvider = new PhysicalFileProvider(Path.Combine(builder.Environment.ContentRootPath, "PrivateWwwRoot"))
        };
        app.UseDefaultFiles(new DefaultFilesOptions(sharedOptions));
        app.UseStaticFiles(new StaticFileOptions(sharedOptions));
        // Imagine user bookmarks SPA route /personal and revisits later
        // Server has to deliver index.html, so the react router engine may handle the route in the browser
        app.MapFallbackToFile("index.html", new StaticFileOptions(sharedOptions));

        app.MapControllers();

        app.Run();
    }
}