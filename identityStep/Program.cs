using identityStep.Authorize;
using identityStep.Data;
using identityStep.Helpers;
using identityStep.Interfaces;
using identityStep.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace identityStep
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddRazorPages();

            builder.Services.AddDbContext<ApplicationDbContext>(options =>

                options.UseSqlServer(builder.Configuration.GetConnectionString("IdentityStep"))

            );

            //scaffollding one
            //builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ApplicationDbContext>();

            builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

            builder.Services.Configure<IdentityOptions>(opt =>
            {
                opt.Password.RequiredLength = 5;
                opt.Password.RequireLowercase = true;
                opt.Lockout.DefaultLockoutTimeSpan = new TimeSpan(0, 0, 5);
                opt.Lockout.MaxFailedAccessAttempts = 2;
            });

            var authhelper = new HelperMethods();
            builder.Services.AddAuthorization(opt =>
            {
                opt.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                opt.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
                opt.AddPolicy("AdminCreate", policy => policy.RequireRole("Admin").RequireClaim("Create", "True"));
                opt.AddPolicy("AdminCreateDeleteEdit", policy => policy.RequireRole("Admin").RequireClaim("Create", "True").RequireClaim("Delete", "True").RequireClaim("Edit", "True"));

                opt.AddPolicy("AdminAllOrSuper",
                    policy => policy.RequireAssertion(
                        context =>
                        (
                        //method from helper
                        authhelper.AuthorizeAdminWithClaimsOrSuperAdmin(context)
                        )
                    )
                );
                opt.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
                opt.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
                opt.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Qvabby")));
            });

            builder.Services.AddAuthentication()
                .AddFacebook(options =>
            {
                options.AppId = "191550813732362";
                options.AppSecret = "3e8675c736f20e5f844a0525da2d5b56";
            }).AddGoogle(options =>
            {
                options.ClientId = "246640904791-qh188s3h1sblnp0pa0js31ov344npev9.apps.googleusercontent.com";
                options.ClientSecret = "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";
            });

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.AccessDeniedPath = "/Home/AccessDenied";
            });

            builder.Services.AddTransient<ICustomEmailSender, EmailSender>();
            builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
            builder.Services.AddScoped<IAuthorizationHandler, AdminWithMoreThan1000DaysHandler>();
            builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.MapRazorPages();
            app.Run();
        }
    }
}