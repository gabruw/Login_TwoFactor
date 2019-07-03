using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Reflection;
using WebApp.Identity.Models;

namespace WebApp.Identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            var connectionString = "Integrated Security=SSPI;" +
                                    "Persist Security Info=False;" +
                                    "Initial Catalog=IdentityTest;" +
                                    @"Data Source=SHU_01\SQLEXPRESS";

            //var connectionString = "Integrated Security=SSPI;" +
            //                        "Persist Security Info=False;" +
            //                        "Initial Catalog=IdentityTest;" +
            //                        @"Data Source=DESKTOP-HOAG8IV\SQLEXPRESS";

            var migrationAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<MyUserDbContext>(options => options.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationAssembly)));

            // Adiciona o Identity
            services.AddIdentity<MyUser, IdentityRole>(options => 
            {
                // Confirmar e-mail login
                options.SignIn.RequireConfirmedEmail = true;

                // Burocracia da senha
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4;

                // Segurança
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(3);
            }).AddEntityFrameworkStores<MyUserDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<DoesNotContainPasswordValidator<MyUser>>();

            // Tempo de validação do Token [3 horas]
            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(3));

            // Scope's
            services.AddScoped<IUserStore<MyUser>, UserOnlyStore<MyUser, MyUserDbContext>>();
            services.AddScoped<IUserClaimsPrincipalFactory<MyUser>, MyUserClaimsPrincipalFactory>();

            // Adiciona Autenticação por Cookies
            services.AddAuthentication("cookies").AddCookie("cookies", options => options.LoginPath = "/Home/Login");
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            // Adiciona o uso de autenticação
            app.UseAuthentication();

            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
