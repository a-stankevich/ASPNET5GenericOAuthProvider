using System;
using System.Security.Claims;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Security;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.Framework.DependencyInjection;

namespace ASPNET5GenericOAuthProvider
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDataProtection();
            services.Configure<ExternalAuthenticationOptions>(options =>
            {
                options.SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType;
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseCookieAuthentication(options =>
            {
                options.LoginPath = new PathString("/login");
            });

            // Configure GitHub
            app.UseOAuthAuthentication("GitHub", options =>
            {
                options.ClientId = "8de23516870d7145b84e";
                options.ClientSecret = "0e3fd9808072907d1aa01df7e547ddbb6f6ec2fb";
                options.CallbackPath = new PathString("/signin-github");
                options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                options.TokenEndpoint = "https://github.com/login/oauth/access_token";
            });

            // Choose an authentication type
            app.Map("/login", socialApp =>
            {
                socialApp.Run(async context =>
                {
                    string authType = context.Request.Query["authtype"];
                    if (!string.IsNullOrEmpty(authType))
                    {
                        context.Response.Challenge(new AuthenticationProperties() { RedirectUri = "/" }, authType);
                        return;
                    }

                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("Choose an authentication type: <br>");
                    foreach (var type in context.GetAuthenticationTypes())
                    {
                        await context.Response.WriteAsync("<a href=\"?authtype=" + type.AuthenticationType + "\">" + (type.Caption ?? "(suppressed)") + "</a><br>");
                    }
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Sign-out to remove the user cookie.
            app.Map("/logout", socialApp =>
            {
                socialApp.Run(async context =>
                {
                    context.Response.SignOut(CookieAuthenticationDefaults.AuthenticationType);
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("You have been logged out. Goodbye " + context.User.Identity.Name + "<br>");
                    await context.Response.WriteAsync("<a href=\"/\">Home</a>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Deny anonymous request beyond this point.
            app.Use(async (context, next) =>
            {
                if (!context.User.Identity.IsAuthenticated)
                {
                    // The cookie middleware will intercept this 401 and redirect to /login
                    context.Response.Challenge();
                    return;
                }
                await next();
            });

            // Display user information
            app.Run(async context =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync("<html><body>");
                await context.Response.WriteAsync("Hello " + context.User.Identity.Name + "<br>");
                foreach (var claim in context.User.Claims)
                {
                    await context.Response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
                }
                await context.Response.WriteAsync("<a href=\"/logout\">Logout</a>");
                await context.Response.WriteAsync("</body></html>");
            });
        }
    }
}
