using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Security;
using Microsoft.AspNet.Security;
using Microsoft.AspNet.Security.Cookies;
using Microsoft.AspNet.Security.OAuth;
using Microsoft.Framework.DependencyInjection;
using Newtonsoft.Json.Linq;

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
                options.ClientId = "a643223e6e429ee091d1";
                options.ClientSecret = "673d832c4b8cd8932aa4444e319cc20bff7bf590";
                options.CallbackPath = new PathString("/signin-github");
                options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                options.UserInformationEndpoint = "https://api.github.com/user";
                options.Notifications = new OAuthAuthenticationNotifications
                {
                    OnGetUserInformationAsync = async context =>
                    {
                        // Get the GitHub user
                        HttpRequestMessage userRequest = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        HttpResponseMessage userResponse = await context.Backchannel.SendAsync(userRequest, context.HttpContext.RequestAborted);
                        userResponse.EnsureSuccessStatusCode();
                        var text = await userResponse.Content.ReadAsStringAsync();
                        JObject user = JObject.Parse(text);

                        var identity = new ClaimsIdentity(
                            context.Options.AuthenticationType,
                            ClaimsIdentity.DefaultNameClaimType,
                            ClaimsIdentity.DefaultRoleClaimType);

                        JToken value;
                        var id = user.TryGetValue("id", out value) ? value.ToString() : null;
                        if (!string.IsNullOrEmpty(id))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, id, ClaimValueTypes.String, context.Options.AuthenticationType));
                        }
                        var userName = user.TryGetValue("login", out value) ? value.ToString() : null;
                        if (!string.IsNullOrEmpty(userName))
                        {
                            identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, userName, ClaimValueTypes.String, context.Options.AuthenticationType));
                        }
                        var name = user.TryGetValue("name", out value) ? value.ToString() : null;
                        if (!string.IsNullOrEmpty(name))
                        {
                            identity.AddClaim(new Claim("urn:github:name", name, ClaimValueTypes.String, context.Options.AuthenticationType));
                        }
                        var link = user.TryGetValue("url", out value) ? value.ToString() : null;
                        if (!string.IsNullOrEmpty(link))
                        {
                            identity.AddClaim(new Claim("urn:github:url", link, ClaimValueTypes.String, context.Options.AuthenticationType));
                        }

                        context.Identity = identity;
                    }
                };
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
