using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace PowerBIEmbedded_AppOwnsData.Utils
{
    public class AuthenticationMiddleware : OwinMiddleware
    {
        private readonly IMemoryCache _memory;

        public AuthenticationMiddleware(OwinMiddleware next, IMemoryCache memory) : base(next)
        {
            _memory = memory;
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (context.Authentication.User.Identity.IsAuthenticated)
            {
                await Next.Invoke(context);
                return;
            }
            await ProcessAsync(context);
        }

        private async Task ProcessAsync(IOwinContext context)
        {
            try
            {
                var count = Convert.ToInt32(_memory.Get("count") ?? 0);

                if (!context.Request.Query.Any())
                {
                    if (count < 1)
                    {
                        count += 1;
                        _memory.Set("count", count);
                        await context.Response.WriteAsync(
                        "<html>" +
                        "<body>" +
                        "<script>" +
                        "window.location = window.location.origin + window.location.pathname + " +
                        "'?' + window.location.hash.substr(1)" +
                        "</script>" +
                        "</body>" +
                        "</html>");

                        return;
                    }
                    else
                    {
                        _memory.Remove("count");
                        context.Response.Redirect(ConfigurationManager.AppSettings["openIdInfo:redirectUri"]);
                    }
                }

                var items = context.Request.Query.ToDictionary(field => field.Key, field => field.Value.First());

                if (items.Count == 0)
                    return;

                if (!items.ContainsKey("access_token"))
                    return;

                var accessToken = items["access_token"];

                var expiresIn = items["expires_in"].Replace("/","");

                await ValidateAsyncTokenAsync(context, accessToken, expiresIn);

            }
            catch (Exception e)
            {
                context.Response.Redirect(ConfigurationManager.AppSettings["redirectUri"]);
            }
        }

        private async Task ValidateAsyncTokenAsync(IOwinContext context, string accessToken, string expiresIn)
        {
            var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, ConfigurationManager.AppSettings["CertificateValue"], false);
            var issuerSigningKey = new X509SecurityKey(new X509Certificate2(new X509Certificate(certCollection[0])));

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = issuerSigningKey
            };

            var validator = new JwtSecurityTokenHandler();

            if (!validator.CanReadToken(accessToken))
                throw new UnauthorizedAccessException("token is not readable");

            var validate = validator.ValidateToken(accessToken, validationParameters, out var validatedToken);

            var claimsIdentity = new ClaimsIdentity(validate.Claims, "Cookie");

            var principal = new ClaimsPrincipal(claimsIdentity);

            var authProperties = new AuthenticationProperties
            {
                ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(double.Parse(expiresIn)),
                IsPersistent = true
            };

            if (principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                context.Authentication.SignIn(authProperties, claimsIdentity);

                context.Authentication.User.AddIdentity((ClaimsIdentity)principal.Identity);

                context.Response.Headers.Add("Bearer", accessToken.Split().ToArray());
            }
            await Next.Invoke(context);
        }
    }
}