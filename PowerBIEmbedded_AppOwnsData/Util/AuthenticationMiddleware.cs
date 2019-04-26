using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace PowerBIEmbedded_AppOwnsData.Util
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
                        context.Response.Redirect(ConfigurationManager.AppSettings["redirectUri"]);
                    }
                }

                var items = context.Request.Query.ToDictionary(field => field.Key, field => field.Value.First());

                if (items.Count == 0)
                    return;

                if (!items.ContainsKey("access_token"))
                    return;

                var accessToken = items["access_token"];

                var expiresIn = items["expires_in"].Replace("/", "");

                await ValidateAsyncTokenAsync(context, accessToken, expiresIn);

            }
            catch (Exception)
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

            var claimsIdentity = new ClaimsIdentity(validate.Claims, DefaultAuthenticationTypes.ApplicationCookie);

            AuthenticationManager.SignIn(new AuthenticationProperties()
            {
                AllowRefresh = true,
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(double.Parse(expiresIn))
            }, claimsIdentity);

            await Next.Invoke(context);
        }

        private static IAuthenticationManager AuthenticationManager
        {
            get { return HttpContext.Current.GetOwinContext().Authentication; }
        }
    }
}