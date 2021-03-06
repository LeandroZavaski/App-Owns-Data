﻿using System.Configuration;
using System.IdentityModel.Claims;
using System.Web.Helpers;
using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using PowerBIEmbedded_AppOwnsData.Util;

[assembly: OwinStartupAttribute(typeof(PowerBIEmbedded_AppOwnsData.Startup))]
namespace PowerBIEmbedded_AppOwnsData
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();

            ConfigureOAuth(app);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            app.UseWebApi(config);
        }
        public void ConfigureOAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = ConfigurationManager.AppSettings["applicationId"],
                Authority = ConfigurationManager.AppSettings["authorityUrl"],
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
            });

            app.UseCustomMiddleware(new MemoryCache(new MemoryCacheOptions()));

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }
    }
}
