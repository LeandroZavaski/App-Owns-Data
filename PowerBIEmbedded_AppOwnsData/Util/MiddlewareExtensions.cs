using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace PowerBIEmbedded_AppOwnsData.Util
{
    public static class MiddlewareExtensions
    {
        public static void UseCustomMiddleware(this IAppBuilder app, IMemoryCache memory)
        {
            app.Use<AuthenticationMiddleware>(memory);
        }
    }
}