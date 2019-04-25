using Microsoft.Extensions.Caching.Memory;
using Owin;

namespace PowerBIEmbedded_AppOwnsData.Utils
{
    public static class MiddlewareExtensions
    {
        public static void UseCustomMiddleware(this IAppBuilder app, IMemoryCache memory)
        {
            app.Use<AuthenticationMiddleware>(memory);
        }
    }
}