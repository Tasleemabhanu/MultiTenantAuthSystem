namespace MultiTenantAuthSystem.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;

            // Skip security headers for Swagger — CSP blocks its JS/CSS
            if (path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }

            // Remove headers that reveal your tech stack
            context.Response.Headers.Remove("X-Powered-By");
            context.Response.Headers.Remove("Server");

            context.Response.Headers.Append(
                "X-Content-Type-Options", "nosniff");

            context.Response.Headers.Append(
                "X-Frame-Options", "DENY");

            context.Response.Headers.Append(
                "X-XSS-Protection", "1; mode=block");

            context.Response.Headers.Append(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");

            context.Response.Headers.Append(
                "Referrer-Policy", "strict-origin-when-cross-origin");

            context.Response.Headers.Append(
                "Permissions-Policy", "geolocation=(), microphone=(), camera=()");

            context.Response.Headers.Append(
                "Cache-Control", "no-store, no-cache, must-revalidate");

            context.Response.Headers.Append(
                "Pragma", "no-cache");

            await _next(context);
        }
    }
}
/*namespace MultiTenantAuthSystem.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Remove the header that reveals your tech stack
            context.Response.Headers.Remove("X-Powered-By");
            context.Response.Headers.Remove("Server");

            // Prevents browsers from MIME-sniffing the content type
            context.Response.Headers.Append(
                "X-Content-Type-Options", "nosniff");

            // Blocks your API from being embedded in iframes
            context.Response.Headers.Append(
                "X-Frame-Options", "DENY");

            // Enables browser XSS protection (older browsers)
            context.Response.Headers.Append(
                "X-XSS-Protection", "1; mode=block");

            // Forces HTTPS for 1 year — only enable in production
            // context.Response.Headers.Append(
            //     "Strict-Transport-Security", "max-age=31536000; includeSubDomains");

            // Restricts what resources the browser can load
            context.Response.Headers.Append(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");

            // Controls how much referrer info is sent
            context.Response.Headers.Append(
                "Referrer-Policy", "strict-origin-when-cross-origin");

            // Disables access to browser features your API doesn't need
            context.Response.Headers.Append(
                "Permissions-Policy", "geolocation=(), microphone=(), camera=()");

            // Prevents caching of sensitive API responses
            context.Response.Headers.Append(
                "Cache-Control", "no-store, no-cache, must-revalidate");

            context.Response.Headers.Append(
                "Pragma", "no-cache");

            await _next(context);
        }
    }
}*/