using Microsoft.Data.SqlClient;
using System.Diagnostics;
using System.Security.Claims;

namespace MultiTenantAuthSystem.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;
        private readonly IConfiguration _configuration;

        // These paths are too noisy to log — skip them
        private static readonly string[] SkippedPaths =
        [
            "/swagger",
            "/favicon.ico",
            "/_framework"
        ];

        public RequestLoggingMiddleware(
            RequestDelegate next,
            ILogger<RequestLoggingMiddleware> logger,
            IConfiguration configuration)
        {
            _next = next;
            _logger = logger;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;

            // Skip noisy swagger/static paths
            if (SkippedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                await _next(context);
                return;
            }

            var stopwatch = Stopwatch.StartNew();

            // Let the request go through the pipeline
            await _next(context);

            stopwatch.Stop();

            // Extract details after the request has been handled
            var method = context.Request.Method;
            var statusCode = context.Response.StatusCode;
            var duration = (int)stopwatch.ElapsedMilliseconds;
            var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // Extract claims from JWT if present
            var userEmail = context.User.FindFirst(ClaimTypes.Email)?.Value;
            var tenantId = context.User.FindFirst("TenantId")?.Value;

            // Log to console
            _logger.LogInformation(
                "{Method} {Path} | Status: {Status} | Duration: {Duration}ms | IP: {IP} | User: {User} | Tenant: {Tenant}",
                method, path, statusCode, duration, ipAddress,
                userEmail ?? "anonymous",
                tenantId ?? "none");

            // Log to DB asynchronously — don't block the response
            _ = Task.Run(() => SaveToDatabase(
                method, path, statusCode,
                ipAddress, userEmail,
                tenantId == null ? null : int.TryParse(tenantId, out int tid) ? tid : null,
                duration));
        }

        private void SaveToDatabase(
            string method,
            string path,
            int statusCode,
            string ipAddress,
            string? userEmail,
            int? tenantId,
            int durationMs)
        {
            try
            {
                var connStr = _configuration.GetConnectionString("DefaultConnection");

                using var connection = new SqlConnection(connStr);
                connection.Open();

                string query = @"INSERT INTO AuditLogs
                                     (Method, Path, StatusCode, IpAddress, UserEmail, TenantId, DurationMs)
                                 VALUES
                                     (@Method, @Path, @StatusCode, @IpAddress, @UserEmail, @TenantId, @DurationMs)";

                using var cmd = new SqlCommand(query, connection);
                cmd.Parameters.AddWithValue("@Method", method);
                cmd.Parameters.AddWithValue("@Path", path);
                cmd.Parameters.AddWithValue("@StatusCode", statusCode);
                cmd.Parameters.AddWithValue("@IpAddress", ipAddress);
                cmd.Parameters.AddWithValue("@UserEmail", (object?)userEmail ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@TenantId", (object?)tenantId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@DurationMs", durationMs);
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // Never crash the app because of a logging failure
                _logger.LogError(ex, "Failed to save audit log to database.");
            }
        }
    }
}
