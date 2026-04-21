using System.Net;
using System.Text.Json;

namespace MultiTenantAuthSystem.Middleware
{
    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionMiddleware> _logger;

        public GlobalExceptionMiddleware(
            RequestDelegate next,
            ILogger<GlobalExceptionMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                // Pass the request down the pipeline normally
                await _next(context);
            }
            catch (Exception ex)
            {
                // Log full details internally — never expose to client
                _logger.LogError(ex,
                    "Unhandled exception on {Method} {Path} at {Time}",
                    context.Request.Method,
                    context.Request.Path,
                    DateTime.UtcNow);

                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";

            // Map exception types to HTTP status codes
            var (statusCode, message) = exception switch
            {
                UnauthorizedAccessException => (
                    HttpStatusCode.Unauthorized,
                    "You are not authorized to perform this action."),

                KeyNotFoundException => (
                    HttpStatusCode.NotFound,
                    "The requested resource was not found."),

                ArgumentNullException or ArgumentException => (
                    HttpStatusCode.BadRequest,
                    "Invalid request data."),

                InvalidOperationException => (
                    HttpStatusCode.BadRequest,
                    "The operation is not valid in the current state."),

                // Catch-all for anything else
                _ => (
                    HttpStatusCode.InternalServerError,
                    "An unexpected error occurred. Please try again later.")
            };

            context.Response.StatusCode = (int)statusCode;

            var response = new
            {
                success = false,
                status = (int)statusCode,
                message = message,
                path = context.Request.Path.Value,
                timestamp = DateTime.UtcNow
            };

            var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await context.Response.WriteAsync(json);
        }
    }
}