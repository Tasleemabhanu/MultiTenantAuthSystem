using System.Security.Claims;

namespace MultiTenantAuthSystem.Services
{
    public class TenantService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public TenantService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        // Extracts tenantId from the JWT token — never trust the request body
        public int GetCurrentTenantId()
        {
            var user = _httpContextAccessor.HttpContext?.User;

            var tenantClaim = user?.FindFirst("TenantId")?.Value;

            if (string.IsNullOrEmpty(tenantClaim) || !int.TryParse(tenantClaim, out int tenantId))
                throw new UnauthorizedAccessException("Tenant could not be determined from token.");

            return tenantId;
        }

        public string GetCurrentUserEmail()
        {
            var user = _httpContextAccessor.HttpContext?.User;
            return user?.FindFirst("ClaimTypes.Email")?.Value ?? string.Empty;
        }

        public string GetCurrentUserRole()
        {
            var user = _httpContextAccessor.HttpContext?.User;
            return user?.FindFirst("ClaimTypes.Role")?.Value ?? string.Empty;
        }
    }
}