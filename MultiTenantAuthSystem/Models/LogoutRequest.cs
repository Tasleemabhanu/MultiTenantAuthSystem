using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class LogoutRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}