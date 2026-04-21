using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
