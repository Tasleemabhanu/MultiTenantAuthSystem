using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public int TenantId { get; set; }
    }
}