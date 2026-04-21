using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [MaxLength(100, ErrorMessage = "Email cannot exceed 100 characters.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters.")]
        [MaxLength(100, ErrorMessage = "Password cannot exceed 100 characters.")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "TenantId is required.")]
        [Range(1, int.MaxValue, ErrorMessage = "TenantId must be a positive number.")]
        public int TenantId { get; set; }
    }
}
/*namespace MultiTenantAuthSystem.Models
{
    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public int TenantId { get; set; }
    }
}*/
