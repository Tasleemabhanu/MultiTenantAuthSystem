using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class CreateProductRequest
    {
        [Required(ErrorMessage = "Product name is required.")]
        [MinLength(2, ErrorMessage = "Name must be at least 2 characters.")]
        [MaxLength(100, ErrorMessage = "Name cannot exceed 100 characters.")]
        public string Name { get; set; } = string.Empty;

        [Required(ErrorMessage = "Price is required.")]
        [Range(0.01, 99999.99, ErrorMessage = "Price must be between 0.01 and 99999.99.")]
        public decimal Price { get; set; }
    }
}
/*using System.ComponentModel.DataAnnotations;

namespace MultiTenantAuthSystem.Models
{
    public class CreateProductRequest
    {
        [Required]
        public string Name { get; set; } = string.Empty;

        [Required]
        [Range(0.01, 99999.99)]
        public decimal Price { get; set; }
    }
}*/