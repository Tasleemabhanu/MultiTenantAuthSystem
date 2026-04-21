using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Models;
using MultiTenantAuthSystem.Services;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // must be logged in
    [EnableRateLimiting("GlobalPolicy")]
    public class ProductController : ControllerBase
    {
        private readonly DatabaseHelper _databaseHelper;
        private readonly TenantService _tenantService;

        public ProductController(DatabaseHelper databaseHelper, TenantService tenantService)
        {
            _databaseHelper = databaseHelper;
            _tenantService = tenantService;
        }

        // GET /api/product — returns only THIS tenant's products
        [HttpGet]
        public IActionResult GetProducts()
        {
            // TenantId comes from JWT token — not from request body
            int tenantId = _tenantService.GetCurrentTenantId();

            var products = new List<object>();

            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            string query = @"SELECT Id, Name, Price, TenantId 
                             FROM Products 
                             WHERE TenantId = @TenantId";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@TenantId", tenantId);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                products.Add(new
                {
                    id = Convert.ToInt32(reader["Id"]),
                    name = reader["Name"].ToString(),
                    price = Convert.ToDecimal(reader["Price"]),
                    tenantId = Convert.ToInt32(reader["TenantId"])
                });
            }

            return Ok(new
            {
                tenantId = tenantId,
                count = products.Count,
                products = products
            });
        }

        // GET /api/product/{id} — returns product only if it belongs to THIS tenant
        [HttpGet("{id}")]
        public IActionResult GetProductById(int id)
        {
            int tenantId = _tenantService.GetCurrentTenantId();

            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // TenantId filter prevents accessing another tenant's product by ID
            string query = @"SELECT Id, Name, Price, TenantId 
                             FROM Products 
                             WHERE Id = @Id AND TenantId = @TenantId";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Id", id);
            command.Parameters.AddWithValue("@TenantId", tenantId);

            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                return Ok(new
                {
                    id = Convert.ToInt32(reader["Id"]),
                    name = reader["Name"].ToString(),
                    price = Convert.ToDecimal(reader["Price"]),
                    tenantId = Convert.ToInt32(reader["TenantId"])
                });
            }

            // Returns 404 even if the product exists — just in another tenant
            return NotFound(new { message = $"Product {id} not found in your tenant." });
        }

        // POST /api/product — Admin only, creates product for THIS tenant
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult CreateProduct([FromBody] CreateProductRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // TenantId always comes from token — ignore any tenantId in request body
            int tenantId = _tenantService.GetCurrentTenantId();

            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            string query = @"INSERT INTO Products (Name, Price, TenantId)
                             OUTPUT INSERTED.Id
                             VALUES (@Name, @Price, @TenantId)";

            int newId;
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Name", request.Name);
            command.Parameters.AddWithValue("@Price", request.Price);
            command.Parameters.AddWithValue("@TenantId", tenantId);
            newId = (int)command.ExecuteScalar();

            return StatusCode(201, new
            {
                message = "Product created successfully.",
                id = newId,
                tenantId = tenantId
            });
        }
    }
}