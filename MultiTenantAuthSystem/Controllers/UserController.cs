using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            /*var email = User.Claims
                .FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email)
                ?.Value;

            var role = User.Claims
                .FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role)
                ?.Value;

            var tenantId = User.Claims
                .FirstOrDefault(c => c.Type == "TenantId")
                ?.Value;*/
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;
            var tenantId = User.FindFirst("TenantId")?.Value;

            return Ok(new
            {
                message = "Profile fetched successfully!",
                email = email,
                role = role,
                tenantId = tenantId
            });
        }

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            var tenantId = User.Claims
                .FirstOrDefault(c => c.Type == "TenantId")
                ?.Value;

            return Ok(new
            {
                message = "Welcome Admin!",
                tenantId = tenantId
            });
        }
        //[HttpGet("test-error")]
        //[AllowAnonymous] // so you don't need a token to test it
        //public IActionResult TestError()
        //{
          //  throw new Exception("Simulated server crash!");
        //}

        // ← ADD HERE temporarily for testing
        //[HttpGet("test-unauth")]
        //[AllowAnonymous]
        //public IActionResult TestUnauth()
        //{
          //  throw new UnauthorizedAccessException();
        //}
    }
}



/*using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            var email = User.Claims
                .FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email)
                ?.Value;

            var role = User.Claims
                .FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role)
                ?.Value;

            return Ok(new
            {
                message = "You accessed a protected API!",
                email = email,
                role = role
            });
        }
        

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new
            {
                message = "Welcome Admin! You accessed admin-only API!"
            });
        }
    }
}*/