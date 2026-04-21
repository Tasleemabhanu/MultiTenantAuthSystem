using FluentAssertions;
using Microsoft.Extensions.Configuration;
using MultiTenantAuthSystem.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MultiTenantAuthSystem.Tests.Services
{
    public class TokenServiceTests
    {
        private readonly TokenService _tokenService;

        public TokenServiceTests()
        {
            // Build a fake configuration — no appsettings.json needed
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["JwtSettings:SecretKey"] = "ThisIsATestSecretKeyThatIsLongEnough123!",
                    ["JwtSettings:Issuer"] = "MultiTenantAuthSystem",
                    ["JwtSettings:Audience"] = "MultiTenantAuthSystemUsers",
                    ["JwtSettings:ExpiryInMinutes"] = "60"
                })
                .Build();

            _tokenService = new TokenService(config);
        }

        [Fact]
        public void GenerateToken_ShouldReturnNonEmptyString()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);

            token.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void GenerateToken_ShouldBeValidJwtFormat()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);

            // JWT has exactly 3 parts separated by dots
            token.Split('.').Should().HaveCount(3);
        }

        [Fact]
        public void GenerateToken_ShouldContainEmailClaim()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            var emailClaim = jwt.Claims
                .FirstOrDefault(c => c.Type == ClaimTypes.Email
                                  || c.Value == "alice@companya.com");

            emailClaim.Should().NotBeNull();
        }

        [Fact]
        public void GenerateToken_ShouldContainTenantIdClaim()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            var tenantClaim = jwt.Claims
                .FirstOrDefault(c => c.Type == "TenantId");

            tenantClaim.Should().NotBeNull();
            tenantClaim!.Value.Should().Be("1");
        }

        [Fact]
        public void GenerateToken_ShouldContainRoleClaim()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            var roleClaim = jwt.Claims
                .FirstOrDefault(c => c.Type == ClaimTypes.Role
                                  || c.Value == "Admin");

            roleClaim.Should().NotBeNull();
        }

        [Fact]
        public void GenerateToken_ShouldExpireInFuture()
        {
            var token = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            jwt.ValidTo.Should().BeAfter(DateTime.UtcNow);
        }

        [Fact]
        public void GenerateToken_DifferentTenantsShouldProduceDifferentTokens()
        {
            var token1 = _tokenService.GenerateToken("alice@companya.com", "Admin", 1);
            var token2 = _tokenService.GenerateToken("alice@companya.com", "Admin", 2);

            token1.Should().NotBe(token2);
        }

        [Fact]
        public void GenerateRefreshToken_ShouldReturnNonEmptyString()
        {
            var token = _tokenService.GenerateRefreshToken();

            token.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void GenerateRefreshToken_ShouldReturnDifferentTokenEachTime()
        {
            var token1 = _tokenService.GenerateRefreshToken();
            var token2 = _tokenService.GenerateRefreshToken();

            token1.Should().NotBe(token2);
        }
    }
}
