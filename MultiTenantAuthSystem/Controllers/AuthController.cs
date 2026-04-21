using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Helpers;
using MultiTenantAuthSystem.Models;
using MultiTenantAuthSystem.Services;
using System.Security.Claims;
using Microsoft.AspNetCore.RateLimiting;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DatabaseHelper _databaseHelper;
        private readonly TokenService _tokenService;
        private readonly LockoutService _lockoutService;

        public AuthController(DatabaseHelper databaseHelper, TokenService tokenService, LockoutService lockoutService)
        {
            _databaseHelper = databaseHelper;
            _tokenService = tokenService;
            _lockoutService = lockoutService;
        }

        // ─── LOGIN ────────────────────────────────────────────────────────────
        [HttpPost("login")]
        [EnableRateLimiting("AuthPolicy")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // Step 1 — Fetch user by email + tenantId
            string query = @"SELECT u.Id, u.Email, u.Role, u.TenantId,
                            u.PasswordSalt, u.PasswordHash,
                            t.Name as TenantName
                     FROM Users u
                     INNER JOIN Tenants t ON u.TenantId = t.Id
                     WHERE u.Email    = @Email
                     AND   u.TenantId = @TenantId";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Email", request.Email);
            command.Parameters.AddWithValue("@TenantId", request.TenantId);

            using var reader = command.ExecuteReader();

            // User not found — return same generic message to avoid user enumeration
            if (!reader.Read())
                return Unauthorized(new { message = "Invalid credentials or wrong tenant." });

            var userId = Convert.ToInt32(reader["Id"]);
            var storedSalt = reader["PasswordSalt"].ToString()!;
            var storedHash = reader["PasswordHash"].ToString()!;
            var email = reader["Email"].ToString()!;
            var role = reader["Role"].ToString()!;
            var tenantId = Convert.ToInt32(reader["TenantId"]);
            var tenantName = reader["TenantName"].ToString()!;

            reader.Close();

            // Step 2 — Check if account is locked
            var lockoutMessage = _lockoutService.CheckLockout(connection, userId);
            if (lockoutMessage != null)
                return StatusCode(429, new
                {
                    message = lockoutMessage,
                    attemptsAllowed = 5,
                    windowMinutes = 15
                });

            // Step 3 — Verify password
            if (!PasswordHelper.VerifyPassword(request.Password, storedSalt, storedHash))
            {
                // Record the failed attempt
                _lockoutService.RecordFailedAttempt(connection, userId);

                // Fetch updated attempt count to warn the user
                string countQuery = "SELECT FailedLoginAttempts FROM Users WHERE Id = @UserId";
                using var countCmd = new SqlCommand(countQuery, connection);
                countCmd.Parameters.AddWithValue("@UserId", userId);
                int attempts = (int)countCmd.ExecuteScalar();

                int remaining = 5 - attempts;
                if (remaining <= 0)
                    return StatusCode(429, new
                    {
                        message = "Too many failed attempts. Account locked for 15 minutes."
                    });

                return Unauthorized(new
                {
                    message = "Invalid credentials or wrong tenant.",
                    attemptsRemaining = remaining
                });
            }

            // Step 4 — Successful login — reset lockout counter
            _lockoutService.ResetFailedAttempts(connection, userId);

            // Step 5 — Generate tokens
            var jwt = _tokenService.GenerateToken(email, role, tenantId);
            var refreshToken = _tokenService.GenerateRefreshToken();

            StoreRefreshToken(connection, userId, tenantId, refreshToken);

            return Ok(new
            {
                message = "Login successful",
                token = jwt,
                refreshToken = refreshToken,
                role = role,
                email = email,
                tenantId = tenantId,
                tenantName = tenantName
            });
        }

        // ─── REFRESH ──────────────────────────────────────────────────────────
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // Look up the refresh token in DB
            string query = @"SELECT rt.UserId, rt.TenantId, rt.ExpiresAt, rt.IsRevoked,
                                    u.Email, u.Role
                             FROM RefreshTokens rt
                             INNER JOIN Users u ON rt.UserId = u.Id
                             WHERE rt.Token = @Token";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Token", request.RefreshToken);

            using var reader = command.ExecuteReader();

            if (!reader.Read())
                return Unauthorized(new { message = "Invalid refresh token." });

            var isRevoked = Convert.ToBoolean(reader["IsRevoked"]);
            var expiresAt = Convert.ToDateTime(reader["ExpiresAt"]);

            if (isRevoked)
                return Unauthorized(new { message = "Refresh token has been revoked." });

            if (expiresAt < DateTime.UtcNow)
                return Unauthorized(new { message = "Refresh token has expired. Please login again." });

            var userId = Convert.ToInt32(reader["UserId"]);
            var tenantId = Convert.ToInt32(reader["TenantId"]);
            var email = reader["Email"].ToString()!;
            var role = reader["Role"].ToString()!;

            reader.Close();

            // Revoke the old refresh token — one-time use
            RevokeRefreshToken(connection, request.RefreshToken);

            // Issue brand new JWT + refresh token
            var newJwt = _tokenService.GenerateToken(email, role, tenantId);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            StoreRefreshToken(connection, userId, tenantId, newRefreshToken);

            return Ok(new
            {
                message = "Token refreshed successfully.",
                token = newJwt,
                refreshToken = newRefreshToken
            });
        }
        // ─── LOGOUT ───────────────────────────────────────────────────────────
        [HttpPost("logout")]
        [Authorize]  // must be logged in to logout
        public IActionResult Logout([FromBody] LogoutRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // Check the refresh token exists and belongs to the current user
            string email = User.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;
            int tenantId = int.Parse(User.FindFirst("TenantId")?.Value ?? "0");

            string selectQuery = @"SELECT rt.Id, rt.IsRevoked, u.Email
                           FROM RefreshTokens rt
                           INNER JOIN Users u ON rt.UserId = u.Id
                           WHERE rt.Token    = @Token
                           AND   u.Email     = @Email
                           AND   rt.TenantId = @TenantId";

            using (var cmd = new SqlCommand(selectQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Token", request.RefreshToken);
                cmd.Parameters.AddWithValue("@Email", email);
                cmd.Parameters.AddWithValue("@TenantId", tenantId);

                using var reader = cmd.ExecuteReader();

                if (!reader.Read())
                    return BadRequest(new { message = "Invalid refresh token." });

                if (Convert.ToBoolean(reader["IsRevoked"]))
                    return BadRequest(new { message = "Token already revoked." });

                reader.Close();
            }

            // Revoke the refresh token
            RevokeRefreshToken(connection, request.RefreshToken);

            return Ok(new { message = "Logged out successfully." });
        }

        // ─── REGISTER ─────────────────────────────────────────────────────────
        [HttpPost("register")]
        [EnableRateLimiting("AuthPolicy")]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            using (var cmd = new SqlCommand(
                "SELECT COUNT(1) FROM Tenants WHERE Id = @TenantId", connection))
            {
                cmd.Parameters.AddWithValue("@TenantId", request.TenantId);
                if ((int)cmd.ExecuteScalar() == 0)
                    return BadRequest(new { message = "Invalid tenant." });
            }

            using (var cmd = new SqlCommand(
                "SELECT COUNT(1) FROM Users WHERE Email = @Email AND TenantId = @TenantId", connection))
            {
                cmd.Parameters.AddWithValue("@Email", request.Email);
                cmd.Parameters.AddWithValue("@TenantId", request.TenantId);
                if ((int)cmd.ExecuteScalar() > 0)
                    return Conflict(new { message = "User already exists in this tenant." });
            }

            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword(request.Password, salt);

            string insertQuery = @"INSERT INTO Users (Email, PasswordSalt, PasswordHash, Role, TenantId)
                                   OUTPUT INSERTED.Id
                                   VALUES (@Email, @Salt, @Hash, @Role, @TenantId)";

            int newUserId;
            using (var cmd = new SqlCommand(insertQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Email", request.Email);
                cmd.Parameters.AddWithValue("@Salt", salt);
                cmd.Parameters.AddWithValue("@Hash", hash);
                cmd.Parameters.AddWithValue("@Role", request.Role);
                cmd.Parameters.AddWithValue("@TenantId", request.TenantId);
                newUserId = (int)cmd.ExecuteScalar();
            }

            return StatusCode(201, new
            {
                message = "User registered successfully.",
                userId = newUserId
            });
        }
        // ─── FORGOT PASSWORD ──────────────────────────────────────────────────
        [HttpPost("forgot-password")]
        [EnableRateLimiting("AuthPolicy")]
        public IActionResult ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // Look up user by email + tenantId
            string selectQuery = @"SELECT Id FROM Users
                           WHERE Email    = @Email
                           AND   TenantId = @TenantId";

            int userId;
            using (var cmd = new SqlCommand(selectQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Email", request.Email);
                cmd.Parameters.AddWithValue("@TenantId", request.TenantId);

                var result = cmd.ExecuteScalar();

                // Always return 200 even if email not found
                // This prevents user enumeration attacks
                if (result == null)
                    return Ok(new
                    {
                        message = "If that email exists, a reset token has been sent."
                    });

                userId = Convert.ToInt32(result);
            }

            // Invalidate any existing unused tokens for this user
            string invalidateQuery = @"UPDATE PasswordResetTokens
                               SET IsUsed = 1
                               WHERE UserId = @UserId AND IsUsed = 0";

            using (var cmd = new SqlCommand(invalidateQuery, connection))
            {
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.ExecuteNonQuery();
            }

            // Generate a new reset token — cryptographically random
            var resetToken = Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)
            );

            // Store the token in DB — expires in 15 minutes
            string insertQuery = @"INSERT INTO PasswordResetTokens
                               (UserId, TenantId, Token, ExpiresAt)
                           VALUES
                               (@UserId, @TenantId, @Token, @ExpiresAt)";

            using (var cmd = new SqlCommand(insertQuery, connection))
            {
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@TenantId", request.TenantId);
                cmd.Parameters.AddWithValue("@Token", resetToken);
                cmd.Parameters.AddWithValue("@ExpiresAt", DateTime.UtcNow.AddMinutes(15));
                cmd.ExecuteNonQuery();
            }

            // In production → send token via email
            // In development → return token directly in response for testing
            return Ok(new
            {
                message = "If that email exists, a reset token has been sent.",
                resetToken = resetToken  // remove this line in production
            });
        }

        // ─── RESET PASSWORD ───────────────────────────────────────────────────
        [HttpPost("reset-password")]
        public IActionResult ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            // Look up the reset token
            string selectQuery = @"SELECT prt.UserId, prt.TenantId,
                                  prt.ExpiresAt, prt.IsUsed
                           FROM PasswordResetTokens prt
                           WHERE prt.Token = @Token";

            int userId;
            int tenantId;
            DateTime expiresAt;
            bool isUsed;

            using (var cmd = new SqlCommand(selectQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Token", request.Token);

                using var reader = cmd.ExecuteReader();

                if (!reader.Read())
                    return BadRequest(new { message = "Invalid or expired reset token." });

                userId = Convert.ToInt32(reader["UserId"]);
                tenantId = Convert.ToInt32(reader["TenantId"]);
                expiresAt = Convert.ToDateTime(reader["ExpiresAt"]);
                isUsed = Convert.ToBoolean(reader["IsUsed"]);

                reader.Close();
            }

            // Validate the token
            if (isUsed)
                return BadRequest(new { message = "Reset token has already been used." });

            if (expiresAt < DateTime.UtcNow)
                return BadRequest(new { message = "Reset token has expired. Please request a new one." });

            // Hash the new password
            var newSalt = Helpers.PasswordHelper.GenerateSalt();
            var newHash = Helpers.PasswordHelper.HashPassword(request.NewPassword, newSalt);

            // Update the password
            string updatePasswordQuery = @"UPDATE Users
                                   SET PasswordSalt = @Salt,
                                       PasswordHash = @Hash,
                                       -- Reset lockout in case they were locked out
                                       FailedLoginAttempts = 0,
                                       LockoutEndTime      = NULL,
                                       LastFailedAttempt   = NULL
                                   WHERE Id = @UserId";

            using (var cmd = new SqlCommand(updatePasswordQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Salt", newSalt);
                cmd.Parameters.AddWithValue("@Hash", newHash);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.ExecuteNonQuery();
            }

            // Mark reset token as used
            string markUsedQuery = @"UPDATE PasswordResetTokens
                             SET IsUsed = 1
                             WHERE Token = @Token";

            using (var cmd = new SqlCommand(markUsedQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Token", request.Token);
                cmd.ExecuteNonQuery();
            }

            // Revoke ALL refresh tokens for this user — force re-login everywhere
            string revokeTokensQuery = @"UPDATE RefreshTokens
                                 SET IsRevoked = 1
                                 WHERE UserId = @UserId";

            using (var cmd = new SqlCommand(revokeTokensQuery, connection))
            {
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.ExecuteNonQuery();
            }

            return Ok(new { message = "Password reset successfully. Please login with your new password." });
        }


        // ─── PRIVATE HELPERS ──────────────────────────────────────────────────

        private void StoreRefreshToken(SqlConnection connection, int userId, int tenantId, string token)
        {
            string query = @"INSERT INTO RefreshTokens (UserId, TenantId, Token, ExpiresAt)
                             VALUES (@UserId, @TenantId, @Token, @ExpiresAt)";

            using var cmd = new SqlCommand(query, connection);
            cmd.Parameters.AddWithValue("@UserId", userId);
            cmd.Parameters.AddWithValue("@TenantId", tenantId);
            cmd.Parameters.AddWithValue("@Token", token);
            cmd.Parameters.AddWithValue("@ExpiresAt", DateTime.Now.AddDays(7));
            cmd.ExecuteNonQuery();
        }

        private void RevokeRefreshToken(SqlConnection connection, string token)
        {
            string query = "UPDATE RefreshTokens SET IsRevoked = 1 WHERE Token = @Token";

            using var cmd = new SqlCommand(query, connection);
            cmd.Parameters.AddWithValue("@Token", token);
            cmd.ExecuteNonQuery();
        }
    }
}






/*using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Models;
using MultiTenantAuthSystem.Services;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DatabaseHelper _databaseHelper;
        private readonly TokenService _tokenService;

        public AuthController(DatabaseHelper databaseHelper, TokenService tokenService)
        {
            _databaseHelper = databaseHelper;
            _tokenService = tokenService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            string query = @"SELECT u.Id, u.Email, u.Role, u.TenantId, t.Name as TenantName 
                           FROM Users u 
                           INNER JOIN Tenants t ON u.TenantId = t.Id
                           WHERE u.Email = @Email 
                           AND u.PasswordHash = @Password 
                           AND u.TenantId = @TenantId";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Email", request.Email);
            command.Parameters.AddWithValue("@Password", request.Password);
            command.Parameters.AddWithValue("@TenantId", request.TenantId);

            using var reader = command.ExecuteReader();

            if (reader.Read())
            {
                var email = reader["Email"].ToString()!;
                var role = reader["Role"].ToString()!;
                var tenantId = Convert.ToInt32(reader["TenantId"]);
                var tenantName = reader["TenantName"].ToString()!;
                var token = _tokenService.GenerateToken(email, role, tenantId);

                return Ok(new
                {
                    message = "Login successful",
                    token = token,
                    role = role,
                    email = email,
                    tenantId = tenantId,
                    tenantName = tenantName
                });
            }

            return Unauthorized(new { message = "Invalid credentials or wrong tenant" });
        }
    }
}*/










/*using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Models;
using MultiTenantAuthSystem.Services;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DatabaseHelper _databaseHelper;
        private readonly TokenService _tokenService;

        public AuthController(DatabaseHelper databaseHelper, TokenService tokenService)
        {
            _databaseHelper = databaseHelper;
            _tokenService = tokenService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            string query = "SELECT Id, Email, Role FROM Users WHERE Email = @Email AND PasswordHash = @Password";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Email", request.Email);
            command.Parameters.AddWithValue("@Password", request.Password);

            using var reader = command.ExecuteReader();

            if (reader.Read())
            {
                var email = reader["Email"].ToString()!;
                var role = reader["Role"].ToString()!;
                var token = _tokenService.GenerateToken(email, role);

                return Ok(new
                {
                    message = "Login successful",
                    token = token,
                    role = role,
                    email = email
                });
            }

            return Unauthorized(new { message = "Invalid credentials" });
        }
    }
}*/


/*using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Models;

namespace MultiTenantAuthSystem.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DatabaseHelper _databaseHelper;

        public AuthController(DatabaseHelper databaseHelper)
        {
            _databaseHelper = databaseHelper;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            using var connection = _databaseHelper.GetConnection();
            connection.Open();

            string query = "SELECT Id, Email, Role FROM Users WHERE Email = @Email AND PasswordHash = @Password";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Email", request.Email);
            command.Parameters.AddWithValue("@Password", request.Password);

            using var reader = command.ExecuteReader();

            if (reader.Read())
            {
                return Ok(new
                {
                    message = "Login successful",
                    role = reader["Role"].ToString(),
                    email = reader["Email"].ToString()
                });
            }

            return Unauthorized(new { message = "Invalid credentials" });
        }
    }
}*/
