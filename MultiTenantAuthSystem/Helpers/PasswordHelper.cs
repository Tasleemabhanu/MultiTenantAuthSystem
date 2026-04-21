using System.Security.Cryptography;
using System.Text;

namespace MultiTenantAuthSystem.Helpers
{
    public static class PasswordHelper
    {
        public static string GenerateSalt()
        {
            var saltBytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(saltBytes);
        }

        public static string HashPassword(string password, string salt)
        {
            var combined = salt + password;
            var bytes = Encoding.UTF8.GetBytes(combined);
            var hash = SHA256.HashData(bytes);
            return Convert.ToHexString(hash).ToLower();
        }

        public static bool VerifyPassword(string passwordAttempt, string storedSalt, string storedHash)
        {
            var hash = HashPassword(passwordAttempt, storedSalt);
            return hash == storedHash;
        }
    }
}