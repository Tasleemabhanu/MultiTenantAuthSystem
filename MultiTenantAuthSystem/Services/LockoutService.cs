using Microsoft.Data.SqlClient;
using MultiTenantAuthSystem.Data;
using MultiTenantAuthSystem.Models;

namespace MultiTenantAuthSystem.Services
{
    public class LockoutService
    {
        private readonly DatabaseHelper _databaseHelper;
        private readonly LockoutSettings _settings;

        public LockoutService(DatabaseHelper databaseHelper, IConfiguration configuration)
        {
            _databaseHelper = databaseHelper;
            _settings = configuration
                .GetSection("LockoutSettings")
                .Get<LockoutSettings>() ?? new LockoutSettings();
        }

        // Returns null if not locked, or a message if locked
        public string? CheckLockout(SqlConnection connection, int userId)
        {
            string query = @"SELECT FailedLoginAttempts, LastFailedAttempt, LockoutEndTime
                             FROM Users
                             WHERE Id = @UserId";

            using var cmd = new SqlCommand(query, connection);
            cmd.Parameters.AddWithValue("@UserId", userId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            var lockoutEnd = reader["LockoutEndTime"] as DateTime?;
            var attempts = Convert.ToInt32(reader["FailedLoginAttempts"]);
            var lastFailed = reader["LastFailedAttempt"] as DateTime?;

            reader.Close();

            // Still within lockout period
            if (lockoutEnd.HasValue && lockoutEnd.Value > DateTime.Now)
            {
                var remaining = (int)Math.Ceiling((lockoutEnd.Value - DateTime.Now).TotalMinutes);
                return $"Account is locked. Try again in {remaining} minute(s).";
            }

            // Lockout period has passed — reset the counter automatically
            if (lockoutEnd.HasValue && lockoutEnd.Value <= DateTime.Now)
            {
                ResetFailedAttempts(connection, userId);
                return null;
            }

            // Attempts window has expired — reset counter
            if (lastFailed.HasValue &&
                (DateTime.Now - lastFailed.Value).TotalMinutes > _settings.AttemptWindowMinutes)
            {
                ResetFailedAttempts(connection, userId);
                return null;
            }

            return null;
        }

        // Call this on every failed login
        public void RecordFailedAttempt(SqlConnection connection, int userId)
        {
            // First get current attempt count
            string selectQuery = @"SELECT FailedLoginAttempts, LastFailedAttempt
                                   FROM Users WHERE Id = @UserId";

            int currentAttempts;
            DateTime? lastFailed;

            using (var cmd = new SqlCommand(selectQuery, connection))
            {
                cmd.Parameters.AddWithValue("@UserId", userId);
                using var reader = cmd.ExecuteReader();
                reader.Read();
                currentAttempts = Convert.ToInt32(reader["FailedLoginAttempts"]);
                lastFailed = reader["LastFailedAttempt"] as DateTime?;
                reader.Close();
            }

            // If last failed attempt was outside the window, reset to 1
            if (lastFailed.HasValue &&
                (DateTime.Now - lastFailed.Value).TotalMinutes > _settings.AttemptWindowMinutes)
            {
                currentAttempts = 0;
            }

            int newAttempts = currentAttempts + 1;

            // Lock the account if max attempts reached
            DateTime? lockoutEnd = null;
            if (newAttempts >= _settings.MaxFailedAttempts)
                lockoutEnd = DateTime.Now.AddMinutes(_settings.LockoutDurationMinutes);

            string updateQuery = @"UPDATE Users
                                   SET FailedLoginAttempts = @Attempts,
                                       LastFailedAttempt   = @LastFailed,
                                       LockoutEndTime      = @LockoutEnd
                                   WHERE Id = @UserId";

            using (var cmd = new SqlCommand(updateQuery, connection))
            {
                cmd.Parameters.AddWithValue("@Attempts", newAttempts);
                cmd.Parameters.AddWithValue("@LastFailed", DateTime.Now);
                cmd.Parameters.AddWithValue("@LockoutEnd", (object?)lockoutEnd ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.ExecuteNonQuery();
            }
        }

        // Call this on successful login
        public void ResetFailedAttempts(SqlConnection connection, int userId)
        {
            string query = @"UPDATE Users
                             SET FailedLoginAttempts = 0,
                                 LastFailedAttempt   = NULL,
                                 LockoutEndTime      = NULL
                             WHERE Id = @UserId";

            using var cmd = new SqlCommand(query, connection);
            cmd.Parameters.AddWithValue("@UserId", userId);
            cmd.ExecuteNonQuery();
        }
    }
}