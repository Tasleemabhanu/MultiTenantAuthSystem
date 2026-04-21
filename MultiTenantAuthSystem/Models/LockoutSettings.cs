namespace MultiTenantAuthSystem.Models
{
    public class LockoutSettings
    {
        public int MaxFailedAttempts { get; set; } = 5;
        public int LockoutDurationMinutes { get; set; } = 15;
        public int AttemptWindowMinutes { get; set; } = 15;
    }
}