using FluentAssertions;
using MultiTenantAuthSystem.Models;

namespace MultiTenantAuthSystem.Tests.Services
{
    public class LockoutServiceTests
    {
        // These tests verify the lockout settings model directly
        // Full LockoutService tests require a DB — covered by integration tests

        [Fact]
        public void LockoutSettings_DefaultValues_ShouldBeCorrect()
        {
            var settings = new LockoutSettings();

            settings.MaxFailedAttempts.Should().Be(5);
            settings.LockoutDurationMinutes.Should().Be(15);
            settings.AttemptWindowMinutes.Should().Be(15);
        }

        [Fact]
        public void LockoutSettings_CustomValues_ShouldBeSet()
        {
            var settings = new LockoutSettings
            {
                MaxFailedAttempts = 3,
                LockoutDurationMinutes = 30,
                AttemptWindowMinutes = 10
            };

            settings.MaxFailedAttempts.Should().Be(3);
            settings.LockoutDurationMinutes.Should().Be(30);
            settings.AttemptWindowMinutes.Should().Be(10);
        }

        [Fact]
        public void LockoutSettings_MaxAttempts_ShouldBePositive()
        {
            var settings = new LockoutSettings();

            settings.MaxFailedAttempts.Should().BePositive();
        }

        [Fact]
        public void LockoutSettings_LockoutDuration_ShouldBePositive()
        {
            var settings = new LockoutSettings();

            settings.LockoutDurationMinutes.Should().BePositive();
        }
    }
}