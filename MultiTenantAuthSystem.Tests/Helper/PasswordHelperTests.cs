using MultiTenantAuthSystem.Helpers;
using FluentAssertions;

namespace MultiTenantAuthSystem.Tests.Helpers
{
    public class PasswordHelperTests
    {
        // ── GenerateSalt ──────────────────────────────────────────────────────

        [Fact]
        public void GenerateSalt_ShouldReturnNonEmptyString()
        {
            var salt = PasswordHelper.GenerateSalt();

            salt.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void GenerateSalt_ShouldReturnDifferentSaltEachTime()
        {
            var salt1 = PasswordHelper.GenerateSalt();
            var salt2 = PasswordHelper.GenerateSalt();

            salt1.Should().NotBe(salt2);
        }

        [Fact]
        public void GenerateSalt_ShouldBeBase64Encoded()
        {
            var salt = PasswordHelper.GenerateSalt();

            // Should not throw — valid Base64
            var action = () => Convert.FromBase64String(salt);
            action.Should().NotThrow();
        }

        // ── HashPassword ──────────────────────────────────────────────────────

        [Fact]
        public void HashPassword_ShouldReturnNonEmptyString()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("MyPassword1", salt);

            hash.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void HashPassword_ShouldReturn64CharHexString()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("MyPassword1", salt);

            // SHA-256 always produces 64 hex characters
            hash.Should().HaveLength(64);
            hash.Should().MatchRegex("^[a-f0-9]+$");
        }

        [Fact]
        public void HashPassword_SameInputShouldProduceSameHash()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash1 = PasswordHelper.HashPassword("MyPassword1", salt);
            var hash2 = PasswordHelper.HashPassword("MyPassword1", salt);

            hash1.Should().Be(hash2);
        }

        [Fact]
        public void HashPassword_DifferentSaltsShouldProduceDifferentHashes()
        {
            var salt1 = PasswordHelper.GenerateSalt();
            var salt2 = PasswordHelper.GenerateSalt();
            var hash1 = PasswordHelper.HashPassword("MyPassword1", salt1);
            var hash2 = PasswordHelper.HashPassword("MyPassword1", salt2);

            // Same password, different salts → different hashes
            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void HashPassword_DifferentPasswordsShouldProduceDifferentHashes()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash1 = PasswordHelper.HashPassword("Password1", salt);
            var hash2 = PasswordHelper.HashPassword("Password2", salt);

            hash1.Should().NotBe(hash2);
        }

        // ── VerifyPassword ────────────────────────────────────────────────────

        [Fact]
        public void VerifyPassword_CorrectPasswordShouldReturnTrue()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("MyPassword1", salt);

            var result = PasswordHelper.VerifyPassword("MyPassword1", salt, hash);

            result.Should().BeTrue();
        }

        [Fact]
        public void VerifyPassword_WrongPasswordShouldReturnFalse()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("MyPassword1", salt);

            var result = PasswordHelper.VerifyPassword("WrongPassword1", salt, hash);

            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyPassword_WrongSaltShouldReturnFalse()
        {
            var salt = PasswordHelper.GenerateSalt();
            var wrongSalt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("MyPassword1", salt);

            var result = PasswordHelper.VerifyPassword("MyPassword1", wrongSalt, hash);

            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyPassword_CaseSensitive()
        {
            var salt = PasswordHelper.GenerateSalt();
            var hash = PasswordHelper.HashPassword("mypassword1", salt);

            var result = PasswordHelper.VerifyPassword("MYPASSWORD1", salt, hash);

            result.Should().BeFalse();
        }
    }
}