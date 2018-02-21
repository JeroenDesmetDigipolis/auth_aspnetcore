using Digipolis.Auth.Options;
using Digipolis.Auth.PDP;
using Moq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Digipolis.Auth.UnitTests.PDP
{
    public class PermissionsClaimsTransformerTests
    {
        private readonly AuthOptions _authOptions;
        private readonly string _userId = "user123";
        private readonly string _profileType = "mprofile";
        private readonly string _profileId = "123456789";

        public PermissionsClaimsTransformerTests()
        {
            _authOptions = new AuthOptions
            {
                ApplicationName = "APP"
            };
        }

        [Fact]
        public void ThrowsExceptionIfOptionsWrapperIsNull()
        {
            Assert.Throws<ArgumentNullException>(() => new PermissionsClaimsTransformer(null, Mock.Of<IPolicyDescisionProvider>()));
        }

        [Fact]
        public void ThrowsExceptionIfOptionsAreNull()
        {
            Assert.Throws<ArgumentNullException>(() => new PermissionsClaimsTransformer(Options.Create<AuthOptions>(null), 
                Mock.Of<IPolicyDescisionProvider>()));
        }

        [Fact]
        public void ThrowsExceptionIfPolicyDescisionProviderIsNull()
        {
            Assert.Throws<ArgumentNullException>(() => new PermissionsClaimsTransformer(Options.Create(new AuthOptions()),
               null));
        }

        [Fact]
        public async Task UseProfileIdWhenAvailable()
        {
            var pdpResponse = new PdpResponse
            {
                applicationId = _authOptions.ApplicationName,
                permissions = new List<String>(new string[] { "permission1", "permission2" })
            };

            var pdpProvider = CreateMockPolicyDescisionProvider(pdpResponse);

            var transformer = new PermissionsClaimsTransformer(Options.Create(_authOptions), pdpProvider.Object);
            var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] 
            {
                new Claim(Claims.Name, _userId),
                new Claim(ClaimTypes.Name, _userId),
                new Claim(Claims.ProfileType, _profileType),
                new Claim(Claims.ProfileId, _profileId),
            }, "Bearer"));

            var result = await transformer.TransformAsync(user);

            Assert.NotNull(result);
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission1"));
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission2"));
            pdpProvider.Verify(m => m.GetPermissionsAsync(_profileType, _profileId, _authOptions.ApplicationName), Times.Once);
            pdpProvider.Verify(m => m.GetPermissionsAsync(_userId, _authOptions.ApplicationName), Times.Never);
        }

        public async Task UseUserIdWhenProfileIdIsNull()
        {
            var pdpResponse = new PdpResponse
            {
                applicationId = _authOptions.ApplicationName,
                permissions = new List<String>(new string[] { "permission1", "permission2" })
            };

            var pdpProvider = CreateMockPolicyDescisionProvider(pdpResponse);

            var transformer = new PermissionsClaimsTransformer(Options.Create(_authOptions), pdpProvider.Object);
            var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
            {
                new Claim(Claims.Name, _userId),
                new Claim(ClaimTypes.Name, _userId),
                new Claim(Claims.ProfileType, null),
                new Claim(Claims.ProfileId, null),
            }, "Bearer"));

            var result = await transformer.TransformAsync(user);

            Assert.NotNull(result);
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission1"));
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission2"));
            pdpProvider.Verify(m => m.GetPermissionsAsync(_profileType, _profileId, _authOptions.ApplicationName), Times.Never);
            pdpProvider.Verify(m => m.GetPermissionsAsync(_userId, _authOptions.ApplicationName), Times.Once);
        }

        [Fact]
        public async Task SetClaims()
        {
            var pdpResponse = new PdpResponse
            {
                applicationId = _authOptions.ApplicationName,
                userId = _userId,
                permissions = new List<String>(new string[] { "permission1", "permission2" })
            };

            var pdpProvider = CreateMockPolicyDescisionProvider(pdpResponse);

            var transformer = new PermissionsClaimsTransformer(Options.Create(_authOptions), pdpProvider.Object);
            var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim(Claims.Name, _userId), new Claim(ClaimTypes.Name, _userId) }, "Bearer"));

            var result = await transformer.TransformAsync(user);

            Assert.NotNull(result);
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission1"));
            Assert.True(result.HasClaim(Claims.PermissionsType, "permission2"));
        }

        [Fact]
        public async Task DoesNothingWhenNoPermissionsReturned()
        {
            var pdpResponse = new PdpResponse
            {
                applicationId = _authOptions.ApplicationName,
                userId = _userId,
            };

            var pdpProvider = CreateMockPolicyDescisionProvider(pdpResponse);

            var transformer = new PermissionsClaimsTransformer(Options.Create(_authOptions), pdpProvider.Object);
            var user = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim(Claims.Name, _userId), new Claim(ClaimTypes.Name, _userId) }, "Bearer"));

            var result = await transformer.TransformAsync(user);

            Assert.NotNull(result);
            Assert.False(result.HasClaim(c => c.Type == Claims.PermissionsType));
        }

        private Mock<IPolicyDescisionProvider> CreateMockPolicyDescisionProvider(PdpResponse pdpResponse)
        {
            var mockPdpProvider = new Mock<IPolicyDescisionProvider>();
            mockPdpProvider.Setup(p => p.GetPermissionsAsync(_userId, _authOptions.ApplicationName))
                .ReturnsAsync(pdpResponse);

            mockPdpProvider.Setup(p => p.GetPermissionsAsync(_profileType, _profileId, _authOptions.ApplicationName))
                .ReturnsAsync(pdpResponse);

            return mockPdpProvider;
        }

    }
}
