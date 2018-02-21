﻿using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Digipolis.Auth.Options;
using System.Linq;

namespace Digipolis.Auth.PDP
{
    public class PolicyDescisionProvider : IPolicyDescisionProvider
    {
        private readonly IMemoryCache _cache;
        private readonly AuthOptions _options;
        private readonly MemoryCacheEntryOptions _cacheOptions;
        private readonly HttpClient _client;
        private readonly bool cachingEnabled;
        private readonly ILogger<PolicyDescisionProvider> _logger;

        public PolicyDescisionProvider(IMemoryCache cache, IOptions<AuthOptions> options, HttpMessageHandler handler, ILogger<PolicyDescisionProvider> logger)
        {
            if (cache == null) throw new ArgumentNullException(nameof(cache), $"{nameof(cache)} cannot be null");
            if (options == null || options.Value == null) throw new ArgumentNullException(nameof(options), $"{nameof(options)} cannot be null");
            if (handler == null) throw new ArgumentNullException(nameof(handler), $"{nameof(handler)} cannot be null");
            if (logger == null) throw new ArgumentNullException(nameof(logger), $"{nameof(logger)} cannot be null");

            _cache = cache;
            _options = options.Value;
            _client = new HttpClient(handler);
            _client.DefaultRequestHeaders.Add(HeaderKeys.Apikey, _options.PdpApiKey);
            _logger = logger;

            if (_options.PdpCacheDuration > 0)
            {
                cachingEnabled = true;
                _cacheOptions = new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = new TimeSpan(0, _options.PdpCacheDuration, 0) };
            }
        }

        public async Task<PdpResponse> GetPermissionsAsync(string user, string application)
        {
            PdpResponse pdpResponse = null;

            if (cachingEnabled)
            {
                pdpResponse = _cache.Get<PdpResponse>(BuildCacheKey(user));

                if (pdpResponse != null)
                    return pdpResponse;
            }

            var response = await _client.GetAsync($"{_options.PdpUrl}/applications/{application}/users/{user.Replace("@","%40")}/permissions");
            if (response.IsSuccessStatusCode)
            {
                pdpResponse = await response.Content.ReadAsAsync<PdpResponse>();
            }
            else
            {
                _logger.LogCritical($"Impossible to retreive permissions from {_options.PdpUrl} for {application} / {user}. Response status code: {response.StatusCode}");
            }

            if (cachingEnabled && (pdpResponse?.permissions.Any()).GetValueOrDefault())
                _cache.Set(BuildCacheKey(user), pdpResponse, _cacheOptions);

            return pdpResponse;
        }

        public async Task<PdpResponse> GetPermissionsAsync(string profileType, string profileId, string application)
        {
            PdpResponse pdpResponse = null;

            if (cachingEnabled)
            {
                pdpResponse = _cache.Get<PdpResponse>(BuildCacheKey($"{profileType}-{profileId}"));

                if (pdpResponse != null)
                    return pdpResponse;
            }

            var response = await _client.GetAsync($"{_options.PdpUrl}/applications/{application}/permissions?profileId={profileId}&profileType={profileType}");
            if (response.IsSuccessStatusCode)
            {
                pdpResponse = await response.Content.ReadAsAsync<PdpResponse>();
            }
            else
            {
                _logger.LogCritical($"Impossible to retreive permissions from {_options.PdpUrl} for {application} / {profileType} {profileId}. Response status code: {response.StatusCode}");
            }

            if (cachingEnabled && (pdpResponse?.permissions.Any()).GetValueOrDefault())
                _cache.Set(BuildCacheKey($"{profileType}-{profileId}"), pdpResponse, _cacheOptions);

            return pdpResponse;
        }

        private string BuildCacheKey(string user) => $"pdpResponse-{user}";
    }
}

    
