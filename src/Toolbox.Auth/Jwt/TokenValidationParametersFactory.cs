﻿using System;
using System.IdentityModel.Tokens;
using Toolbox.Auth.Options;

namespace Toolbox.Auth.Jwt
{
    public class TokenValidationParametersFactory
    {
        public static TokenValidationParameters Create(AuthOptions authOptions, IJwtTokenSignatureValidator signatureValidator)
        {
            return new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidAudience = authOptions.JwtAudience,
                ValidateIssuer = true,
                ValidIssuer = authOptions.JwtIssuer,
                ValidateLifetime = true,
                ValidateSignature = String.IsNullOrWhiteSpace(authOptions.JwtSigningKeyProviderUrl) ? false : true,
                SignatureValidator = signatureValidator.SignatureValidator,
                ClockSkew = TimeSpan.FromMinutes(authOptions.JwtValidatorClockSkew),
                NameClaimType = "sub"
            };
        }
    }
}
