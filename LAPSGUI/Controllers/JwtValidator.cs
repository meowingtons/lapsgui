using Jose;
using LAPSAPI.Models;
using Newtonsoft.Json;
using System;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LAPSAPI.Controllers
{
    public class JwtValidator
    {
        private readonly IConfiguration _configuration;

        public JwtValidator(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public bool Validate(string token)
        {
            JwtToken decodedToken = DecodeToken(token);

            if (decodedToken.exp < DateTimeOffset.Now.ToUnixTimeSeconds())
            {
                throw new UnauthorizedAccessException("Token is expired");
            }

            if (decodedToken.aud != _configuration["TokenAudienceURI"])
            {
                throw new UnauthorizedAccessException("TokenAudienceURI does not match");
            }

            if (decodedToken.iss != _configuration["TokenIssuerURI"])
            {
                throw new UnauthorizedAccessException("TokenIssuerURI does not match");
            }

            if (decodedToken.email == null || decodedToken.email == "")
            {
                throw new Exception("UPN claim is not present");
            }

            return true;
        }

        public JwtToken DecodeToken(string token)
        {
            try
            {
                var publicKey = new X509Certificate2(_configuration["TokenSigningCertificatePath"]).PublicKey.Key as RSACryptoServiceProvider;
                string verifiedToken = JWT.Decode(token, publicKey);
                JwtToken decodedToken = JsonConvert.DeserializeObject<JwtToken>(verifiedToken);

                return decodedToken;
            }

            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
