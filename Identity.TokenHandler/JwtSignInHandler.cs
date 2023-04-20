using Identity.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Identity.TokenHandler
{
    public interface IJwtSignInHandler 
    {
        Task<string> BuildJwt(ClaimsPrincipal principal, string tokenIssuer, string tokenAudience);
        Task<bool> validate(string token, string tokenIssuer, string tokenAudience, string role);
        Task<UserInfo> UserInfo(string token, string tokenIssuer, string tokenAudience);
    }
    public class JwtSignInHandler : IJwtSignInHandler    {
 
        private readonly SymmetricSecurityKey key;  

        public JwtSignInHandler(SymmetricSecurityKey symmetricKey)
        {
            this.key = symmetricKey;            
        }

        public async Task<string> BuildJwt(ClaimsPrincipal principal,string tokenIssuer,string tokenAudience)
        {
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: tokenIssuer,
                audience: tokenAudience,
                claims: principal.Claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
            );
            return await Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));         
        }

        public async Task<bool> validate(string token, string tokenIssuer, string tokenAudience,string role)
        {            
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters
            {                
                IssuerSigningKey = key,
                ValidIssuer = tokenIssuer,
                ValidAudience = tokenAudience,
                ClockSkew = TimeSpan.Zero
            };
            SecurityToken validatedToken;
            var claimsPrincipal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                //Just in case I want to validate if user exist and is valid
                //var userId = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;                
                var roles = jwtSecurityToken.Claims.Where(c => c.Type == ClaimTypes.Role)?.Select(c => c.Value);            
                return await Task.FromResult((roles != null && roles.Contains(role)));            
            }
           
            return await Task.FromResult(false);
        }

        public async Task<UserInfo> UserInfo(string token, string tokenIssuer, string tokenAudience)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = key,
                ValidIssuer = tokenIssuer,
                ValidAudience = tokenAudience,
                ClockSkew = TimeSpan.Zero
            };
            SecurityToken validatedToken;
            var claimsPrincipal = tokenHandler.ValidateToken(token, tokenValidationParameters, out validatedToken);
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                
                var userId = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;                
                var username = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                return await Task.FromResult(new Models.UserInfo() { 
                UserId = userId,
                UserName = username
                });
            }
            return await Task.FromResult(new UserInfo());
        }

       
    }
}
