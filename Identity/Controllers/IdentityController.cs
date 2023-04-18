using Identity.Models;
using Identity.TokenHandler;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    [Route("[controller]")]  
    public class IdentityController : ControllerBase    
    {
        private readonly IJwtSignInHandler _tokenFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<IdentityController> _logger;
        public IdentityController(IJwtSignInHandler tokenFactory, IConfiguration configuration, ILogger<IdentityController> logger) 
        {
            _tokenFactory = tokenFactory;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpPost("Tokenvalidate")]
        [AllowAnonymous]
        public async Task<IdentityResponse<bool>> Tokenvalidate([FromBody]TokenRequest request) 
        {
            try
            {               
                string? token = request.Token.Replace("Bearer ", "");
                _logger.LogInformation($"validation try for token {token}");
                string? issuer = _configuration["TokenIssuer"];
                string? audience = request.Role == Enum.GetName(Roles.Admin) ? _configuration["AdminAudience"] : _configuration["ClientAudience"];
                var valid = await _tokenFactory.validate(token, issuer, audience, request.Role);
                _logger.LogInformation($"{valid} validation result for token");  
                return new IdentityResponse<bool> { Data = valid,StatusCode = 200,Success = true };   
              
            }
            catch (Exception)
            {
                return new IdentityResponse<bool> { Data = false, StatusCode = 200, Success = true };
            }
                   
        }

    }
}
