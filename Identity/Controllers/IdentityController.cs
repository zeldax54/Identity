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
        private readonly string? _issuer;

        public IdentityController(IJwtSignInHandler tokenFactory, IConfiguration configuration, ILogger<IdentityController> logger) 
        {
            _tokenFactory = tokenFactory;
            _configuration = configuration;
            _logger = logger;
            _issuer = _configuration["TokenIssuer"];
        }

        [HttpPost("Tokenvalidate")]
        [AllowAnonymous]
        public async Task<IdentityResponse<bool>> Tokenvalidate([FromBody]TokenRequest request) 
        {
            try
            {               
                string? token = request.Token.Replace("Bearer ", "");
                _logger.LogInformation($"Validation try for token {token}");                
                string? audience = request.Role == Enum.GetName(Roles.Admin) ? _configuration["AdminAudience"] : _configuration["ClientAudience"];
                var valid = await _tokenFactory.validate(token, _issuer, audience, request.Role);
                _logger.LogInformation($"{valid} validation result for token");  
                return new IdentityResponse<bool> { Data = valid,StatusCode = 200,Success = true };               
            }
            catch (Exception e)
            {
                _logger.LogError($"TokenRefresh error. {e.Message}");
                return new IdentityResponse<bool> { Data = false, StatusCode = 500, Success = false };
            }                   
        }


        [HttpPost("Tokenrefresh")]
        [Authorize("Bearer", Roles = "Admin,User")]
        public async Task<IdentityResponse<string>> TokenRefresh([FromBody] TokenRequest request)
        {
            try
            {
                var claimPrincipal = HttpContext.User;
                string? audience = request.Role == Enum.GetName(Roles.Admin) ? _configuration["AdminAudience"] : _configuration["ClientAudience"];
                string token = await _tokenFactory.RefreshToken(claimPrincipal, request.Token, _issuer, audience, request.Role);
                _logger.LogInformation($"Token refreshed for {claimPrincipal.Claims.First(c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier).Value}");
                return new IdentityResponse<string> { Data = token, StatusCode = 200, Success = true };
            }
            catch (Exception e)
            {
                _logger.LogError($"TokenRefresh error. {e.Message}");
                return new IdentityResponse<string> { Data = "", StatusCode = 500, Success = false };
            }
        }

    }
}
