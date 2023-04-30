using Azure.Core;
using Identity.Bussiness;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace Identity.Controllers
{
    
    [Route("[controller]")]
    public class UserController : ControllerBase    
    {
        private readonly IConfiguration _configuration;
        private readonly IIdentityUserManager _identityUserManager;

        public UserController(IIdentityUserManager identityUserManager, IConfiguration configuration) 
        {
            _identityUserManager = identityUserManager;
            _configuration = configuration;
        }
      
        [AllowAnonymous]
        [HttpGet("register")]
        public async Task<ActionResult<IdentityResponse<string>>> Register([FromQuery] RegisterRequest request)
        {
            var result = await _identityUserManager.Register(request.Name, request.LastName, request.Email, request.Password);
            return Ok(result);
        }
        [AllowAnonymous]
        [HttpGet("login")]
        public async Task<IActionResult> Login([FromQuery] RegisterRequest request)
        {
            var result = await _identityUserManager.LogIn(request.Email, request.Password);
            return Ok(result);
        }

        [Authorize("Bearer",Roles = "Admin")]
        [HttpGet("UserInfo")]
        public async Task<IdentityResponse<UserInfo>> UserInfo()
        {
            string token = Request.Headers["Authorization"].ToString()?.Replace("Bearer ", "");
            string? issuer = _configuration["TokenIssuer"];
            string? audience = _configuration["AdminAudience"];
            var info = await _identityUserManager.UserInfo(token,issuer, audience);
            return new IdentityResponse<UserInfo> { Data = info, StatusCode = 200, Success = true };
        }
    }
}
