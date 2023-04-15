using Identity.Bussiness;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace Identity.Controllers
{
    [AllowAnonymous]
    [Route("[controller]")]
    public class UserController : ControllerBase    
    {
        private readonly IIdentityUserManager _identityUserManager;

        public UserController(IIdentityUserManager identityUserManager) 
        {
            _identityUserManager = identityUserManager;
        }

        [HttpGet("register")]
        public async Task<ActionResult<IdentityResponse<string>>> Register([FromQuery] RegisterRequest request)
        {
            var result = await _identityUserManager.Register(request.Name, request.LastName, request.Email, request.Password);
            return Ok(result);
        }

        [HttpGet("login")]
        public async Task<ActionResult<IdentityResponse<string>>> Login([FromQuery] RegisterRequest request)
        {
            var result = await _identityUserManager.Register(request.Name, request.LastName, request.Email, request.Password);
            return Ok(result);
        }
    }
}
