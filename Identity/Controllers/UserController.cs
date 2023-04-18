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
        private readonly IIdentityUserManager _identityUserManager;

        public UserController(IIdentityUserManager identityUserManager) 
        {
            _identityUserManager = identityUserManager;
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
        public async Task<ActionResult<IdentityResponse<string>>> Login([FromQuery] RegisterRequest request)
        {
            var result = await _identityUserManager.LogIn(request.Email, request.Password);
            return Ok(result);
        }

        [Authorize("Bearer",Roles = "Admin")]
        [HttpGet("logoff")]
        public async Task<ActionResult<IdentityResponse<string>>> LogOff()
        {
            var c = HttpContext;
             await _identityUserManager.LogOff();
            return Ok();
        }
    }
}
