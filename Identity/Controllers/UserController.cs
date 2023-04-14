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
        public async Task<ActionResult<IdentityResponse<string>>> Register(string name, string lastname, string email, string password)
        {
            var result =  await _identityUserManager.Register(name,lastname,email,password);
            return Ok( new IdentityResponse<string>() { Data = result,StatusCode = 200,Success = true });
        }
    }
}
