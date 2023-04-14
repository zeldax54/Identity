using Identity.Models;
using Identity.Models.Messages;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Data;

namespace Identity.Bussiness
{
    public interface IIdentityUserManager
    { 
        Task<string> Register(string name,string lastname,string email,string password);
        Task<UserManagerResult> LogIn(string email,string password);
    }
    public class IdentityUserManager : IIdentityUserManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<IdentityUserManager> _logger;
        private readonly SignInManager<ApplicationUser> _signInManager;
       
        public IdentityUserManager(UserManager<ApplicationUser> userManager, ILogger<IdentityUserManager> logger, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _logger = logger;
            _signInManager = signInManager;
        }

        public async Task<string> Register(string name, string lastname, string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)            
               return IdentityMessages.EmailExist;
            
            var applicationUser = new ApplicationUser()
            {
                Name = name,
                LastName = lastname,
                Email = email,
                Isactive = false,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = email.Split('@')[0],
                EmailConfirmed = false,
            };
            var result = await _userManager.CreateAsync(applicationUser,password);
            if (!result.Succeeded) {
                _logger.LogError(string.Join(Environment.NewLine, result.Errors));
                return IdentityMessages.UserCreationFail;
            }
            //  _roleManager.
            var userRole = Enum.GetName(Roles.User);
            await _userManager.AddToRoleAsync(applicationUser, userRole);
            return IdentityMessages.UserCreated;               
        }

        public async Task<UserManagerResult> LogIn(string email,string password)
        {
            UserManagerResult result = new UserManagerResult();
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                result.ResultCode = 0;
                result.ResultMessage = IdentityMessages.WrongCredentials;
            }          
            else if (await _userManager.CheckPasswordAsync(user, password)) 
            {
                await _signInManager.PasswordSignInAsync(user, password, false, false);
                result.ResultCode = 1;
                result.ResultMessage = IdentityMessages.LogInCorrect;
            }
            return result;
        }
    }
}
