﻿using Identity.Models;
using Identity.Models.Messages;
using Identity.TokenHandler;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Identity.Bussiness
{
    public interface IIdentityUserManager
    { 
        Task<IdentityResponse<string>> Register(string name,string lastname,string email,string password);
        Task<IdentityResponse<Tuple<string, string>>> LogIn(string email,string password);
        Task LogOff();
        Task<UserInfo> UserInfo(string token, string issuer, string audience);
    }
    public class IdentityUserManager : IIdentityUserManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<IdentityUserManager> _logger;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IJwtSignInHandler _tokenFactory;
        IUserClaimsPrincipalFactory<ApplicationUser> _claimsFactory;
        IConfiguration _configuration;


        public IdentityUserManager(UserManager<ApplicationUser> userManager, ILogger<IdentityUserManager> logger, SignInManager<ApplicationUser> signInManager, 
            IJwtSignInHandler tokenFactor, IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory, IConfiguration configuration)
        {
            _userManager = userManager;
            _logger = logger;
            _signInManager = signInManager;
            _tokenFactory = tokenFactor;
            _claimsFactory = claimsFactory;
            _configuration = configuration;
        }

        public async Task<IdentityResponse<string>> Register(string name, string lastname, string email, string password)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                var registerResult = new IdentityResponse<string>();
               
                if (user != null) 
                {
                    registerResult.Success = false;
                    registerResult.ErrorMessage = IdentityMessages.EmailExist;
                    registerResult.StatusCode = 400;              
                    return registerResult;
                }                 

                var applicationUser = new ApplicationUser()
                {
                    Name = name,
                    LastName = lastname,
                    Email = email,
                    Isactive = true,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = email.Split('@')[0],
                    EmailConfirmed = false,
                };

                var result = await _userManager.CreateAsync(applicationUser, password);
                if (!result.Succeeded)
                {
                    _logger.LogError(string.Join(Environment.NewLine, result.Errors));
                    registerResult.Success = false;
                    registerResult.ErrorMessage = IdentityMessages.UserCreationFail;
                    registerResult.StatusCode = 400;
                    return registerResult;
                }
               
                var userRole = Enum.GetName(Roles.User);
                await _userManager.AddToRoleAsync(applicationUser, userRole);
                registerResult.Success = true;
                registerResult.Data = IdentityMessages.UserCreated;
                registerResult.StatusCode = 200;
              
                return registerResult;
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
                var registerResult = new IdentityResponse<string>();
                registerResult.Success = false;
                registerResult.ErrorMessage = IdentityMessages.UserCreationFail;
                registerResult.StatusCode = 400;
                return registerResult;
            }           
        }

        public async Task<IdentityResponse<Tuple<string, string>>> LogIn(string email,string password)
        {
            try
            {
                var loginresult = new IdentityResponse<Tuple<string,string>>();
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    loginresult.StatusCode = 400;
                    loginresult.ErrorMessage = IdentityMessages.WrongCredentials;
                }
                else if (await _userManager.CheckPasswordAsync(user, password))
                {
                    _logger.LogInformation($"Login user {email}. {DateTime.UtcNow}");
                    //cookie stuff
                    await _signInManager.PasswordSignInAsync(user, password, true, false);
                    var principal = await _claimsFactory.CreateAsync(user);

                    /* var nuevaClaim = new Claim("callerRight", "");
                     ((ClaimsIdentity)principal.Identity).AddClaim(nuevaClaim);*/

                    loginresult.StatusCode = 200;

                    var adminRole = principal.Claims.Where(c => c.Type == ClaimTypes.Role)?.Select(c => c.Value);
                   
                    string? audience = (adminRole!= null && adminRole.Contains("Admin"))
                        ? _configuration["AdminAudience"] : _configuration["ClientAudience"];

                    string? issuer = _configuration["TokenIssuer"];
                    string token = await _tokenFactory.BuildJwt(principal, issuer, audience);
                    Tuple<string, string> t = Tuple.Create(token,user.Id);                   
                    loginresult.Data = t;
                    return loginresult;
                }
                else
                {
                    loginresult.StatusCode = 400;
                    loginresult.ErrorMessage = IdentityMessages.WrongCredentials;
                }
                return loginresult;
            }
            catch (Exception e)
            {
                _logger.LogError(e.Message);
                var loginresult = new IdentityResponse<Tuple<string,string>>();
                loginresult.Success = false;
                loginresult.ErrorMessage = IdentityMessages.WrongCredentials;
                loginresult.StatusCode = 400;
                return loginresult;
            }
        }

        public async Task LogOff()
        {
            await _signInManager.SignOutAsync(); 
        }

        public async Task<UserInfo> UserInfo(string token,string issuer,string audience)
        {
            return await _tokenFactory.UserInfo(token, issuer, audience);
        }
    }
}
