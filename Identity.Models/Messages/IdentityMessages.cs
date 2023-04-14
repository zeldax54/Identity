using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Models.Messages
{
    public static class IdentityMessages
    {
        public const string EmailExist = "Email already exist";
        public const string UserCreationFail = "Something went wrong. User creation fail";
        public const string UserCreated = "User Created!";
        public const string WrongCredentials = "Wrong credential";
        public const string LogInCorrect = "Log In Successfully";
    }
}
