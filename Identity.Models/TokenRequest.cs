using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Models
{
    public class TokenRequest
    {
        public string Role { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
    }
}
