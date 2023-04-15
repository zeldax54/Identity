using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Models
{
    public class UserManagerResult
    {
        public int ResultCode { get; set; }
        public string ResultMessage { get; set; } = string.Empty;
        public bool Susscess { get; set; } = true;
    }
}
