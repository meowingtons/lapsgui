using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LAPSAPI.Models
{
    public class JwtToken
    {
        public string sub;
        public long exp;
        public string iss;
        public string aud;
        public string upn;
        public string email;
    }
}
