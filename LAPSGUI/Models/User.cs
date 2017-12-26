using System;
using System.Collections.Generic;
using Nancy.Security;

namespace LAPSAPI.Models
{
    public class User : IUserIdentity
    {
        private readonly JwtToken jwtToken;

        public User(JwtToken token)
        {
            this.jwtToken = token;
        }

        public string UserName { get { return jwtToken.email; } }

        public IEnumerable<string> Claims => throw new NotImplementedException();
    }
}
