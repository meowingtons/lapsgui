using System.Collections.Generic;

namespace LAPSAPI.Models
{
    public class PasswordHistory
    {
        public string ComputerName { get; set; }
        public List<string> Passwords = new List<string>();
    }
}
