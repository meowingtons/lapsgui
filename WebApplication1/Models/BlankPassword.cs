using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LAPSAPI.Models
{
    public class BlankPassword
    {
        public string ComputerName { get; set; }
        public string OrganizationalUnit { get; set; }
        public string WhenCreated { get; set; }
    }

    public class BlankPasswordReport
    {
        public List<BlankPassword> ComputerNames = new List<BlankPassword>();
    }
}
