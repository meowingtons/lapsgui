using Nancy;
using Nancy.Extensions;
using Nancy.Security;
using Newtonsoft.Json;
using System;
using System.Dynamic;
using Microsoft.Extensions.Configuration;

namespace LAPSAPI
{
    public class LAPSModule : NancyModule
    {
        IConfiguration _configuration;

        public LAPSModule(IConfiguration configuration)
        {
            _configuration = configuration;

            //this.RequiresHttps();
            this.RequiresAuthentication();

            LdapConnection ldap = new LdapConnection(_configuration["LDAPServerHostname"], _configuration["LDAPBaseContext"], _configuration["LDAPBindPassword"], _configuration["LDAPBindUsername"]);

            Get["/api/computer/{ComputerName:maxlength(16)}/password"] = parameters => JsonConvert.SerializeObject(ldap.GetLocalAdminPassword(parameters.ComputerName));

            Get["/api/computer/{ComputerName:maxlength(16)}/expiration"] = parameters => JsonConvert.SerializeObject(ldap.GetLocalAdminExpirationDateUTC(parameters.ComputerName));

            Get["/api/computer/{ComputerName:maxlength(16)}/history"] = parameters => JsonConvert.SerializeObject(ldap.GetLocalAdminPasswordHistory(parameters.ComputerName));

            Get["/api/report/blankpasswords"] = _ => JsonConvert.SerializeObject(ldap.GetBlankLocalAdminPasswords());

            Patch["/api/computer/{ComputerName:maxlength(16)}/expiration"] = parameters =>
            {
                try
                {
                    dynamic obj = JsonConvert.DeserializeObject<ExpandoObject>(Request.Body.AsString());
                    DateTime newExpirationTime = Convert.ToDateTime(obj.newExpirationTime);
                    ldap.SetLocalAdminPasswordExpiration(parameters.ComputerName, newExpirationTime);
                    return obj.newExpirationTime;
                }

                catch
                {
                    return 500;
                }
            };

            Patch["/api/computer/{ComputerName:maxlength(16)}/forceexpiration"] = parameters =>
            {
                try
                {
                    ldap.SetLocalAdminPasswordToExpired(parameters.ComputerName);
                    return 200;
                }

                catch (Exception ex)
                {
                    return ex.Message;
                }
            };
        }
    }
}
