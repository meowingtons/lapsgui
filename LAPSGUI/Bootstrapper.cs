using Nancy;
using Nancy.Bootstrapper;
using Nancy.TinyIoc;
using Nancy.Authentication.Stateless;
using System;
using LAPSAPI.Models;
using LAPSAPI.Controllers;
using Microsoft.Extensions.Configuration;
using NLog.Config;
using NLog;
using NLog.Targets;

namespace LAPSAPI
{
    public class Bootstrapper : DefaultNancyBootstrapper
    {
        private readonly IConfiguration _config;

        public Bootstrapper(IConfiguration config)
        {
            _config = config;
        }

        protected override void ApplicationStartup(TinyIoCContainer container, IPipelines pipelines)
        {
            base.ApplicationStartup(container, pipelines);

            //configure the NLog stuff
            LoggingConfiguration logConfig = new LoggingConfiguration();
            FileTarget fileTarget = new FileTarget();
            fileTarget.FileName = "${basedir}/logFile.txt";
            logConfig.AddTarget("file", fileTarget);
            fileTarget.Layout = @"${date:format=MM-dd-yyyy_HH\:mm\:ss} | ${message}";

            var rule1 = new LoggingRule("*", LogLevel.Info, fileTarget);
            logConfig.LoggingRules.Add(rule1);

            LogManager.Configuration = logConfig;

            //create configuration with validation for JWT tokens for federated authentication
            StatelessAuthenticationConfiguration configuration = new StatelessAuthenticationConfiguration(ctx =>
            {
               if (string.IsNullOrEmpty(ctx.Request.Headers.Authorization))
               {
                   //Auth header doesn't exist or is null, so assume no user
                   return null;
               }

               try
               {
                   //validate the token is legit
                   var validator = new JwtValidator(_config);
                   bool result = validator.Validate(ctx.Request.Headers.Authorization);

                   //if token was validated successfully, return User object
                   if (result)
                   {
                       //return new User, passing the token in to populate the various claims
                       return new User(validator.DecodeToken(ctx.Request.Headers.Authorization));
                   }

                   //if we somehow get here, return null
                   return null;
               }
               catch (Exception ex)
               {
                    //something happened during the validation, so return null
                    //return null;
                    throw ex;
               }
            });

            StatelessAuthentication.Enable(pipelines, configuration);
        }

        protected override void ConfigureApplicationContainer(TinyIoCContainer container)
        {
            base.ConfigureApplicationContainer(container);
            container.Register(_config);
        }
    }
}
