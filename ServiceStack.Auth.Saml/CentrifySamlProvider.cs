using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ServiceStack.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace ServiceStack.Auth.Saml
{
    public class CentrifySamlProvider : SamlAuthProvider
    {
        public const string Name = "centrifysaml";
        public const string Realm = "/auth/centrifysaml";

        public CentrifySamlProvider(IAppSettings appSettings, X509Certificate2 signingCert)
            : base(appSettings, Realm, Name, signingCert)
        {

        }
        protected override Dictionary<string, string> CreateAuthInfo(SamlResponseAttributes attributes)
        {
            var authInfo = new Dictionary<string, string>
            {
                { "user_id", attributes.NameID },
                { "secondary_id", attributes.Attributes.GetValueOrDefault("Employee Id") },
                { "username", attributes.Attributes.GetValueOrDefault("Login") },
                { "email", attributes.Attributes.GetValueOrDefault("Email") },
                { "department", attributes.Attributes.GetValueOrDefault("Department") },
                { "name", attributes.Attributes.GetValueOrDefault("Full Name") },
                { "first_name", attributes.Attributes.GetValueOrDefault("First Name") },
                { "last_name", attributes.Attributes.GetValueOrDefault("Last Name") }
            };
            return authInfo;
        }       
    }
}
