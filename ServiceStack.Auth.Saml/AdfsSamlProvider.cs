using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using ServiceStack.Configuration;

namespace ServiceStack.Auth.Saml
{
    public class AdfsSamlProvider : SamlAuthProvider
    {
        public const string Name = "adfssaml";
        public const string Realm = "/auth/adfssaml";
        protected Func<SamlResponseAttributes, Dictionary<string, string>> _responseParser;

        public AdfsSamlProvider(IAppSettings appSettings, X509Certificate2 signingCert, Func<SamlResponseAttributes, Dictionary<string, string>> responseParser)
            : base(appSettings, Realm, Name, signingCert)
        {
            if (responseParser == null)
            {
                throw new ArgumentException("SAML Response Parser function required");
            }
            _responseParser = responseParser;

        }
        protected override Dictionary<string, string> CreateAuthInfo(SamlResponseAttributes attributes)
        {

            var authInfo = _responseParser(attributes);
            return authInfo;
        }
    }
}
