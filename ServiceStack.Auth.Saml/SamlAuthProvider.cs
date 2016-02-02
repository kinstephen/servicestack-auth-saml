using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using ServiceStack.Auth;
using ServiceStack.Configuration;
using System.Linq;
using System.Xml;
using System.IO;
using ServiceStack.Logging;

namespace ServiceStack.Auth.Saml
{
    
    public abstract class SamlAuthProvider : AuthProvider
    {
        private ILog Logger = LogManager.GetLogger(typeof(SamlAuthProvider));

        public string AuthorizeUrl { get; set; }
        public string Issuer { get; set; }               
        public String SamlResponseFormKey { get; set; }
        public String LogoutUrl { get; set; }
        public X509Certificate2 SamlSigningCert { get; set; }

        public SamlAuthProvider(IAppSettings appSettings, string authRealm, string provider, X509Certificate2 signingCert)            
        {
            Logger.Info("SamlAuthProvider Starting up for Realm: {0}, Provider: {1}".Fmt(authRealm, provider));
            this.AuthRealm = appSettings != null ? appSettings.Get("SamlRealm", authRealm) : authRealm;
            this.Provider = provider;
            this.SamlSigningCert = signingCert;
            if(appSettings != null)
            {
                this.CallbackUrl = appSettings.GetString("saml.{0}.CallbackUrl".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.CallbackUrl"));
                this.RedirectUrl = appSettings.GetString("saml.{0}.RedirectUrl".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.RedirectUrl"));
                this.LogoutUrl = appSettings.GetString("saml.{0}.LogoutUrl".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.LogoutUrl"));
                this.Issuer = appSettings.GetString("saml.{0}.Issuer".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.Issuer"));
                this.AuthorizeUrl = appSettings.GetString("saml.{0}.AuthorizeUrl".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.AuthorizeUrl"));
                this.SamlResponseFormKey = appSettings.GetString("saml.{0}.ResponseFormKey".Fmt(provider)) ?? this.FallbackConfig(appSettings.GetString("saml.ResponseFormKey"));
                Logger.Info("Obtained the following settings from appSettings");
                Logger.Info(new
                {
                    this.CallbackUrl,
                    this.RedirectUrl,
                    this.LogoutUrl,
                    this.Issuer,
                    this.AuthorizeUrl,
                    this.SamlResponseFormKey
                }.ToJson());
            }

            
        }

        protected IAuthTokens Init(IServiceBase authService, ref IAuthSession session, Authenticate request)
        {
            Logger.Debug("SamlAuthProvider::Init:ENTER");
            if (this.CallbackUrl.IsNullOrEmpty())
            {
                this.CallbackUrl = authService.Request.AbsoluteUri;
                Logger.Debug("CallbackUrl was null, setting to: {0}".Fmt(this.CallbackUrl));
            }
                

            session.ReferrerUrl = GetReferrerUrl(authService, session, request);
            Logger.Debug("Session ReferrerUrl Set to: {0}".Fmt(session.ReferrerUrl));

            var tokens = session.ProviderOAuthAccess.FirstOrDefault(x => x.Provider == this.Provider);
            if (tokens == null)
            {
                Logger.Debug("Tokens were null, initializing");
                session.ProviderOAuthAccess.Add(tokens = new AuthTokens { Provider = this.Provider });                
            }
            Logger.Debug("Tokens contains");
            Logger.Debug(tokens.ToJson());
            Logger.Debug("SamlAuthProvider::Init:RETURN");
            return tokens;
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {
            Logger.Debug("SamlAuthProvider::Authenticate:ENTER");
            var tokens = this.Init(authService, ref session, request);

            if(authService.Request.Verb == "POST")
            {
                Logger.Debug("SamlAuthProvider received POST response");
                XmlDocument xDoc = this.ParseSamlResponse(authService.Request.FormData[this.SamlResponseFormKey]);
                if(this.IsResponseValid(xDoc))
                {
                    Logger.Debug("SAMLResponse Valid");
                    var attributes = this.ParseSamlResponseAttributes(xDoc);
                    Logger.Debug("Obtained SAMLResponse Attributes");
                    Logger.Debug(attributes.ToJson());
                    var authInfo = CreateAuthInfo(attributes);
                    Logger.Debug("Parsed SAMLResponse attributes");
                    Logger.Debug(authInfo.ToJson());
                    session.IsAuthenticated = true;
                    Logger.Debug("Session.IsAuthenticated = {0}".Fmt(session.IsAuthenticated));
                    Logger.Debug("SamlAuthProvider::Authenticate:RETURN OnAuthResponse");
                    return OnAuthenticated(authService, session, tokens, authInfo) ??
                        authService.Redirect(SuccessRedirectUrlFilter(this, session.ReferrerUrl));

                } else
                {
                    Logger.Debug("SAMLResponse Invalid");
                    Logger.Debug("SamlAuthProvider::Authenticate:RETURN FailedRedirect");
                    return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl));
                }
            } else
            {
                var redirectUrl = "{0}?SAMLRequest={1}".Fmt(this.AuthorizeUrl, this.CreateSamlRequest(this.CallbackUrl, this.Issuer).UrlEncode());
                Logger.Debug("SAML Authority RedirectUrl: {0}".Fmt(redirectUrl));
                var httpResult = new HttpResult
                {
                    StatusCode = System.Net.HttpStatusCode.TemporaryRedirect,
                    Location = redirectUrl
                };
                session.ReferrerUrl = authService.Request.QueryString["redirect"];
                Logger.Debug("Session.ReferrerUrl: {0}".Fmt(session.ReferrerUrl));
                authService.SaveSession(session, this.SessionExpiry);
                Logger.Debug("SamlAuthProvider::Authenticate:RETURN RedirectToAuthorize");
                return httpResult;
            }
        }

        public override bool IsAuthorized(IAuthSession session, IAuthTokens tokens, Authenticate request = null)
        {
            Logger.Debug("SamlAuthProvider::IsAuthorized:ENTER");
            if (request != null)
            {
                if (!LoginMatchesSession(session, request.UserName))
                {
                    Logger.Debug("SamlAuthProvider::IsAuthorized:Return False - LoginSessionMisMatch");
                    return false;
                }
            }

            var retVal = session != null && session.IsAuthenticated && tokens != null && !string.IsNullOrEmpty(tokens.UserId);            
            Logger.Debug("SamlAuthProvider::IsAuthorized:RETURN {0}".Fmt(retVal));
            return retVal;
        }

        protected abstract Dictionary<string, string> CreateAuthInfo(SamlResponseAttributes attributes);

        
        protected override void LoadUserAuthInfo(AuthUserSession userSession, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            // move authInfo data into tokens, try to keep naming conventions used by oath providers
            try
            {
                tokens.UserId = authInfo["user_id"];
                tokens.UserName = authInfo["username"];
                tokens.DisplayName = authInfo["name"];
                tokens.FirstName = authInfo["first_name"];
                tokens.LastName = authInfo["last_name"];
                tokens.Email = authInfo["email"];                                
                userSession.UserAuthName = tokens.UserId;
                userSession.UserAuthId = authInfo.GetValueOrDefault("secondary_id");

                string profileUrl;
                if (authInfo.TryGetValue("picture", out profileUrl))
                    tokens.Items[AuthMetadataProvider.ProfileUrlKey] = profileUrl;

                this.LoadUserOAuthProvider(userSession, tokens);                
            }
            catch (Exception ex)
            {
                Log.Error("Could not retrieve Profile info for '{0}'".Fmt(tokens.DisplayName), ex);
            }
            
        }

        protected void LoadUserOAuthProvider(IAuthSession authSession, IAuthTokens tokens)
        {
            var userSession = authSession as AuthUserSession;
            if (userSession == null)
            {
                return;
            }

            userSession.UserName = tokens.UserName ?? userSession.UserName;
            userSession.DisplayName = tokens.DisplayName ?? userSession.DisplayName;
            userSession.FirstName = tokens.FirstName ?? userSession.FirstName;
            userSession.LastName = tokens.LastName ?? userSession.LastName;
            userSession.PrimaryEmail = tokens.Email ?? userSession.PrimaryEmail ?? userSession.Email;
            userSession.Email = tokens.Email ?? userSession.PrimaryEmail ?? userSession.Email;
        }

        public override object Logout(IServiceBase service, Authenticate request)

        {
            base.Logout(service, request);
            return service.Redirect(LogoutUrlFilter(this, this.LogoutUrl));
        }

        // Following methods inspired/borrowed from https://github.com/centrify/CentrifySAMLSDK_CS
        private XmlDocument ParseSamlResponse(string encodedSamlResponse)
        {
            System.Text.ASCIIEncoding encencoder = new System.Text.ASCIIEncoding();
            string strCleanResponse = encencoder.GetString(Convert.FromBase64String(encodedSamlResponse));

            XmlDocument xDoc = new XmlDocument();
            xDoc.PreserveWhitespace = true;
            xDoc.XmlResolver = null;
            xDoc.LoadXml(strCleanResponse);

            return xDoc;
        }

        protected bool IsResponseValid(XmlDocument xDoc)
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            XmlNodeList nodeList = xDoc.SelectNodes("//ds:Signature", manager);

            SignedXml signedXml = new SignedXml(xDoc);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return signedXml.CheckSignature(this.SamlSigningCert, true);
        }

        protected SamlResponseAttributes ParseSamlResponseAttributes(XmlDocument xDoc)
        {

            XmlNamespaceManager xManager = new XmlNamespaceManager(xDoc.NameTable);
            xManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            xManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            XmlNode nameNode = xDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", xManager);

            var retVal = new SamlResponseAttributes
            {
                OriginalResponseDoc = xDoc,
                NameID = nameNode.InnerText,
                Attributes = new Dictionary<string, string>()
            };

            XmlNodeList attributes = xDoc.GetElementsByTagName("Attribute");
            foreach(XmlNode attribute in attributes)
            {
                retVal.Attributes.Add(attribute.Attributes["Name"].Value, attribute.InnerText);
            }

            return retVal;
        }
       
        protected string CreateSamlRequest(string assertionConsumerSvcUrl, string issuer)
        {
            using (StringWriter SWriter = new StringWriter())
            {
                XmlWriterSettings xWriterSettings = new XmlWriterSettings();
                xWriterSettings.OmitXmlDeclaration = true;

                using (XmlWriter xWriter = XmlWriter.Create(SWriter, xWriterSettings))
                {
                    xWriter.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("ID", "_" + System.Guid.NewGuid().ToString());
                    xWriter.WriteAttributeString("Version", "2.0");
                    xWriter.WriteAttributeString("IssueInstant", DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));
                    xWriter.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                    xWriter.WriteAttributeString("AssertionConsumerServiceURL", assertionConsumerSvcUrl);

                    xWriter.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xWriter.WriteString(issuer);
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
                    xWriter.WriteAttributeString("AllowCreate", "true");
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                    xWriter.WriteAttributeString("Comparison", "exact");
                    xWriter.WriteEndElement();

                    xWriter.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                    xWriter.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                    xWriter.WriteEndElement();

                    xWriter.WriteEndElement();
                }

                byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(SWriter.ToString());
                return System.Convert.ToBase64String(toEncodeAsBytes);
            }
        }

        protected class SamlResponseAttributes
        {
            public XmlDocument OriginalResponseDoc { get; set; }
            public string NameID { get; set; }
            public Dictionary<string, string> Attributes { get; set; }
        }
    }

}
