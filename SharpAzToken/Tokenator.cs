using SharpAzToken.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;

namespace SharpAzToken
{
    class Tokenator
    {

        public static string RequestForPendingAuthentication(string code, string clientID,  string proxy, bool useOAuthV2)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("code",code),
                new KeyValuePair<string, string>("grant_type","urn:ietf:params:oauth:grant-type:device_code"),
                new KeyValuePair<string, string>("client_id", clientID)
                });
            if (useOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy);
            }

        }

        public static string RequestDeviceCode(string clientid, string payload, string proxy, bool useOAuthV2)
        {
            if (useOAuthV2)
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", clientid),
                    new KeyValuePair<string, string>("scope", payload)
                });
                return Helper.PostToDeviceCodeEndpoint(formContent, proxy, useOAuthV2);
            }
            else
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", clientid),
                    new KeyValuePair<string, string>("resource", payload)
                });
                return Helper.PostToDeviceCodeEndpoint(formContent, proxy, useOAuthV2);
            }
        }

        public static string RequestP2PCertificate(string JWT, string tenant, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("request", JWT),
                new KeyValuePair<string, string>("windows_api_version", "1.0")
                });
            return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
        }

        public static string GetTokenWithClientIDAndSecret(string clientID, string clientSecret, string tenant, string proxy, string payload, bool UseOAuthV2)
        {
            if (UseOAuthV2)
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("scope", payload),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("resource", payload),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }

        public static string GetTokenFromUsernameAndPasswordV1(string username, string password, string proxy, string clientID, string ressourceId, string tenant)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password)
                });
            return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
        }

        private static string GetTokenWithUserNameAndPasswordV2(string username, string password, string proxy, string scope, string clientId, string tenant)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("username", username),
                new KeyValuePair<string, string>("password", password),
                new KeyValuePair<string, string>("claims", "{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}")
                });
            return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);

        }

        public static string GetTokenFromRefreshTokenV1(string refreshToken, string tenant, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });           
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant); 
        }
        public static string GetTokenWithRefreshTokenV2(string refreshToken, string proxy, string scope, string clientId, string tenant, string claims = @"{""access_token"":{""xms_cc"":{""values"":[""cp1""]}}}")
        {
            if(claims != null)
            {
                var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("claims", claims),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                var formContent = new FormUrlEncodedContent(new[]
{
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            
        }
        public static string GetTokenWithCodeV1(string code, string tenant, string proxy, string clientID, string ressourceId)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
                new KeyValuePair<string, string>("code", code)
                });
            return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
        }

        public static string GetTokenWithCodeV2(string code, string tenant, string proxy, string clientID, string scope)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
                new KeyValuePair<string, string>("code", code)
                });
            return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
        }

        public static string GetP2PCertificate(string JWT, string tenant, string proxy)
        {
            return RequestP2PCertificate(JWT, tenant, proxy);
         } 
        

        public static string GetTokenFromPRTAndDerivedKey(string PRT, string tenant, string DerivedKey, string Context, string Proxy, string clientID, string payload, bool useAuthV2)
        {
            string result = null;
            string prtCookie = Helper.createPRTCookie(PRT, Context, DerivedKey, Proxy);
            if (useAuthV2)
            {
                string code = Helper.getCodeFromPRTCookieV2(prtCookie, Proxy, payload, clientID);
                result = GetTokenWithCodeV2(code, tenant, Proxy, clientID, payload);
            }
            else {
                string code = Helper.getCodeFromPRTCookieV1(prtCookie, Proxy, payload, clientID);
                result = GetTokenWithCodeV1(code, tenant, Proxy, clientID, payload);
            }
            return result;
        }

        public static string GetTokenFromPRTAndSessionKey(string PRT, string tenant, string SessionKey, string Proxy, string clientID, string payload, bool useOauthv2, bool useKDFv2)
        {
            string result = null;
            var context = Helper.GetByteArray(24);
            var decodedKey = Helper.Base64Decode(SessionKey);
            var derivedKey = Helper.CreateDerivedKey(decodedKey, context);

            var contextHex = Helper.Binary2Hex(context);
            var derivedSessionKeyHex = Helper.Binary2Hex(derivedKey);

            string prtCookie = Helper.createPRTCookie2(PRT, Proxy, SessionKey, useKDFv2);
            string code;
            if (useOauthv2)
            {
                code = Helper.getCodeFromPRTCookieV2(prtCookie, Proxy, payload, clientID);
            }
            else
            {
                code = Helper.getCodeFromPRTCookieV1(prtCookie, Proxy, payload, clientID);
            }
            if(code == null | code.Length == 0)
            {
                return null;
            }
            if (useOauthv2)
            {
                result = GetTokenWithCodeV2(code, tenant, Proxy, clientID, payload);
            }
            else
            {
                result = GetTokenWithCodeV1(code, tenant, Proxy, clientID, payload);
            }
            return result;
        }

        public static string GetTokenFromPRTCookieV1(string PRTCookie, string Proxy, string clientID, string resourceID)
        {
            string code = Helper.getCodeFromPRTCookieV1(PRTCookie, Proxy, resourceID, clientID);
            if (code == null || code.Length == 0)
            {
                return null;
            }
            return GetTokenWithCodeV1(code, null, Proxy, clientID, resourceID);
        }

        public static string GetTokenFromPRTCookieV2(string PRTCookie, string Proxy, string clientID, String scope)
        {
            string code = Helper.getCodeFromPRTCookieV2(PRTCookie, Proxy, scope, clientID);
            if (code == null || code.Length == 0)
            {
                return null;
            }
            return GetTokenWithCodeV1(code, null, Proxy, clientID, scope);
        }

        public static string GetTokenFromDeviceCodeFlow(string ClientID, string ResourceID, string Proxy, bool useOAuthV2)
        {
            string result = null;
            result = RequestDeviceCode(ClientID, ResourceID, Proxy, useOAuthV2);
            var InitDeviceCode = JsonConvert.DeserializeObject<DeviceCodeResp>(result);
            Console.WriteLine(JToken.FromObject(InitDeviceCode).ToString(Formatting.Indented));

            var SecondsToWait = InitDeviceCode.interval;
            int WaitedTime = 0;
            while (WaitedTime < InitDeviceCode.expires_in)
            {
                result = RequestForPendingAuthentication(InitDeviceCode.device_code, ClientID, Proxy, useOAuthV2 );
                JToken parsedesults = JToken.Parse(result);
                if (parsedesults["error"] != null)
                {
                    Console.WriteLine("[+] Response from Azure: " + parsedesults["error"]);
                }else
                {
                    return result;
                }
                System.Threading.Thread.Sleep(SecondsToWait * 1000);
                WaitedTime += SecondsToWait;
                result = null;
            }
            return null;
        }

        public static string getTokenV1(TokenOptionsV1 opts)
        {
            string result = null;
            string clientID = opts.ClientID;
            string resourceID = opts.ResourceID;

            if (opts.Devicecode)
            {
                result = GetTokenFromDeviceCodeFlow(clientID, resourceID, opts.Proxy, false);
            }
            else if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = GetTokenFromPRTAndDerivedKey(opts.PRT, opts.Tenant, opts.DerivedKey, opts.Context, opts.Proxy, clientID, resourceID, false);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                result = GetTokenFromPRTAndSessionKey(opts.PRT, opts.Tenant, opts.SessionKey, opts.Proxy, clientID, resourceID, false, opts.useKDFv2);
            }
            else if (opts.PrtCookie != null)
            {
                result = GetTokenFromPRTCookieV1(opts.PrtCookie, opts.Proxy, clientID, resourceID);
            }
            else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
            {
                result = GetTokenWithClientIDAndSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy, resourceID, false);
            }
            else if (opts.RefreshToken != null & opts.ResourceID != null)
            {
                result = GetTokenFromRefreshTokenV1(opts.RefreshToken, opts.Tenant, opts.Proxy, opts.ClientID, opts.ResourceID);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                result = GetTokenFromUsernameAndPasswordV1(opts.UserName, opts.Password, opts.Proxy, opts.ClientID, opts.ResourceID, opts.Tenant);
            }
            else
            {
                Console.WriteLine("[-] Please set the corect arguments.");
                return null;
            }
            return result;
        }

        public static string getTokenV2(TokenOptionsV2 opts)
        {
            string result = null;
            string clientID = opts.ClientID;
            string scope = opts.Scope;

            if (opts.Devicecode)
            {
                result = GetTokenFromDeviceCodeFlow(clientID, scope, opts.Proxy, true);
            }
            else if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = GetTokenFromPRTAndDerivedKey(opts.PRT, opts.Tenant, opts.DerivedKey, opts.Context, opts.Proxy, clientID, scope, true);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                result = GetTokenFromPRTAndSessionKey(opts.PRT, opts.Tenant, opts.SessionKey, opts.Proxy, clientID, scope, true, opts.useKDFv2);
            }
            else if (opts.RefreshToken != null & opts.Scope != null)
            {
                result = GetTokenWithRefreshTokenV2(opts.RefreshToken, opts.Proxy, opts.Scope, opts.ClientID, opts.Tenant);
            }
            else if (opts.UserName != null & opts.Password != null)
            {
                result = GetTokenWithUserNameAndPasswordV2(opts.UserName, opts.Password, opts.Proxy, opts.Scope, opts.ClientID, opts.Tenant);
            }
            else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
            {
                result = GetTokenWithClientIDAndSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy, scope, true);
            }
            else if (opts.PrtCookie != null)
            {
                result = GetTokenFromPRTCookieV2(opts.PrtCookie, opts.Proxy, clientID, scope);
            }
            else
            {
                Console.WriteLine("[-] Please set the corect arguments.");
                return null;
            }
            return result;
        }


    }
}
