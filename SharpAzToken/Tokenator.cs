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

        public static string RequestForPendingAuthentication(string code, string clientID,  string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("code",code),
                new KeyValuePair<string, string>("grant_type","urn:ietf:params:oauth:grant-type:device_code"),
                new KeyValuePair<string, string>("client_id", clientID)
                });

            return Helper.PostToTokenEndpoint(formContent, proxy);

        }

        public static string RequestDeviceCode(string clientid, string resourceid, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("client_id", clientid),
                new KeyValuePair<string, string>("resource", resourceid)
                });
            return Helper.PostToDeviceCodeEndpoint(formContent, proxy);
        }

        public static string RequestP2PCertificate(string JWT, string tenant, string proxy)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("request", JWT)
                });
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
        }

        public static string GetTokenWithClientIDAndSecret(string clientID, string clientSecret, string tenant, string proxy, string ressourceId, bool UseOAuthV2)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>(ressourceId, ressourceId),
                new KeyValuePair<string, string>("client_secret", clientSecret)
                });
            if (UseOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }

        public static string GetTokenFromUsernameAndPassword(string username, string password, string tenant, string proxy, string clientID, string ressourceId, bool UseOAuthV2)
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
            if (UseOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }

        public static string GetTokenFromRefreshToken(string refreshToken, string tenant, string proxy, string clientID, string ressourceId, bool UseOAuthV2)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("scope", "openid"),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("resource", ressourceId),
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });
            if (UseOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }
        public static string GetTokenWithCode(string code, string tenant, string proxy, string clientID, string ressourceId)
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

        public static string GetTokenWithRefreshTokenAndScope(string refreshToken, string proxy, string scope, string clientId, string tenant, bool UseOAuthV2)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("scope", scope),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("claims", "{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}"),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
                });

            if (UseOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }

        private static string GetTokenWithUserNameAndPasswordAndScope(string username, string password, string proxy, string scope, string clientId, string tenant, bool UseOAuthV2)
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

            if (UseOAuthV2)
            {
                return Helper.PostToTokenV2Endpoint(formContent, proxy, tenant);
            }
            else
            {
                return Helper.PostToTokenEndpoint(formContent, proxy, tenant);
            }
        }

        public static string GetP2PCertificate(string JWT, string tenant, string proxy)
        {
            return RequestP2PCertificate(JWT, tenant, proxy);
         } 
        

        public static string GetTokenFromPRTAndDerivedKey(string PRT, string tenant, string DerivedKey, string Context, string Proxy, string clientID, string resourceID)
        {
            string result = null;
            string prtCookie = Helper.createPRTCookie(PRT, Context, DerivedKey, Proxy);
            string code = Helper.getCodeFromPRTCookie(prtCookie, Proxy, resourceID, clientID);
            result = GetTokenWithCode(code, tenant, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromPRTAndSessionKey(string PRT, string tenant, string SessionKey, string Proxy, string clientID, string resourceID)
        {
            string result = null;
            var context = Helper.GetByteArray(24);
            var decodedKey = Helper.Base64Decode(SessionKey);
            var derivedKey = Helper.CreateDerivedKey(decodedKey, context);

            var contextHex = Helper.Binary2Hex(context);
            var derivedSessionKeyHex = Helper.Binary2Hex(derivedKey);

            string prtCookie = Helper.createPRTCookie(PRT, contextHex, derivedSessionKeyHex, Proxy);
            string code = Helper.getCodeFromPRTCookie(prtCookie, Proxy, resourceID, clientID);
            if(code == null | code.Length == 0)
            {
                return null;
            }
            result = GetTokenWithCode(code, tenant, Proxy, clientID, resourceID);
            return result;
        }

        public static string GetTokenFromPRTCookie(string PRTCookie, string Proxy, string clientID, string resourceID)
        {
            string code = Helper.getCodeFromPRTCookie(PRTCookie, Proxy, resourceID, clientID);
            if (code == null || code.Length == 0)
            {
                return null;
            }
            return GetTokenWithCode(code, null, Proxy, clientID, resourceID);
        }

        public static string GetTokenFromDeviceCodeFlow(string ClientID, string ResourceID, string Proxy)
        {
            string result = null;
            result = RequestDeviceCode(ClientID, ResourceID, Proxy);
            var InitDeviceCode = JsonConvert.DeserializeObject<DeviceCodeResp>(result);
            Console.WriteLine(JToken.FromObject(InitDeviceCode).ToString(Formatting.Indented));

            var SecondsToWait = InitDeviceCode.interval;
            int WaitedTime = 0;
            while (WaitedTime < InitDeviceCode.expires_in)
            {
                result = RequestForPendingAuthentication(InitDeviceCode.device_code, ClientID, Proxy);
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

        public static string getToken(TokenOptions opts)
        {
            string result = null;
            string clientID = opts.ClientID;
            string resourceID = opts.ResourceID;

            if (opts.Devicecode)
            {
                result = GetTokenFromDeviceCodeFlow(clientID, resourceID, opts.Proxy);
            }
            else if (opts.PRT != null & opts.DerivedKey != null & opts.Context != null)
            {
                result = GetTokenFromPRTAndDerivedKey(opts.PRT, opts.Tenant, opts.DerivedKey, opts.Context, opts.Proxy, clientID, resourceID);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                result = GetTokenFromPRTAndSessionKey(opts.PRT, opts.Tenant, opts.SessionKey, opts.Proxy, clientID, resourceID);
            }
            else if (opts.PrtCookie != null)
            {
                result = GetTokenFromPRTCookie(opts.PrtCookie, opts.Proxy, clientID, resourceID);
            }
            else if (opts.RefreshToken != null & opts.Scope == null)
            {
                result = GetTokenFromRefreshToken(opts.RefreshToken, opts.Tenant, opts.Proxy, clientID, resourceID, opts.UseOAuthV2);
            }else if(opts.RefreshToken != null & opts.Scope != null)
            {
                result = GetTokenWithRefreshTokenAndScope(opts.RefreshToken, opts.Proxy, opts.Scope, opts.ClientID, opts.Tenant, opts.UseOAuthV2);
            }
            else if (opts.UserName != null & opts.Password != null & opts.Scope == null)
            {
                result = GetTokenFromUsernameAndPassword(opts.UserName, opts.Password, opts.Tenant, opts.Proxy, clientID, resourceID, opts.UseOAuthV2);
            }
            else if (opts.UserName != null & opts.Password != null &opts.Scope != null)
            {
                result = GetTokenWithUserNameAndPasswordAndScope(opts.UserName, opts.Password, opts.Proxy, opts.Scope, opts.ClientID, opts.Tenant, opts.UseOAuthV2 );
            }
            else if (opts.Tenant != null & opts.ClientID != null & opts.ClientSecret != null)
            {
                result = GetTokenWithClientIDAndSecret(opts.ClientID, opts.ClientSecret, opts.Tenant, opts.Proxy, opts.ResourceID, opts.UseOAuthV2);
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
