using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SharpAzToken
{
    class Helper
    {
        public static string getCodeFromPRTCookieV1(string cookie, string proxy, string resourceID, string clientID)
        {
            String uri = string.Format(@"/common/oauth2/authorize?client_id={0}&resource={1}&response_type=code&&redirect_uri=urn:ietf:wg:oauth:2.0:oob",
                clientID,
                resourceID
             );
            return getCodeFromPRTCookie(cookie, proxy, uri);
        }

        public static string getCodeFromPRTCookieV2(string cookie, string proxy, string scope, string clientID)
        {
            String uri = string.Format(@"/common/oauth2/authorize?client_id={0}&scope={1}&response_type=code&&redirect_uri=urn:ietf:wg:oauth:2.0:oob",
                clientID,
                scope
             );
            return getCodeFromPRTCookie(cookie, proxy, uri);
        }
        public static string getCodeFromPRTCookie(string cookie, string proxy, string uri)
        {
            HttpClient client = getDefaultClient(proxy);
            using (client)
            {
                var message = new HttpRequestMessage(HttpMethod.Get, uri);
                String xcookie = "x-ms-RefreshTokenCredential=" + cookie;
                message.Headers.Add("Cookie", xcookie);
                var response = client.SendAsync(message).Result;
                if (response.StatusCode.Equals("200"))
                {
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }
                string location = "";
                if (response.Headers.Contains("Location"))
                {
                    location = response.Headers.Location.ToString();
                }
                else
                {
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return "";
                }

                int startOf = location.IndexOf("code=");
                if (startOf == -1)
                {
                    Console.WriteLine("[-] Something went wrong, cannot fetch code with PRT cookie, maybe Conditional Access Policy blocks.");
                    return null;
                }
                int endOf = location.IndexOf("&", startOf + 5);
                int len = endOf - startOf;
                string code = location.Substring(startOf + 5, len - 5);
                client.Dispose();
                return code;
            }
        }

        public static HttpClient getDefaultClient(String proxy = null, bool useCookies = true, UserAgentEnums userAgent = UserAgentEnums.Edge, String baseAdress = "https://login.microsoftonline.com")
        {
            HttpClientHandler handler = new HttpClientHandler();
            if (proxy != null)
            {
                handler.Proxy = new WebProxy(proxy);
                handler.UseProxy = true;
            }

            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                };
            handler.AllowAutoRedirect = false;

            handler.UseCookies = useCookies;
            var client = new HttpClient(handler);
            client.BaseAddress = new Uri(baseAdress);
            client.DefaultRequestHeaders.Clear();
            //client.DefaultRequestHeaders.Add("UA-CPU", "AMD64");
            string usedUserAgent = GetEnumDescription((UserAgentEnums)userAgent);
            client.DefaultRequestHeaders.Add("User-Agent", usedUserAgent);
            return client;

        }

        // https://stackoverflow.com/questions/1459006/is-there-a-c-sharp-equivalent-to-pythons-unhexlify
        public static byte[] Hex2Binary(string hex)
        {
            var chars = hex.ToCharArray();
            var bytes = new List<byte>();
            for (int index = 0; index < chars.Length; index += 2)
            {
                var chunk = new string(chars, index, 2);
                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
            }
            return bytes.ToArray();
        }

        //https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        public static string Binary2Hex(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        //https://stackoverflow.com/questions/1228701/code-for-decoding-encoding-a-modified-base64-url
        public static byte[] Base64Decode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    throw new System.Exception(
             "Illegal base64prt string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        public static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        public static string createPRTCookieWithKDFv2(string prt, string context, string derived_sessionkey, string sessionkey, string proxy)
        {
            string nonce = getNonce(proxy);
           
            byte[] data = Base64Decode(prt);
            string prtdecoded = Encoding.UTF8.GetString(data);


            //https://stackoverflow.com/questions/9453101/how-do-i-get-epoch-time-in-c
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            int iat = (int)t.TotalSeconds;
           
            var payload = new Dictionary<string, object>
            {
                { "refresh_token", prtdecoded },
                { "is_primary", "true" },
                { "iat", iat },
                { "request_nonce", nonce }
            };

            var contextBytes = Helper.GetByteArray(24);
            Dictionary<string, object> header = null;
            var derivedContext = contextBytes;
            header = new Dictionary<string, object>
            {
                { "ctx", contextBytes },
                { "kdf_ver", 2 }

            };
            derivedContext = GetKDFv2(payload,  contextBytes);

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            
            var decodedKey = Helper.Base64Decode(sessionkey);
            var derivedKey = Helper.CreateDerivedKey(decodedKey, derivedContext);
            
            var cookie = encoder.Encode(header, payload, derivedKey);
            return cookie;
        }

        public static string createPRTCookie(string prt, string context, string derived_sessionkey, string sessionkey, string proxy)
        {
            
            string nonce = getNonce(proxy);

            byte[] data = Base64Decode(prt);
            string prtdecoded = Encoding.UTF8.GetString(data);

            var payload = new Dictionary<string, object>
            {
                { "refresh_token", prtdecoded },
                { "is_primary", "true" },
                { "request_nonce", nonce }
            };

            Dictionary<string, object> header = null;

            byte[] currentContext;
            if (context != null)
            {
                currentContext = Hex2Binary(context);
            }
            else
            {
                currentContext = Helper.GetByteArray(24);
            }

            header = new Dictionary<string, object>
            {
                { "ctx", currentContext }
            };

            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            if (sessionkey != null)
            {
                var decodedKey = Helper.Base64Decode(sessionkey);
                var derivedKey = Helper.CreateDerivedKey(decodedKey, currentContext);
                var cookie = encoder.Encode(header, payload, derivedKey);
                return cookie;
            }
            else
            {
                byte[] sdata = null;
                string secret = derived_sessionkey.Replace(" ", "");
                sdata = Hex2Binary(secret);
                var cookie = encoder.Encode(header, payload, sdata);
                return cookie;
            }
        }



        public static string signJWT(Dictionary<string, object> header, Dictionary<string, object> payload, string key)
        {
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            string secret = key.Replace(" ", "");
            byte[] sdata = Hex2Binary(secret);
            return encoder.Encode(header, payload, sdata); 
        }

        public static String getNonce(string proxy)
        {
            using (var client = getDefaultClient(proxy))
            {
                String uri = string.Format(@"/Common/oauth2/authorize?client_id={0}", "1b730954-1685-4b74-9bfd-dac224a7b894");
                var response = client.GetAsync(uri).Result;
                var responseContent = response.Content;
                string responseString = responseContent.ReadAsStringAsync().Result;
                int startOf = responseString.IndexOf("\"nonce\":\"");
                int endOf = responseString.IndexOf("\"", startOf + 9);
                int len = endOf - startOf;
                string nonce = responseString.Substring(startOf + 9, len - 9);
                client.Dispose();
                return nonce;
            }
        }


        private static string PostTo(string uri, FormUrlEncodedContent formContent, string proxy, UserAgentEnums userAgent)
        {
            using (var message = new HttpRequestMessage(HttpMethod.Post, uri))
            using (var client = Helper.getDefaultClient(proxy, false, userAgent))
            {
                //message.Headers.Add("client-request-id", Guid.NewGuid().ToString());
                //message.Headers.Add("return-client-request-id", "true");
                message.Content = formContent;
                var response = client.SendAsync(message).Result;
                var result = response.Content.ReadAsStringAsync().Result;
                return result;
            }
        }

        private static string GetFrom(string uri, string proxy, UserAgentEnums userAgent)
        {
            using (var message = new HttpRequestMessage(HttpMethod.Get, uri))
            using (var client = Helper.getDefaultClient(proxy, false, userAgent))
            {
                var response = client.SendAsync(message).Result;
                return response.Content.ReadAsStringAsync().Result;
            }
        }

        public static int PatchRequest(string uri, string accesstoken, string proxy, UserAgentEnums userAgent = UserAgentEnums.Edge)
        {
            using(var content = new StringContent("{}", Encoding.UTF8, "application/json"))
            using (var message = new HttpRequestMessage(HttpMethod.Patch, uri))
            using (var client = Helper.getDefaultClient(proxy, false, userAgent, "https://graph.windows.net"))
            {
                message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accesstoken);
                message.Content = content;
                var response = client.SendAsync(message).Result;
                return (int)response.StatusCode;
            }
        }

        public static string GetOpenIDConfiguration(string domain, string proxy)
        {
            string uri = "/" + domain + "/.well-known/openid-configuration";
            return GetFrom(uri,proxy, UserAgentEnums.Edge);
        }

        public static string PostToDeviceCodeEndpoint(FormUrlEncodedContent formContent, string proxy, bool useOAuthV2, UserAgentEnums userAgent = UserAgentEnums.Edge)
        {
            string uri = null;
            if (useOAuthV2)
            {
                uri = "/common/oauth2/v2.0/devicecode";
            }
            else
            {
                uri = "/common/oauth2/devicecode";
            }
            return PostTo(uri, formContent, proxy, userAgent);
        }

        public static string PostToTokenV2Endpoint(FormUrlEncodedContent formContent, string proxy, string tenant = null, UserAgentEnums userAgent = UserAgentEnums.Edge)
        {
            string uri = "/organizations/oauth2/v2.0/token";
            if (tenant != null)
            {
                uri = "/" + tenant + "/oauth2/v2.0/token";
            }
            return PostTo(uri, formContent, proxy, userAgent);
        }

        public static string PostToTokenEndpoint(FormUrlEncodedContent formContent, string proxy, string tenant = null, UserAgentEnums userAgent = UserAgentEnums.Edge)
        {
            string uri = "/common/oauth2/token";
            if (tenant != null)
            {
                uri = "/" + tenant + "/oauth2/token";
            }
            return PostTo(uri, formContent, proxy, userAgent);
        }

        public static string GetNonce2(string proxy, UserAgentEnums userAgent = UserAgentEnums.Edge)
        {
            var formContent = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "srv_challenge")
                });
            string result = PostToTokenEndpoint(formContent, proxy);
            JToken parsedNonce = JToken.Parse(result);
            return parsedNonce["Nonce"].ToString();
        }

        public static string GetTenantFromAccessToken(string accesstoken)
        {
            return GetInfoFromBase64JSON(accesstoken, "tid");
        }

        public static string GetAudienceFromAccessToken(string accesstoken)
        {
            return GetInfoFromBase64JSON(accesstoken, "aud");
        }
        public static string getUPNFromAccessToken(string accesstoken)
        {
            return GetInfoFromBase64JSON(accesstoken, "upn");
        }

        public static string GetInfoFromBase64JSON(string jsonString, string info)
        {
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            string decodedaccesstoken = decoder.Decode(jsonString);
            JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
            return parsedAccessToken[info].ToString();
        }

        public static byte[] GetByteArray(int size)
        {
            Random rnd = new Random();
            byte[] b = new byte[size]; // convert kb to byte
            rnd.NextBytes(b);
            return b;
        }

        public static byte[] CombineByteArrays(byte[] first, byte[] second)
        {
            return first.Concat(second).ToArray();
        }

        public static byte[] CreateDerivedKey(byte[] sessionKey, byte[] context)
        {
            byte[] sessionKeyBytes = sessionKey;
            byte[] contextBytes = context;
            byte[] label = System.Text.Encoding.UTF8.GetBytes("AzureAD-SecureConversation");

            var first = new byte[]{ 0x00, 0x00, 0x00, 0x01 };
            var second = new byte[] { 0x00 };
            var third = new byte[] { 0x00, 0x00, 0x01, 0x00 };
            
            var value = CombineByteArrays(first, label);
            value = CombineByteArrays(value, second);
            value = CombineByteArrays(value, contextBytes);
            value = CombineByteArrays(value, third);
            var hmac = new System.Security.Cryptography.HMACSHA256(sessionKeyBytes);
            var hmacOutput = hmac.ComputeHash(value);
            return hmacOutput;
        }

        public static byte[] ConvertToByteArray(string str, Encoding encoding)
        {
            return encoding.GetBytes(str);
        }

        public static String ToBinary(Byte[] data)
        {
            return string.Join(" ", data.Select(byt => Convert.ToString(byt, 2).PadLeft(8, '0')));
        }

        public static byte[] GetKDFv2(Dictionary<string, object> payload, Byte[] context)
        {
            var SHA256 = System.Security.Cryptography.SHA256.Create();
            //var payloadJsons = JsonConvert.SerializeObject(payload);
            string payloadJson = JsonSerializer.Serialize(payload);
            payloadJson = payloadJson.Replace(@"\", "");
            payloadJson = payloadJson.Replace(@" ", String.Empty);
            var encodedJSON = Encoding.UTF8.GetBytes(payloadJson);
            var buffer = new byte[encodedJSON.Length + context.Length];

            Array.Copy(context, 0, buffer, 0, context.Length);
            Array.Copy(encodedJSON, 0, buffer, context.Length, encodedJSON.Length);
            return SHA256.ComputeHash(buffer);
        }

        // Credits to https://stackoverflow.com/questions/2650080/how-to-get-c-sharp-enum-description-from-value
        public static string GetEnumDescription(Enum value)
        {
            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes = fi.GetCustomAttributes(typeof(DescriptionAttribute), false) as DescriptionAttribute[];
            if (attributes != null && attributes.Any())
            {
                return attributes.First().Description;
            }
            return value.ToString();
        }
    }
}
