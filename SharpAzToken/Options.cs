using CommandLine;


namespace SharpAzToken
{

    [Verb("default", HelpText = "Default options, not visible")]
    class DefaultOptions
    {
        [Option(HelpText = "Set Proxy")]
        public string Proxy { get; set; }
    }

    [Verb("devicekeys", HelpText = "Play with Device Keys - Get a PRT and a SessionKey for a certificate.")]
    class DeviceKeyOptions : DefaultOptions
    {
        [Option(HelpText = "Specify path to device certificate (PFX).", Required = true)]
        public string PFXPath { get; set; }
        
        [Option(HelpText = "Set Tenant")]
        public string Tenant { get; set; }

        [Option(HelpText = "Set username")]
        public string UserName { get; set; }

        [Option(HelpText = "Set password")]
        public string Password { get; set; }

        [Option(HelpText = "Set Refreshtoken")]
        public string RefreshToken { get; set; }
        
        [Option(HelpText = "Set ClientID (ApplicationID), for example GraphAPI (1b730954-1685-4b74-9bfd-dac224a7b894)", Default = "1b730954-1685-4b74-9bfd-dac224a7b894")]
        public string ClientID { get; set; }
    }

    [Verb("p2pcert", HelpText = "Ask for a P2P Certificate.")]
    class P2POptions : DefaultOptions
    {
        [Option(HelpText = "Specify path to device certificate (PFX).")]
        public string PFXPath { get; set; }
        [Option(HelpText = "Specify a password for the certificate", Default = "")]
        public string PFXPassword { get; set; }

        [Option(HelpText = "Device Name")]
        public string DeviceName { get; set; }

        [Option(HelpText = "Set Tenant")]
        public string Tenant { get; set; }

        [Option(HelpText = "Set username")]
        public string UserName { get; set; }

        [Option(HelpText = "Set password")]
        public string Password { get; set; }

        [Option(HelpText = "Set PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Set Session Key")]
        public string SessionKey { get; set; }

        [Option(HelpText = "Set DerivedKey")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Set Context")]
        public string Context { get; set; }
    }

    [Verb("nonce", HelpText = "Request a nonce from Azure.")]
    class NonceOptions : DefaultOptions
    {
    }

    [Verb("utils", HelpText = "Some arbitrary usefull functions.")]
    class UtilsOptions : DefaultOptions
    {
        [Option(HelpText = "Resolve a domain to a TenantID")]
        public string Domain { get; set; }
    }

    [Verb("cookie", HelpText = "Create a PRT Cookie for further usage or your browser.")]
    class CookieOptions : DefaultOptions
    {
        [Option(HelpText = "Use PRT (from Mimikatz)")]
        public string PRT { get; set; }

        [Option(HelpText = "Use DerivedKey (from Mimikatz)")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Use Context (from Mimikatz)")]
        public string Context { get; set; }

        [Option(HelpText = "Use Session Key")]
        public string SessionKey { get; set; }

        [Option(HelpText = "Use KeyDerivationFunction 2", Default = true)]
        public bool useKDFv2 { get; set; }
    }

    [Verb("token", HelpText = "Play with Azure tokens using \"/oauth2/token\" endpoint.")]
    class TokenOptionsV1 : DefaultOptions
    {
        [Option(HelpText = "Use PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Use Session Key")]
        public string SessionKey { get; set; }

        [Option(HelpText = "Use DeviceCode authentication", Default = false)]
        public bool Devicecode{ get; set; }

        [Option(HelpText = "Use DerivedKey")]
        public string DerivedKey { get; set; }

        [Option(HelpText = "Use Context")]
        public string Context { get; set; }

        [Option(HelpText = "Use Refreshtoken")]
        public string RefreshToken { get; set; }

        [Option(HelpText = "Use PRTCookie")]
        public string PrtCookie { get; set; }

        [Option(HelpText = "Set ClientID (ApplicationID), for example GraphAPI (1b730954-1685-4b74-9bfd-dac224a7b894)", Default = "1b730954-1685-4b74-9bfd-dac224a7b894")]
        public string ClientID { get; set; }

        [Option(HelpText = "Use Client Secret")]
        public string ClientSecret { get; set; }

        [Option(HelpText = "Specify Tenant")]
        public string Tenant { get; set; }
         
        [Option(HelpText = "Use username")]
        public string UserName { get; set; }

        [Option(HelpText = "Use password")]
        public string Password { get; set; }

        [Option(HelpText = "Set resource ID for access token, for example for Device Management (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9)", Default = "https://graph.windows.net")]
        public string ResourceID { get; set; }

        [Option(HelpText = "Set a client used for token request, you can choose between: Outlook, Substrate, Teams, Graph, MSGraph, Core, Office, Intune, Windows, ComplianceCenter, SharepointOnline or ExchangeOnlineV2. Or you can set custom values with --clientid and --resourceid")]
        public string ClientName { get; set; }
        [Option(HelpText = "Use KeyDerivationFunction 2", Default = true)]
        public bool useKDFv2{ get; set; }
    }

    [Verb("tokenv2", HelpText = "Play with Azure tokens using \"/oauth2/v2.0/token\" endpoint.")]
    class TokenOptionsV2 : DefaultOptions
    {
        [Option(HelpText = "Use PRT")]
        public string PRT { get; set; }

        [Option(HelpText = "Use Session Key")]
        public string SessionKey { get; set; }

        [Option(HelpText = "Use DeviceCode authentication", Default = false)]
        public bool Devicecode { get; set; }

        [Option(HelpText = "Use DerivedKey")]
        public string DerivedKey { get; set; }
        [Option(HelpText = "Use PRTCookie")]
        public string PrtCookie { get; set; }

        [Option(HelpText = "Use Context")]
        public string Context { get; set; }

        [Option(HelpText = "Use Refreshtoken")]
        public string RefreshToken { get; set; }

        [Option(HelpText = "Set ClientID (ApplicationID), for example GraphAPI (1b730954-1685-4b74-9bfd-dac224a7b894)", Default = "1b730954-1685-4b74-9bfd-dac224a7b894")]
        public string ClientID { get; set; }

        [Option(HelpText = "Use Client Secret")]
        public string ClientSecret { get; set; }

        [Option(HelpText = "Specify Tenant")]
        public string Tenant { get; set; }

        [Option(HelpText = "Use username")]
        public string UserName { get; set; }

        [Option(HelpText = "Use password")]
        public string Password { get; set; }

        [Option(HelpText = "Set a client used for token request, you can choose between: Outlook, Substrate, Teams, Graph, MSGraph, Core, Office, Intune, Windows, ComplianceCenter or ExchangeOnlineV2. Or you can set custom values with --clientid and --scope")]
        public string ClientName { get; set; }

        [Option(HelpText = "Set a custom scope", Default = ".default offline_access")]
        public string Scope { get; set; }
        
        [Option(HelpText = "Use KeyDerivationFunction 2", Default = true)]
        public bool useKDFv2 { get; set; }
    }

    [Verb("mdm", HelpText = "Do things with Intune like joining a device")]
    class DeviceOptions : DefaultOptions
    {
        [Option(HelpText = "Join a device, then you need to set at least a devicename (--devicename)", Default = false)]
        public bool JoinDevice { get; set; }

        [Option(HelpText = "Mark a device as compliant, then you need to set at least the deviceid (--objectid)", Default = false)]
        public bool MarkCompliant { get; set; }

        [Option(HelpText = "Specifiy the ObjectID of the device")]
        public string ObjectID{ get; set; }

        [Option(HelpText = "Specifiy device name")]
        public string DeviceName { get; set; }

        [Option(HelpText = "Set this, if you want only register the device", Default = false)]
        public bool RegisterDevice { get; set; }

        [Option(HelpText = "Set access token - use token with --clientid 1b730954-1685-4b74-9bfd-dac224a7b894 and --resourceid 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 or --clientname Windows")]
        public string AccessToken { get; set; }

        [Option(HelpText = "Set Tenant")]
        public string Tenant { get; set; }

        [Option(HelpText = "Set username")]
        public string UserName { get; set; }

        [Option(HelpText = "Set password")]
        public string Password { get; set; }
    }
}
