# SharpAzToken

SharpAzToken (formerly Lantern) is a small tool I created to learn about Azure authentication, tokens and C#. Maybe It helps you to learn, too. The code for authentication, is mainly adapted from [auth.py](https://github.com/dirkjanm/ROADtools/blob/master/roadlib/roadtools/roadlib/auth.py) of [roadtools](https://github.com/dirkjanm/ROADtools) from [Dirk-Jan](https://twitter.com/_dirkjan) and ported to c#. All credits for the authentication part goes to him.

How Azure PRT works is mainly described in these two articles:

* [https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
* [https://dirkjanm.io/digging-further-into-the-primary-refresh-token/](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)

Additionally, I started to implement Azure Device Join and to learn about that. Here I copied and adapted the code mainly from [AADInternals](https://github.com/Gerenios/AADInternals). Here all credits goes to [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD). If you want to learn more about device join I can recommend reading [this](https://o365blog.com/) blog.

At the moment you can request some tokens in various ways and join a device to Azure. Additionally you can use this device the get PRT and a session key. More is coming.

**Note:** This tools is for learning and it is in pre-, pre-, pre- (what comes before alpha?) status. 

## Compiling

You can build it with VisualStudio 2019 and .NetCore. Simple open the project and compile it. I tested it for Windows and Linux.

## Usage

### Proxy

You can always see whats going on if you add a proxy like:  

```
--proxy http://127.0.0.1:8080
```

Tipp: Disable HTTP2 support on your proxy. The library I use does not support HTTP2 and I had problems with burp, if I didn't disable HTTP2.

### Help

```
.\SharpAzToken.exe --help
  _________.__                           _____         ___________     __
 /   _____/|  |__ _____ _____________   /  _  \ _______\__    ___/___ |  | __ ____   ____
 \_____  \ |  |  \\__  \\_  __ \____ \ /  /_\  \\___   / |    | /  _ \|  |/ // __ \ /    \
 /        \|   Y  \/ __ \|  | \/  |_> >    |    \/    /  |    |(  <_> )    <\  ___/|   |  \
/_______  /|___|  (____  /__|  |   __/\____|__  /_____ \ |____| \____/|__|_ \\___  >___|  /
        \/      \/     \/      |__|           \/      \/                   \/    \/     \/

SharpAzToken 0.0.3

  p2pcert       Ask for a P2P Certificate.
  nonce         Request a nonce from Azure.
  cookie        Create a PRT Cookie for further usage or your browser.
  token         Play with Azure tokens using "/oauth2/token" endpoint.
  tokenv2       Play with Azure tokens using "/oauth2/v2.0/token" endpoint.
  mdm           Do things with Intune like joining a device
  devicekeys    Play with Device Keys - Get a PRT and a SessionKey for a
                certificate.
  utils         Some arbitrary usefull functions.
  help          Display more information on a specific command.
  version       Display version information.


```

### P2PCert

Request a certificate to perform a Pass-The-Cert.

```
SharpAzToken.exe p2pcert --help

  --pfxpath        Specify path to device certificate (PFX).
  --pfxpassword    (Default: ) Specify a password for the certificate
  --devicename     Device Name
  --tenant         Set Tenant
  --username       Set username
  --password       Set password
  --prt            Set PRT
  --sessionkey     Set Session Key
  --derivedkey     Set DerivedKey
  --context        Set Context
  --proxy          Set Proxy
  --help           Display this help screen.
  --version        Display version information.
```

### Nonce

Request a nonce you can use the following command: 

```cmd
SharpAzToken.exe nonce --help

  --proxy      Set Proxy
  --help       Display this help screen.
  --version    Display version information.

```

### Cookie

Create a PRT-Cookie for the browser you can use:

```cmd
SharpAzToken.exe cookie --help

 --prt           Use PRT (from Mimikatz)
  --derivedkey    Use DerivedKey (from Mimikatz)
  --context       Use Context (from Mimikatz
  --sessionkey    Use Session Key
  --proxy         Set Proxy
  --help          Display this help screen.
  --version       Display version information.
```

### Token

Create tokens in various combination and play with them:

```cmd
.\SharpAzToken.exe token --help
  _________.__                           _____         ___________     __
 /   _____/|  |__ _____ _____________   /  _  \ _______\__    ___/___ |  | __ ____   ____
 \_____  \ |  |  \\__  \\_  __ \____ \ /  /_\  \\___   / |    | /  _ \|  |/ // __ \ /    \
 /        \|   Y  \/ __ \|  | \/  |_> >    |    \/    /  |    |(  <_> )    <\  ___/|   |  \
/_______  /|___|  (____  /__|  |   __/\____|__  /_____ \ |____| \____/|__|_ \\___  >___|  /
        \/      \/     \/      |__|           \/      \/                   \/    \/     \/

SharpAzToken 0.0.3

  --prt             Use PRT
  --sessionkey      Use Session Key
  --devicecode      (Default: false) Use DeviceCode authentication
  --derivedkey      Use DerivedKey
  --context         Use Context
  --refreshtoken    Use Refreshtoken
  --prtcookie       Use PRTCookie
  --clientid        (Default: 1b730954-1685-4b74-9bfd-dac224a7b894) Set ClientID
                    (ApplicationID), for example GraphAPI
                    (1b730954-1685-4b74-9bfd-dac224a7b894)
  --clientsecret    Use Client Secret
  --tenant          Specify Tenant
  --username        Use username
  --password        Use password
  --resourceid      (Default: https://graph.windows.net) Set resource ID for
                    access token, for example for Device Management
                    (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9)
  --clientname      Set a client used for token request, you can choose between:
                    Outlook, Substrate, Teams, Graph, MSGraph, Core, Office,
                    Intune, Windows, ComplianceCenter, SharepointOnline or
                    ExchangeOnlineV2. Or you can set custom values with
                    --clientid and --resourceid
  --proxy           Set Proxy
  --help            Display this help screen.
  --version         Display version information.
```

### Tokenv2

Create a token using "/oauth2/v2.0/token" endpoint.

```cmd
.\SharpAzToken.exe tokenv2 --help


  _________.__                           _____         ___________     __
 /   _____/|  |__ _____ _____________   /  _  \ _______\__    ___/___ |  | __ ____   ____
 \_____  \ |  |  \\__  \\_  __ \____ \ /  /_\  \\___   / |    | /  _ \|  |/ // __ \ /    \
 /        \|   Y  \/ __ \|  | \/  |_> >    |    \/    /  |    |(  <_> )    <\  ___/|   |  \
/_______  /|___|  (____  /__|  |   __/\____|__  /_____ \ |____| \____/|__|_ \\___  >___|  /
        \/      \/     \/      |__|           \/      \/                   \/    \/     \/

SharpAzToken 0.0.3

  --prt             Use PRT
  --sessionkey      Use Session Key
  --devicecode      (Default: false) Use DeviceCode authentication
  --derivedkey      Use DerivedKey
  --prtcookie       Use PRTCookie
  --context         Use Context
  --refreshtoken    Use Refreshtoken
  --clientid        (Default: 1b730954-1685-4b74-9bfd-dac224a7b894) Set ClientID
                    (ApplicationID), for example GraphAPI
                    (1b730954-1685-4b74-9bfd-dac224a7b894)
  --clientsecret    Use Client Secret
  --tenant          Specify Tenant
  --username        Use username
  --password        Use password
  --clientname      Set a client used for token request, you can choose between:
                    Outlook, Substrate, Teams, Graph, MSGraph, Core, Office,
                    Intune, Windows, ComplianceCenter or ExchangeOnlineV2. Or
                    you can set custom values with --clientid and --scope
  --scope           (Default: .default offline_access) Set a custom scope
  --proxy           Set Proxy
  --help            Display this help screen.
  --version         Display version information.
```

### MDM

Join a device or mark a device as compliant.

```cmd
SharpAzToken.exe mdm --help

  --joindevice        (Default: false) Join a device, then you need to set at
                      least a devicename (--devicename)
  --markcompliant     (Default: false) Mark a device as compliant, then you need
                      to set at least the deviceid (--objectid)
  --objectid          Specifiy the ObjectID of the device
  --devicename        Specifiy device name
  --registerdevice    (Default: false) Set this, if you want only register the
                      device
  --accesstoken       Set access token - use token with --clientid
                      1b730954-1685-4b74-9bfd-dac224a7b894 and --resourceid
                      01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 or --clientname
                      Windows
  --tenant            Set Tenant
  --username          Set username
  --password          Set password
  --proxy             Set Proxy
  --help              Display this help screen.
  --version           Display version information.
```

### Devicekeys

Generate PRT and session key from a Deivce certificat. Have to join a device before. 

```cmd

SharpAzToken.exe devicekeys --help

  --pfxpath         Required. Specify path to device certificate (PFX).
  --tenant          Set Tenant
  --username        Set username
  --password        Set password
  --refreshtoken    Set Refreshtoken
  --clientid        (Default: 1b730954-1685-4b74-9bfd-dac224a7b894) Set ClientID
                    (ApplicationID), for example GraphAPI
                    (1b730954-1685-4b74-9bfd-dac224a7b894)
  --proxy           Set Proxy
  --help            Display this help screen.
  --version         Display version information.

```
