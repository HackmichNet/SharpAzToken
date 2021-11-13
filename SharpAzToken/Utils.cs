using SharpAzToken.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace SharpAzToken
{
    class Utils
    {
        public static String GetTenantIdToDomain(string Domain, String Proxy)
        {
            String result = null;
            result = Helper.GetOpenIDConfiguration(Domain, Proxy);
            if (result == null)
            {
                return null;
            }
            var resultParsed = JsonConvert.DeserializeObject<OpenIDConfigurationResp>(result);
            if (resultParsed.authorization_endpoint != null) { 
                result = resultParsed.authorization_endpoint.Split("/")[3];
            }else{
                return null;
            }
            return result;
        }

    }
}
