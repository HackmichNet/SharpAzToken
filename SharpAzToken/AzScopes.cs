using System;
using System.Collections.Generic;
using System.Text;

namespace SharpAzToken
{
    public static class AzScopes
    {
        public static string ComplianceCenter = "https://ps.compliance.protection.outlook.com/.default offline_access openid profile";
        public static string ExchangeOnlineV2 = "openid offline_access profile https://outlook.office365.com/.default";
    }
}
