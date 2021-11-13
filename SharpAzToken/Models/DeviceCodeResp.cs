using System;
using System.Collections.Generic;
using System.Text;

namespace SharpAzToken.Models
{
    public class DeviceCodeResp
    {
        public string user_code { get; set; }
        public string device_code { get; set; }
        public string verification_url { get; set; }
        public int expires_in { get; set; }
        public int interval { get; set; }
        public string message { get; set; }
    }

}
