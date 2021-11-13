using System;
using System.Collections.Generic;
using System.Text;

namespace SharpAzToken.Models
{
  
    public class DeviceEnrollmentReq
    {
        public string TransportKey { get; set; }
        public int JoinType { get; set; }
        public string DeviceDisplayName { get; set; }
        public string OSVersion { get; set; }
        public Certificaterequest CertificateRequest { get; set; }
        public string TargetDomain { get; set; }
        public string DeviceType { get; set; }
        public Attributes Attributes { get; set; }
    }

    public class Certificaterequest
    {
        public string Type { get; set; }
        public string Data { get; set; }
    }

    public class Attributes
    {
        public string ReuseDevice { get; set; }
        public string ReturnClientSid { get; set; }
        public string SharedDevice { get; set; }
    }
}