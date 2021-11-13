using System;
using System.Collections.Generic;
using System.Text;

namespace SharpAzToken.Models
{
    public class DeviceEnrollmentResp
    {
        public Certificate Certificate { get; set; }
        public User User { get; set; }
        public Membershipchange[] MembershipChanges { get; set; }
    }

    public class Certificate
    {
        public string Thumbprint { get; set; }
        public string RawBody { get; set; }
    }

    public class User
    {
        public string Upn { get; set; }
    }

    public class Membershipchange
    {
        public string LocalSID { get; set; }
        public string[] AddSIDs { get; set; }
    }

}
