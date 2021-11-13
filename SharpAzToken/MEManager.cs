using SharpAzToken.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace SharpAzToken
{
    class MEManager
    {
        public static DeviceEnrollmentResp addNewDeviceToAzure(string proxy, string accesstoken, string certificaterequest, string transportKey, string targetDomain, string deviceDisplayName, bool registerDevice)
        {
            using (var client = Helper.getDefaultClient(proxy, false, "https://enterpriseregistration.windows.net"))
            using (var message = new HttpRequestMessage(HttpMethod.Post, "/EnrollmentServer/device/?api-version=1.0"))
            {
                //message.Headers.Add("Authorization", "Bearer " + accesstoken);
                message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accesstoken);
                message.Headers.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");

                int jointype = 0;
                if (registerDevice)
                {
                    jointype = 4;
                }

                var body = new DeviceEnrollmentReq
                {
                    TransportKey = transportKey,
                    JoinType = jointype,
                    DeviceDisplayName = deviceDisplayName,
                    OSVersion = "10.0.19041.804",
                    CertificateRequest = new Certificaterequest
                    {
                        Data = certificaterequest,
                        Type = "pkcs10"
                    },
                    TargetDomain = targetDomain,
                    DeviceType = "Windows",
                    Attributes = new Attributes
                    {
                        ReturnClientSid = "true",
                        ReuseDevice = "true",
                        SharedDevice = "false"
                    }
                };

                var content = new StringContent(JsonConvert.SerializeObject(body, Formatting.Indented));
                message.Content = content;
                var response = client.SendAsync(message).Result;
                if (response.IsSuccessStatusCode)
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    var devEnrollmentResp = JsonConvert.DeserializeObject<DeviceEnrollmentResp>(result);
                    return devEnrollmentResp;
                }
            }
            return null;
        }

        public static int MarkDeviceAsCompliant(string ObjectID, String accesstoken, String Proxy)
        {
            String tenantid = Helper.GetTenantFromAccessToken(accesstoken);
            String uri = "/" + tenantid + "/devices/" + ObjectID + "?api-version=1.61-internal";
            return Helper.PatchRequest(uri, accesstoken, Proxy);
        }
    }
}
