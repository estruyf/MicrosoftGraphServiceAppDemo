using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using RestSharp;

namespace EStruyf.DaemonApplication
{
    class Program
    {
        private static readonly string GraphUrl = ConfigurationManager.AppSettings["GraphUrl"];
        private static readonly string ClientId = ConfigurationManager.AppSettings["ClientId"];
        private static readonly string Authority = ConfigurationManager.AppSettings["Authority"];
        private static readonly string Thumbprint = ConfigurationManager.AppSettings["Thumbprint"];

        static void Main(string[] args)
        {
            if (!string.IsNullOrEmpty(Thumbprint) && 
                !string.IsNullOrEmpty(GraphUrl) && 
                !string.IsNullOrEmpty(ClientId) && 
                !string.IsNullOrEmpty(Authority))
            {
                // Retrieve the certificate
                var certificate = GetCertificate();
                if (certificate != null)
                {
                    // Get an access token
                    var token = GetAccessToken(certificate);
                    if (!string.IsNullOrEmpty(token.Result))
                    {
                        // Fetch the latest events
                        var client = new RestClient(GraphUrl);
                        var request = new RestRequest("/v1.0/users/{UserId or UserPrincipleName}}/Events", Method.GET);
                        request.AddHeader("Authorization", "Bearer " + token.Result);
                        request.AddHeader("Content-Type", "application/json");
                        request.AddHeader("Accept", "application/json");

                        var response = client.Execute(request);
                        var content = response.Content;

                        Console.WriteLine(content);
                    }
                }
            }
        }

        private static X509Certificate2 GetCertificate()
        {
            X509Certificate2 certificate = null;
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, false);
            // Get the first cert with the thumbprint
            if (certCollection.Count > 0)
            {
                certificate = certCollection[0];
            }
            certStore.Close();
            return certificate;
        }

        private static async Task<string> GetAccessToken(X509Certificate2 certificate)
        {
            var authenticationContext = new AuthenticationContext(Authority, false);
            var cac = new ClientAssertionCertificate(ClientId, certificate);
            var authenticationResult = await authenticationContext.AcquireTokenAsync(GraphUrl, cac);
            return authenticationResult.AccessToken;
        }
    }
}
