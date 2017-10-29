using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Cryptopia.Api
{
    public class PrivateApi : IPrivateApi
	{
		private async Task<string> CallPrivateApiAsync(string requestUri, string apiKey, string apiSecret, string jsonPostData)
		{
            var request = new HttpRequestMessage()
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(requestUri),
                Content = new StringContent(jsonPostData, Encoding.UTF8, "application/json")
            };

            using (request)
            {
                if (object.ReferenceEquals(request.Content, null))
                {
                    return string.Empty;
                }

                string requestContentBase64String = string.Empty;

                using (var md5 = MD5.Create())
                {
                    requestContentBase64String = Convert.ToBase64String(md5.ComputeHash(await request.Content.ReadAsByteArrayAsync()));
                }

                // create random nonce for each request
                var nonce = Guid.NewGuid().ToString("N");

                // creating the raw signature string
                var signatureString = string.Concat(apiKey, HttpMethod.Post, HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower()), nonce, requestContentBase64String);
                var signature = Encoding.UTF8.GetBytes(signatureString);

                using (var hmac = new HMACSHA256(Convert.FromBase64String(apiSecret)))
                {
                    string headerValue = string.Format("{0}:{1}:{2}", apiKey, Convert.ToBase64String(hmac.ComputeHash(signature)), nonce);
                    request.Headers.Authorization = new AuthenticationHeaderValue("amx", headerValue);
                }

                // send request
                using (var client = new HttpClient())
                {
                    var response = await client.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        return await response.Content.ReadAsStringAsync();
                    }
                }

                return string.Empty;
            }
		}

		public string CallPrivateApi(string requestUri, string apiKey, string apiSecret, string jsonPostData)
		{
			if (string.IsNullOrWhiteSpace(requestUri) || string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(apiSecret) || string.IsNullOrWhiteSpace(jsonPostData))
			{
				return string.Empty;
			}

			return CallPrivateApiAsync(requestUri, apiKey, apiSecret, jsonPostData).Result;
		}
	}
}
