using System;

namespace Cryptopia.Api
{
	public interface IPrivateApi
	{
		string CallPrivateApi(string requestUri, string apiKey, string apiSecret, string jsonPostData);
	}
}
