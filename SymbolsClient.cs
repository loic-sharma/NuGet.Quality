using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace NuGet.Quality
{
    public class SymbolsClient
    {
        private readonly HttpClient _httpClient;
        private readonly Uri _serverUri;

        public SymbolsClient(HttpClient httpClient, Uri serverUri)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _serverUri = serverUri ?? throw new ArgumentNullException(nameof(serverUri));
        }

        public async Task<Stream> GetSymbolsAsync(string key, IReadOnlyList<string> checksums, CancellationToken cancellationToken)
        {
            var uri = new Uri(_serverUri, key);

            using var request = new HttpRequestMessage();
            request.Method = HttpMethod.Get;
            request.RequestUri = uri;

            if (checksums.Any())
            {
                request.Headers.Add("SymbolChecksum", string.Join(";", checksums));
            }

            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            return await response.Content.ReadAsStreamAsync();
        }
    }
}
