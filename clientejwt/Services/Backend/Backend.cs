using clientejwt.Models;
using Microsoft.Net.Http.Headers;
using System.Text.Json;
using System.Text;

namespace clientejwt.Services.Backend
{
    public class Backend : IBackend
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;

        public Backend(IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<AuthUser> AutenticacionAsync(string correo, string password)
        {
            AuthUser token = null;  
            LoginViewModel usuario = new()
            {
                Correo = correo,
                Password = password
            };
            StringContent jsonContent = new(JsonSerializer.Serialize(usuario), Encoding.UTF8, "application/json");
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["UrlWebAPI"]}/login")
            {
                Content = jsonContent
            };
            var httpClient = _httpClientFactory.CreateClient();
            try
            {
                var response = await httpClient.SendAsync(httpRequestMessage);

                if (response.IsSuccessStatusCode)
                {
                    token = await response.Content.ReadFromJsonAsync<AuthUser>();
                }
            }
            catch (Exception)
            {
            }

            return token;
        }

        public async Task<List<UsuarioViewModel>> GetUsuariosAsync(string accessToken)
        {
            List<UsuarioViewModel> usuarios = new();

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, $"{_configuration["UrlWebAPI"]}/home")
            {
                Headers = { { HeaderNames.Authorization, "Bearer " + accessToken } }
            };

            var httpClient = _httpClientFactory.CreateClient();

            try
            {
                var response = await httpClient.SendAsync(httpRequestMessage);

                if (response.IsSuccessStatusCode)
                {
                    usuarios = await response.Content.ReadFromJsonAsync<List<UsuarioViewModel>>();
                }
            }
            catch (Exception)
            {
            }

            return usuarios;
        }

        public async Task<UsuarioViewModel> GetUsuarioAsync(string correo, string accessToken)
        {
            UsuarioViewModel usuario = new();

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, $"{_configuration["UrlWebAPI"]}/home/{correo}")
            {
                Headers = { { HeaderNames.Authorization, "Bearer " + accessToken } },
            };

            var httpClient = _httpClientFactory.CreateClient();

            try
            {
                var response = await httpClient.SendAsync(httpRequestMessage);

                if (response.IsSuccessStatusCode)
                {
                    usuario = await response.Content.ReadFromJsonAsync<UsuarioViewModel>();
                }
            }
            catch (Exception)
            {
            }

            return usuario;
        }
    }
}
