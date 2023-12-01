using clientejwt.Models;

namespace clientejwt.Services.Backend
{
    public interface IBackend
    {
        public Task<List<UsuarioViewModel>> GetUsuariosAsync(string accessToken);
        public Task<AuthUser> AutenticacionAsync(string correo, string password);
        public Task<UsuarioViewModel> GetUsuarioAsync(string correo, string accessToken);
    }
}
