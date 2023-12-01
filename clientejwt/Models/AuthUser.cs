namespace clientejwt.Models
{
    public class AuthUser
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Nombre { get; set; }
        public string Rol { get; set; }
        public string AccessToken { get; set; }
    }
}
