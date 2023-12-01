using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace clientejwt.Models
{
    public class UsuarioViewModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "Nombre")]
        public string Nombrecompleto { get; set; }
        public string Rol { get; set; }
    }
}
