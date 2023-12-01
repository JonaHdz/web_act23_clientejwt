using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace clientejwt.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "El campo {0} es obligatorio.")]
        [EmailAddress(ErrorMessage = "El campo {0} no es correo válido.")]
        [Display(Name = "Correo electrónico")]
        public string Correo { get; set; }

        [Required(ErrorMessage = "El campo {0} es obligatorio.")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }
    }
}
