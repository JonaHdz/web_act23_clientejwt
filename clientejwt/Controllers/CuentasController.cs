using clientejwt.Models;
using clientejwt.Services.Backend;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace clientejwt.Controllers
{
    [Authorize]
    public class CuentasController : Controller
    {
        private readonly IBackend _backend;

        public CuentasController(IBackend backend)
        {
            _backend = backend;
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginAsync(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var authUser = await _backend.AutenticacionAsync(model.Correo, model.Password);

                    if (authUser == null)
                    {
                        ModelState.AddModelError("Correo", "Credenciales no válidas. Inténtelo nuevamente.");
                    }
                    else
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, authUser.Email),
                            new Claim(ClaimTypes.GivenName, authUser.Nombre),
                            new Claim(ClaimTypes.Email, authUser.Email),
                            new Claim("token", authUser.AccessToken),
                            new Claim(ClaimTypes.Role, authUser.Rol),
                        };

                        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var authProperties = new AuthenticationProperties();
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
                        return RedirectToAction("Index", "Home");
                    }
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError(string.Empty, ex.Message);
                }
            }
            return View(model);
        }

        public async Task<IActionResult> PerfilAsync()
        {
            var token = User.FindFirstValue("token");
            var correo = User.FindFirstValue(ClaimTypes.Email);
            ViewData["token"] = User.FindFirstValue("token");

            var usuario = await _backend.GetUsuarioAsync(correo, token);

            return View(usuario);
        }

        public async Task<IActionResult> LogoutAsync(string returnUrl = null)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (returnUrl != null)
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Login");
            }
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}