using clientejwt.Models;
using clientejwt.Services.Backend;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace clientejwt.Controllers
{
    public class HomeController : Controller
    {
        private readonly IBackend _backend;

        public HomeController(IBackend backend)
        {
            _backend = backend;
        }

        public async Task<IActionResult> IndexAsync()
        {
            var token = User.FindFirstValue("token");
            var usuarios = await _backend.GetUsuariosAsync(token);
            return View(usuarios);
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}