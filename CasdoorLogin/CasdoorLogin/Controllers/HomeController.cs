using Microsoft.AspNetCore.Mvc;

namespace CasdoorLogin.Controllers
{
    public sealed class HomeController : Controller
    {
        [HttpGet("/")]
        public IActionResult Index() => View();
    }
}
