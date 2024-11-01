using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SemosTest.Models;

namespace SemosTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        [HttpGet("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }

        [Authorize(Roles = StaticUserRoles.USER)]
        [HttpGet("UserGet")]
        public IActionResult UserGet()
        {
            return Ok("User data");
        }

        [Authorize(Roles = StaticUserRoles.ADMIN)]
        [HttpGet("AdminGet")]
        public IActionResult AdminGet()
        {
            return Ok("Admin secret data");
        }
    }
}
