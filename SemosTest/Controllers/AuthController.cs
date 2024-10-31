using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SemosTest.Models;

namespace SemosTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public AuthController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        [HttpPost("SeedRoles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool userRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool adminRolesExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);

            if (userRolesExists && adminRolesExists) 
            { 
                return Ok("Seeding is already done"); 
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));

            return Ok("Role seeding completed");
        }
    }
}
