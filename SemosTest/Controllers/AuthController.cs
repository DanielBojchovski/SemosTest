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
        private readonly UserManager<IdentityUser> _userManager;
        public AuthController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
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

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            IdentityUser? userExists = await _userManager.FindByEmailAsync(request.Email);

            if (userExists is not null)
            {
                return BadRequest("User already exists");
            }

            IdentityUser newUser = new IdentityUser
            {
                UserName = request.UserName,
                Email = request.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            IdentityResult createUserResult = await _userManager.CreateAsync(newUser, request.Password);

            if (createUserResult.Succeeded is false) 
            {
                string errorString = "User creation failsed because: ";
                foreach (IdentityError error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return BadRequest(errorString);
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User created");
        }
    }
}
