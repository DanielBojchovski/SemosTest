using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SemosTest.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SemosTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        public AuthController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
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
            IdentityUser? user = await _userManager.FindByEmailAsync(request.Email);

            if (user is not null)
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

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            IdentityUser? user = await _userManager.FindByEmailAsync(request.Email);

            if (user is null)
            {
                return Unauthorized("Invalid credentials");
            }

            bool isPasswordCorrect = await _userManager.CheckPasswordAsync(user, request.Password);

            if (isPasswordCorrect is false)
            {
                return Unauthorized("Invalid credentials");
            }

            IList<string> userRoles = await _userManager.GetRolesAsync(user);

            List<Claim> authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name, user.UserName ?? ""),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim("email", user.Email ?? "")
            };

            foreach (string userRole in userRoles)
            {
                authClaims.Add(new Claim("roles", userRole));
            }

            string token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);
        }

        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            SymmetricSecurityKey authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtOptions:SecretKey"]!));

            JwtSecurityToken tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JwtOptions:Issuer"],
                    audience: _configuration["JwtOptions:Audience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }
    }
}
