using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult CreateToken([FromBody] LoginModel login)
        {
            if (login == null) return Unauthorized();
            string tokenString = string.Empty;
            bool validUser = Authenticate(login);
            if (validUser)
            {
                tokenString = BuildToken();
            }
            else
            {
                return Unauthorized();
            }
            return Ok(new { Token = tokenString });
        }

        private string BuildToken()
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtToken:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _config["JwtToken:Issuer"],
              _config["JwtToken:Issuer"],
              claims: new[] { new Claim("id", "123", "role", "administrator") },
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool Authenticate(LoginModel login)
        {
            bool validUser = false;
            /* Use Database connection query to to your DB and validate
            with user table and once, its found send boolean flag.
            and please  comment the below code  */
            if (login.Username == "thecodebuzz" && login.Password == "dont-tell-anyone")
            {
                validUser = true;
            }
            return validUser;
        }

        [HttpGet]
        
        public async Task<IEnumerable<string>> Get()
        {

            var accessToken = await HttpContext.GetTokenAsync("access_token");

            return new string[] { accessToken };
        }

    }
}
