using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace WebAPI
{
    public class LoginModel
    {
            public string Username { get; set; }
            public string Password { get; set; }

    }
}