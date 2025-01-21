using AuthDemo.API.Context;
using AuthDemo.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthDemo.API.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task<IdentityResult> Register(LoginUser user)
        {
            var identityUser = new IdentityUser
            {
                UserName = user.UserName,
                Email = user.UserName
            };
            return await _userManager.CreateAsync(identityUser, user.Password);
        }

        public async Task<LoginResponse> Login(LoginUser user)
        {
            var response = new LoginResponse();
            var identityUser = await _userManager.FindByEmailAsync(user.UserName);
            if (identityUser is null || !await _userManager.CheckPasswordAsync(identityUser, user.Password))
            {
                return response;
            }
            response.IsLoggedIn = true;
            response.JwtToken = GenerateTokenString(user);

            return response;
        }

        public string GenerateTokenString(LoginUser user)
        {
            var key = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(key))
            {
                throw new InvalidOperationException("JWT key is not configured.");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var signingCred = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha512);
            SecurityToken securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(60),
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                signingCredentials: signingCred
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
        }
    }
}
