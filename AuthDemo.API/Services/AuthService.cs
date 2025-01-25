using AuthDemo.API.Context;
using AuthDemo.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthDemo.API.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ExtendedIdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ExtendedIdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task<IdentityResult> Register(LoginUser user)
        {
            var identityUser = new ExtendedIdentityUser
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
            response.JwtToken = GenerateTokenString(user.UserName);
            response.RefreshToken = GenerateRefreshTokenString();

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddHours(12);
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        public async Task<IdentityResult?> DeleteUser(string userEmail)
        {
            var identityUser = await _userManager.FindByEmailAsync(userEmail);
            if(identityUser is null)
            {
                return null;
            }

            return await _userManager.DeleteAsync(identityUser);

        }

        private string GenerateRefreshTokenString()
        {
            var randomNomber = new byte[64];

            using (var numberGenerator = RandomNumberGenerator.Create())
            {
                numberGenerator.GetBytes(randomNomber);
            }

            return Convert.ToBase64String(randomNomber);
        }

        public string GenerateTokenString(string userName)
        {
            var key = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(key))
            {
                throw new InvalidOperationException("JWT key is not configured.");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, userName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var signingCred = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha512);
            SecurityToken securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddSeconds(60),
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                signingCredentials: signingCred
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
        }

        public async Task<LoginResponse> RefreshToken(RefreshTokenModel model)
        {
            var response = new LoginResponse();

            var principal = GetTokenPrincipal(model.JwtToken);
            var emailClaim = principal?.FindFirst(ClaimTypes.Email);
            var email = emailClaim?.Value;

            if (email == null)
            {
                return response;
            }

            var identityUser = await _userManager.FindByEmailAsync(email);

            if(identityUser is null || identityUser.RefreshToken != model.RefreshToken || identityUser.RefreshTokenExpiry < DateTime.Now)
            {
                return response;
            }

            response.IsLoggedIn = true;
            response.JwtToken = GenerateTokenString(identityUser.UserName ?? string.Empty);
            response.RefreshToken = GenerateRefreshTokenString();

            identityUser.RefreshToken = response.RefreshToken;
            identityUser.RefreshTokenExpiry = DateTime.Now.AddHours(12);
            await _userManager.UpdateAsync(identityUser);

            return response;
        }

        private ClaimsPrincipal? GetTokenPrincipal(object token)
        {
            var principal = new JwtSecurityTokenHandler().ValidateToken(token.ToString(), new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidAudience = _configuration["Jwt:Audience"]
            }, out var validatedToken);

            return principal;
        }
    }
}
