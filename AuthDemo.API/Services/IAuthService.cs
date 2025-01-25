using AuthDemo.API.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthDemo.API.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> Login(LoginUser user);
        Task<IdentityResult> Register(LoginUser user);
        string GenerateTokenString(string userName);
        Task<IdentityResult?> DeleteUser(string userEmail);
        Task<LoginResponse> RefreshToken(RefreshTokenModel model);
    }
}