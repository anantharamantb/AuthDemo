using Microsoft.AspNetCore.Identity;

namespace AuthDemo.API.Models;

public class ExtendedIdentityUser : IdentityUser
{
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiry { get; set; }

}