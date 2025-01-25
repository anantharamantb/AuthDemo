namespace AuthDemo.API.Models
{
    public class LoginResponse
    {
        public bool IsLoggedIn { get; set; } = false;
        public string JwtToken { get; set; } = string.Empty; 
        public string RefreshToken { get; internal  set; } = string.Empty; 
    }
}
