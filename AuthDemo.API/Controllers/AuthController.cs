using AuthDemo.API.Models;
using AuthDemo.API.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthDemo.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(LoginUser user)
        {
            var result = await _authService.Register(user);

            if (result.Succeeded)
            {
                return Ok("User registered successfully");
            }
            else
            {
                return BadRequest(result.Errors);

            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUser user)
        {
            var loginResult = await _authService.Login(user);

            if(loginResult.IsLoggedIn)
            {
                return Ok(loginResult);
            }

            return Unauthorized();
        }
    }
}
