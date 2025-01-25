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

        [HttpDelete]
        public async Task<ActionResult> DeleteUser(string userEmail)
        {
            await _authService.DeleteUser(userEmail);

            return NoContent();
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

        [HttpPost("refreshtoken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            var loginResult = await _authService.RefreshToken(model);

            if (loginResult.IsLoggedIn)
            {
                return Ok(loginResult);
            }

            return Unauthorized();
        }
    }
}
