using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;

namespace RateLimit.Blog.Controllers
{
    [ApiController]
    public class GreetUser : ControllerBase
    {
        private readonly ILogger<GreetUser> _logger;

        public GreetUser(ILogger<GreetUser> logger)
        {
            _logger = logger;
        }

        [HttpGet("auth")]
        [EnableRateLimiting("jwt")]
        [Authorize]
        public async Task<IActionResult> GreetAuthenticatedUser()
        {
            var userNameClaim = User.FindFirst(ClaimTypes.Name)?.Value;

            Console.WriteLine(User.Identity);
            var greeting = $"Hello, {userNameClaim}!";

            var token = Request.Headers["Authorization"].ToString();
            var tokenNumber = token.StartsWith("Bearer ") ? token.Substring(7) : token;

            var response = new
            {
                Greeting = greeting
            };
            _logger.LogWarning("Response: {@Response}", response);
            return Ok(response);
        }

        [HttpGet("anon")]
        [EnableRateLimiting("jwt")]
        public async Task<IActionResult> GreetUnAuthenticatedUser()
        {
            Console.WriteLine(User.Identity);
            var greeting = $"Hello, Guest!";

            var token = Request.Headers["Authorization"].ToString();
            var tokenNumber = token.StartsWith("Bearer ") ? token.Substring(7) : token;
            var response = new
            {
                Greeting = greeting,
            };
            _logger.LogWarning("Response: {@Response}", response);
            return await Task.FromResult<IActionResult>(Ok(response));
        }
    }
}
