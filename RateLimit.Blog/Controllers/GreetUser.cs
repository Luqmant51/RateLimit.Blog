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
        public IActionResult GreetAuthenticatedUser()
        {
            var userNameClaim = User.FindFirst(ClaimTypes.Name)?.Value;
            var greeting = $"Hello, {userNameClaim}!";

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
            var greeting = $"Hello, Guest!";
            var response = new
            {
                Greeting = greeting,
            };
            _logger.LogWarning("Response: {@Response}", response);
            return await Task.FromResult<IActionResult>(Ok(response));
        }
    }
}
