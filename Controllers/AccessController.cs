using System.Security.Claims;
using Backend.Util;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers
{
    /// <summary>
    /// Not an API Controller
    /// </summary>
    [Route("access")]
    public class AccessController(ILogger<AccessController> logger, IConfiguration configuration) : Controller
    {
        private readonly ILogger<AccessController> _logger = logger;
        private readonly string _access_secret = configuration["Access:SecretHash"];

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Get(string token = null, string returnUrl = null)
        {
            // Skip authentication only if user is already authenticated and no token is passed.
            // If user is authenticated and a token is passed, renew cookie
            if (!User.Identity.IsAuthenticated || null != token)
            {
                if (string.IsNullOrWhiteSpace(token)) 
                {
                    _logger.LogInformation("access denied: token missing");
                    return Unauthorized("access denied");
                }

                if (!SecretHasher.VerifyHashString(token, _access_secret))
                {
                    _logger.LogInformation("access denied: token invalid");
                    return Unauthorized("access denied");
                }

                // no claims required
                var defaultPrincipal = new ClaimsPrincipal(new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme));
                var keepCookieWhenBrowserIsClosed = new AuthenticationProperties { IsPersistent = true };
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, defaultPrincipal, keepCookieWhenBrowserIsClosed);
                _logger.LogInformation("access granted");
            }

            return Redirect(returnUrl ?? "~/");
        }

        #if DEBUG

        /// <summary>
        /// Use this endpoint together with swagger ui in DEV environment to compute a hash that can be configured under 'Access:SecretHash'
        /// </summary>
        /// <param name="input">The 'password'-token, that has to be included in links to grant access (like '/access?token=Pa$$w0rd')</param>
        /// <param name="iterations">For rudimentary security requirements like in this app, this may be way lower than recommended 10000 for password storage.</param>
        /// <returns>The hash string that can be put in configuration</returns>
        [AllowAnonymous]
        [HttpPost("ComputeHashString")]
        public IActionResult ComputeHashString(string input, int? iterations = null)
        {
            return Ok(SecretHasher.ComputeHashString(input, iterations));
        }

        #endif
    }
}