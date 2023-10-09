using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TopNewsApi.Core.DTO_s.User;
using TopNewsApi.Core.Services;
using TopNewsApi.Core.Validations.User;
using TopNewsApi.Core.DTO_s.Token;
using TopNewsApi.Core.Validations.Token;

namespace TopNewsApi.Api.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserService _userService;
        public UserController(UserService userService)
        {
            _userService = userService;
        }

        [Authorize(Roles = "Administrator")]
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUserAsync([FromBody] RegisterUserDto model)
        {
            //var validator = new RegisterUserValidation();
            //var validationResult = validator.Validate(model);
            //if (validationResult.IsValid)
            //{
                var result = await _userService.RegisterUserAsync(model);

                return Ok(result);
            //}
            //else
            //{
            //    return BadRequest(validationResult.Errors);
            //}
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> LoginUserAsync([FromBody] LoginUserDto model)
        {
            var validator = new LoginUserValidation();
            var validationResult = validator.Validate(model);
            if (validationResult.IsValid)
            {
                var result = await _userService.LoginUserAsync(model);
                return Ok(result);
            }
            else
            {
                return BadRequest(validationResult.Errors);
            }
        }

        [AllowAnonymous]
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmailAsync(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return NotFound();

            var result = await _userService.ConfirmEmailAsync(userId, token);

            if (result.Success)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [AllowAnonymous]
        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPasswordAsync([FromBody] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return NotFound();
            }

            var result = await _userService.ForgotPasswordAsync(email);

            if (result.Success)
            {
                return Ok(result);
            }
            else
            {
                return BadRequest(result);
            }
        }

        [AllowAnonymous]
        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPasswordAsync([FromForm] ResetPasswordDto model)
        {
            //var validator = new ResetPasswordValidation();
            //var validationResult = await validator.ValidateAsync(model);
            //if (validationResult.IsValid)
            //{
                var result = await _userService.ResetPasswordAsync(model);
                return Ok(result);

            //    if (result.Success)
            //    {
            //        return Ok(result);
            //    }
            //    return BadRequest(result);
            //}
            //else
            //{
            //    return BadRequest(validationResult.Errors);
            //}
        }

        [AllowAnonymous]
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] TokenRequestDto model)
        {
            var validator = new TokenRequestValidation();
            var validationResult = await validator.ValidateAsync(model);
            if (validationResult.IsValid)
            {
                var result = await _userService.RefreshTokenAsync(model);
                if (result.Success)
                {
                    return Ok(result);
                }
                return BadRequest(result);
            }
            else
            {
                return BadRequest(validationResult.Errors);
            }

        }

        [Authorize(Roles = "Administrator")]
        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsersAsync()
        {
            var result = await _userService.GetAllUsersAsync();
            if (result.Success)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [Authorize]
        [HttpGet("logout")]
        public async Task<IActionResult> LogoutUserAsync(string userId)
        {
            var result = await _userService.LogoutUserAsync(userId);
            if (result.Success)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [Authorize]
        [HttpPost("ChangePassword")]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordDto model)
        {
            //var validator = new ChangePasswordValidation();
            //var validationResult = await validator.ValidateAsync(model);
            //if (validationResult.IsValid)
            //{
                var result = await _userService.ChangePasswordAsync(model);
                return Ok(result);
            //}
            //else
            //{
            //    return BadRequest(validationResult.Errors);
            //}
        }
        [Authorize]
        [HttpPost("UpdateProfile")]
        public async Task<IActionResult> UpdateProfileAsync([FromBody] UpdateProfileDto model)
        {
            //var validator = new UpdateProfileValidation();
            //var validationResult = await validator.ValidateAsync(model);
            //if (validationResult.IsValid)
            //{
                var result = await _userService.UpdateProfileAsync(model);
                return Ok(result);
            //}
            //else
            //{
            //    return BadRequest(validationResult.Errors);
            //}
        }

        [Authorize(Roles = "Administrator")]
        [HttpPost("UpdateUser")]
        public async Task<IActionResult> UpdateUserAsync([FromBody] UpdateUserDto model)
        {
            //var validator = new UpdateUserValidation();
            //var validationResult = await validator.ValidateAsync(model);
            //if (validationResult.IsValid)
            //{
                var result = await _userService.UpdateUserAsync(model);
                return Ok(result);
            //}
            //else
            //{
            //    return BadRequest(validationResult.Errors);
            //}
        }

        [Authorize(Roles = "Administrator")]
        [HttpPost("DeleteUser")]
        public async Task<IActionResult> DeleteUserAsync([FromBody] string id)
        {
            var result = await _userService.DeleteUserAsync(id);
            if (result.Success)
            {
                return Ok(result);
            }
            else
            {
                return BadRequest(result);
            }
        }
    }
}
