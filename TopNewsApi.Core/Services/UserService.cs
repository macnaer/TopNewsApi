using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TopNewsApi.Core.DTO_s.Token;
using TopNewsApi.Core.DTO_s.User;
using TopNewsApi.Core.Entities.Tokens;
using TopNewsApi.Core.Entities.User;

namespace TopNewsApi.Core.Services
{
    public class UserService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private IConfiguration _configuration;
        private readonly EmailService _emailService;
        private readonly JwtService _jwtService;
        private readonly IMapper _mapper;

        public UserService(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, JwtService jwtService, IConfiguration configuration, EmailService emailService, IMapper mapper)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailService = emailService;
            _jwtService = jwtService;
            _mapper = mapper;
        }
        public async Task<ServiceResponse> RegisterUserAsync(RegisterUserDto model)
        {

            if (model.Password != model.ConfirmPassword)
            {
                return new ServiceResponse
                {
                    Message = "Confirm pssword do not match",
                    Success = false
                };
            }

            var newUser = _mapper.Map<RegisterUserDto, AppUser>(model);
            var result = await _userManager.CreateAsync(newUser, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(newUser, model.Role);

                await SendConfirmationEmailAsync(newUser);

                var tokens = await _jwtService.GenerateJwtTokensAsync(newUser);

                return new ServiceResponse
                {
                    Message = "User successfully created.",
                    Success = true
                };
            }
            else
            {
                return new ServiceResponse
                {
                    Message = "Error user not created.",
                    Success = false,
                    Errors = result.Errors.Select(e => e.Description)
                };
            }
        }

        public async Task SendConfirmationEmailAsync(AppUser newUser)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

            var encodedEmailToken = Encoding.UTF8.GetBytes(token);
            var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

            string url = $"{_configuration["HostSettings:URL"]}/api/User/confirmemail?userid={newUser.Id}&token={validEmailToken}";

            string emailBody = $"<h1>Confirm your email</h1> <a href='{url}'>Confirm now</a>";
            await _emailService.SendEmailAsync(newUser.Email, "Email confirmation.", emailBody);
        }

        public async Task<ServiceResponse> LoginUserAsync(LoginUserDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "Login or password incorrect.",
                    Success = false
                };
            }

            var signInResult = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (signInResult.Succeeded)
            {

                var tokens = await _jwtService.GenerateJwtTokensAsync(user);

                return new ServiceResponse
                {
                    AccessToken = tokens.Token,
                    RefreshToken = tokens.refreshToken.Token,
                    Message = "Logged in successfully",
                    Success = true,
                };
            }
            if (signInResult.IsNotAllowed)
            {
                return new ServiceResponse
                {
                    Message = "User cannot sign in without a confirmed email.",
                    Success = false,
                };

            }
            if (signInResult.IsLockedOut)
            {
                return new ServiceResponse
                {
                    Message = "User is blocked",
                    Success = false
                };
            }

            return new ServiceResponse
            {
                Message = "Login or password incorrect.",
                Success = false,
            };

        }

        public async Task<ServiceResponse> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new ServiceResponse
                {
                    Success = false,
                    Message = "User not found"
                };

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(user, normalToken);

            if (result.Succeeded)
                return new ServiceResponse
                {
                    Message = "Email confirmed successfully!",
                    Success = true,
                };

            return new ServiceResponse
            {
                Success = false,
                Message = "Email did not confirm",
                Errors = result.Errors.Select(e => e.Description)
            };
        }

        public async Task<ServiceResponse> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "No user associated with email",
                    Success = false
                };
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Encoding.UTF8.GetBytes(token);
            var validToken = WebEncoders.Base64UrlEncode(encodedToken);

            string url = $"{_configuration["HostSettings:URL"]}/ResetPassword?email={email}&token={validToken}";
            string emailBody = "<h1>Follow the instructions to reset your password</h1>" + $"<p>To reset your password <a href='{url}'>Click here</a></p>";
            await _emailService.SendEmailAsync(email, "Fogot password", emailBody);

            return new ServiceResponse
            {
                Success = true,
                Message = $"Reset password for {_configuration["HostSettings:URL"]} has been sent to the email successfully!"
            };
        }

        public async Task<ServiceResponse> ResetPasswordAsync(ResetPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "No user associated with email",
                };
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                return new ServiceResponse
                {
                    Success = false,
                    Message = "Password doesn't match its confirmation",
                };
            }

            var decodedToken = WebEncoders.Base64UrlDecode(model.Token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ResetPasswordAsync(user, normalToken, model.NewPassword);
            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "Password has been reset successfully!",
                    Success = true,
                };
            }
            return new ServiceResponse
            {
                Message = "Something went wrong",
                Success = false,
                Errors = result.Errors.Select(e => e.Description),
            };
        }

        public async Task<ServiceResponse> RefreshTokenAsync(TokenRequestDto model)
        {
            var result = await _jwtService.VerifyTokenAsync(model);
            return result;
        }

        public async Task<ServiceResponse> GetAllUsersAsync()
        {
            List<AppUser> users;
           
            users = await _userManager.Users.ToListAsync();
            
           
            List<UsersDto> mappedUsers = users.Select(u => _mapper.Map<AppUser, UsersDto>(u)).ToList();

            for (int i = 0; i < users.Count; i++)
            {
                mappedUsers[i].Role = (await _userManager.GetRolesAsync(users[i])).FirstOrDefault();
            }

            return new ServiceResponse()
            {
                Success = true,
                Payload = mappedUsers,
                Message = "All users loaded."
            };
        }

        public async Task<ServiceResponse> LogoutUserAsync(string userId)
        {

            IEnumerable<RefreshToken> tokens = await _jwtService.GetAll();
            foreach (RefreshToken token in tokens)
            {
                await _jwtService.Delete(token);
            }

            await _signInManager.SignOutAsync();
            return new ServiceResponse()
            {
                Success = true,
                Message = "User successfully logged out."
            };
        }

        public async Task<ServiceResponse> ChangePasswordAsync(ChangePasswordDto model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "User not found.",
                    Success = false
                };
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                return new ServiceResponse
                {
                    Message = "Password do not match.",
                    Success = false
                };
            }

            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "Password successfully updated.",
                    Success = true,
                };
            }
            else
            {
                return new ServiceResponse
                {
                    Message = "Password not updated.",
                    Success = false,
                    Errors = result.Errors.Select(e => e.Description),
                };
            }
        }

        public async Task<ServiceResponse> UpdateProfileAsync(UpdateProfileDto model)
        {
            var user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "User not found.",
                    Success = false
                };
            }
            else
            {
                if (user.Email != model.Email)
                {
                    var res = await _userManager.FindByIdAsync(model.Id);
                    res.EmailConfirmed = false;
                    var confirmationResut = await _userManager.UpdateAsync(res);

                }

                var updatedUser = _mapper.Map<AppUser>(user);
                updatedUser.Email = model.Email;
                updatedUser.FirstName = model.Name;
                updatedUser.LasrName = model.Surname;
                updatedUser.PhoneNumber = model.Phone;
                updatedUser.UserName = model.Email;

                var result = await _userManager.UpdateAsync(updatedUser);
                if (result.Succeeded)
                {
                    var tokens = await _jwtService.GenerateJwtTokensAsync(updatedUser);

                    if (updatedUser.EmailConfirmed)
                    {
                        return new ServiceResponse
                        {
                            AccessToken = tokens.Token,
                            RefreshToken = tokens.refreshToken.Token,
                            Message = "User successfully updated.",
                            Success = true
                        };
                    }
                    else
                    {
                        await SendConfirmationEmailAsync(updatedUser);
                        return new ServiceResponse
                        {
                            AccessToken = tokens.Token,
                            RefreshToken = tokens.refreshToken.Token,
                            Message = "Confirm email please.",
                            Success = true
                        };
                    }
                }

                return new ServiceResponse
                {
                    Message = "Email possibly used. Try another email.",
                    Success = false,
                    Errors = result.Errors.Select(e => e.Description),
                };
            }
        }

        public async Task<ServiceResponse> UpdateUserAsync([FromBody] UpdateUserDto model)
        {
            var user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "User not found.",
                    Success = false
                };
            }
            else
            {
                if (user.Email != model.Email)
                {
                    var res = await _userManager.FindByIdAsync(model.Id);
                    res.EmailConfirmed = false;
                    var confirmationResut = await _userManager.UpdateAsync(res);

                }

                var currentRole = (await _userManager.GetRolesAsync(user)).FirstOrDefault();

                await _userManager.RemoveFromRoleAsync(user, currentRole);

                var updatedUser = _mapper.Map<AppUser>(user);
                updatedUser.Email = model.Email;
                updatedUser.FirstName = model.Name;
                updatedUser.LasrName = model.Surname;
                updatedUser.PhoneNumber = model.Phone;
                updatedUser.UserName = model.Email;

                await _userManager.AddToRoleAsync(updatedUser, model.Role);

                var result = await _userManager.UpdateAsync(updatedUser);
                if (result.Succeeded)
                {

                    if (updatedUser.EmailConfirmed)
                    {
                        return new ServiceResponse
                        {
                            Message = "User successfully updated.",
                            Success = true
                        };
                    }
                    else
                    {
                        await SendConfirmationEmailAsync(updatedUser);
                        return new ServiceResponse
                        {
                            Message = "Confirm email please.",
                            Success = true
                        };
                    }
                }

                return new ServiceResponse
                {
                    Message = "Email possibly used. Try another email.",
                    Success = false,
                    Errors = result.Errors.Select(e => e.Description),
                };

            }
        }

        public async Task<ServiceResponse> DeleteUserAsync(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return new ServiceResponse
                {
                    Message = "User not found.",
                    Success = false
                };
            }

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                return new ServiceResponse
                {
                    Message = "User successfully deleted.",
                    Success = true
                };
            }

            return new ServiceResponse
            {
                Message = "User NOT deleted.",
                Success = false
            };
        }

    }
}
