using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TopNewsApi.Core.DTO_s.User;
using TopNewsApi.Core.Entities.User;

namespace TopNewsApi.Core.Services
{
    public class UserService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        private readonly JwtService _jwtService;

        public UserService(JwtService jwtService, RoleManager<IdentityRole> roleManager, IConfiguration config, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IMapper mapper)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
            _config = config;
            _roleManager = roleManager;
            _jwtService = jwtService;
        }


        //public async Task<ServiceResponse> GetAllAsync()
        //{
        //    List<AppUser> users = await _userManager.Users.ToListAsync();
        //    List<UsersDto> mappedUsers = users.Select(u => _mapper.Map<AppUser, UsersDto>(u)).ToList();

        //    for (int i = 0; i < users.Count; i++)
        //    {
        //        mappedUsers[i].Role = (await _userManager.GetRolesAsync(users[i])).FirstOrDefault();
        //    }


        //    return new ServiceResponse
        //    {
        //        Success = true,
        //        Message = "All users loaded.",
        //        Payload = mappedUsers
        //    };
        //}

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

            var signinResult = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: true, lockoutOnFailure: true);
            if (signinResult.Succeeded)
            {
                var tokens = await _jwtService.GenerateJwtTokensAsync(user);
                return new ServiceResponse
                {
                    AccessToken = tokens.Token,
                    RefreshToken = tokens.refreshToken.Token,
                    Message = "User signed in successfully.",
                    Success = true
                };
            }

            if (signinResult.IsNotAllowed)
            {
                return new ServiceResponse
                {
                    Message = "Confirm your email please.",
                    Success = false
                };
            }

            if (signinResult.IsLockedOut)
            {
                return new ServiceResponse
                {
                    Message = "User is blocked connect to support.",
                    Success = false
                };
            }

            return new ServiceResponse
            {
                Message = "Login or password incorrect.",
                Success = false
            };
        }

        public async Task LogoutUserAsync()
        {
            await _signInManager.SignOutAsync();
        }

        //public async Task<List<IdentityRole>> LoadRoles()
        //{
        //    var roles = await _roleManager.Roles.ToListAsync();
        //    return roles;
        //}
    }
}
