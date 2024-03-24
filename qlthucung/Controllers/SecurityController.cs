using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using qlthucung.Models;
using qlthucung.Security;

namespace qlthucung.Controllers
{
    public class SecurityController : Controller
    {
        private readonly UserManager<AppIdentityUser> userManager;
        private readonly SignInManager<AppIdentityUser> signInManager;
        private readonly RoleManager<AppIdentityRole> roleManager;

        public SecurityController(UserManager<AppIdentityUser> userManager,
            SignInManager<AppIdentityUser> signInManager,
            RoleManager<AppIdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(Register register)
        {
            if (ModelState.IsValid)
            {
                var user = new AppIdentityUser
                {
                    UserName = register.UserName,
                    Email = register.Email,
                    FullName = register.FullName,
                    BirthDate = register.BirthDate
                };

                // Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
                var passwordHasher = new PasswordHasher<AppIdentityUser>();
                user.PasswordHash = passwordHasher.HashPassword(user, register.Password);

                var result = await userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    // Kiểm tra và tạo vai trò "Customer" nếu chưa tồn tại
                    var customerRoleExists = await roleManager.RoleExistsAsync("Customer");
                    if (!customerRoleExists)
                    {
                        var role = new AppIdentityRole
                        {
                            Name = "Customer",
                            Description = "Regular customer role"
                        };
                        await roleManager.CreateAsync(role);
                    }

                    // Thêm người dùng vào vai trò "Customer"
                    await userManager.AddToRoleAsync(user, "Customer");

                    await signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToAction("Index", "SanPham");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }

            return View(register);
        }

        [HttpGet]
        public IActionResult SignIn()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignIn(SignIn signIn)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(signIn.UserName, signIn.Password, signIn.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    HttpContext.Session.SetString("username", signIn.UserName);
                    return RedirectToAction("Index", "SanPham");
                }

                ModelState.AddModelError("", "Tên tài khoản hoặc mật khẩu không chính xác!");
            }

            return View(signIn);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> SignOut()
        {
            await signInManager.SignOutAsync();
            HttpContext.Session.Remove("username");
            return RedirectToAction("SignIn", "Security");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
