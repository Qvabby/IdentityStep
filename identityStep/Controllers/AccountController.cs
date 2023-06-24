using identityStep.Data;
using identityStep.Interfaces;
using identityStep.Models;
using identityStep.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace identityStep.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public readonly UserManager<IdentityUser> _userManager;
        public readonly SignInManager<IdentityUser> _signinManager;
        public readonly ApplicationDbContext _db;
        public readonly ICustomEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<IdentityUser> usermanager, SignInManager<IdentityUser> signinmanager, ApplicationDbContext db, ICustomEmailSender mailsender, UrlEncoder UrlEncoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = usermanager;
            _signinManager = signinmanager;
            _db = db;
            _emailSender = mailsender;
            _urlEncoder = UrlEncoder;
            _roleManager = roleManager;
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register(string? returnUrl = null)
        {
            if (!await _roleManager.RoleExistsAsync("Admin"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }
            List<SelectListItem> list = new List<SelectListItem>();

            var rolelist = _db.Roles.ToList();
            foreach (var role in rolelist)
            {
                list.Add(new SelectListItem() { Value = role.Name, Text = role.Name });
            }
            //list.Add(new SelectListItem() { Value = "Admin", Text = "Admin" });
            //list.Add(new SelectListItem() { Value = "User", Text = "User" });

            ViewData["ReturnUrl"] = returnUrl;

            var registerViewModel = new RegisterViewModel() { RoleList = list};
            return View(registerViewModel);
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            var User = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name, DateCreated = DateTime.Now };
            var result = await _userManager.CreateAsync(User, model.Password);
            if (result.Succeeded)
            {
                if (!string.IsNullOrWhiteSpace(model.SelectedListItem) && model.SelectedListItem == "Admin")
                {
                    await _userManager.AddToRoleAsync(User, "Admin");
                }
                else
                {
                    await _userManager.AddToRoleAsync(User, "User");
                }
                //await _SignuserManager.SignInAsync()
                await _signinManager.SignInAsync(User, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            List<SelectListItem> list = new List<SelectListItem>();
            var rolelist = _db.Roles.ToList();
            foreach (var role in rolelist)
            {
                list.Add(new SelectListItem() { Value = role.Name, Text = role.Name });
            }

            model.RoleList = list;
            AddError(result);
            return View(model);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? ReturnUrl = null)
        {
            ViewData["ReturnUrl"] = ReturnUrl;
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string? ReturnUrl = null)
        {
            ViewData["ReturnUrl"] = ReturnUrl;
            ReturnUrl = ReturnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var result = await _signinManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = _db.aplicationUsers.FirstOrDefault(x => x.Email.ToLower() == model.Email.ToLower());
                    var claims = await _userManager.GetClaimsAsync(user);
                    if (claims.Count > 0)
                    {
                        await _userManager.RemoveClaimAsync(user,claims.FirstOrDefault(x => x.Type == "FirstName"));
                    }
                    await _userManager.AddClaimAsync(user, new Claim("FirstName", user.Name));
                    return LocalRedirect(ReturnUrl);
                }
                else if (result.IsLockedOut)
                {
                    var user = _db.aplicationUsers.FirstOrDefault(u => u.Email == model.Email);
                    var time = user.LockoutEnd - DateTime.UtcNow;
                    var Seconds = time.Value.Seconds;
                    var Minutes = time.Value.Minutes;
                    string ErrorMessage = $"Hello {user.Email}. Your Account is Locked for {Minutes} Minutes {Seconds} seconds";
                    ModelState.AddModelError(string.Empty, ErrorMessage);
                    return View(model);
                }
            }
            return RedirectToAction("Login");
        }
        [HttpPost]
        public async Task<IActionResult> LogOut()
        {
            await _signinManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                //password reseting token
                var Token = await _userManager.GeneratePasswordResetTokenAsync(user);
                //callback url which creates url of reseting password
                var CallbackUrl = Url.Action("ResetPassword", "Account", new { UserId = user.Id, Code = Token }, protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Your Password - ItStep", $"Please Reset your password by clicking this link: <a href=\" {CallbackUrl} \">Click Here</a>");
                return RedirectToAction("ForgotPasswordConfirmation");
            }
            return RedirectToAction("Error", "Home");
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string Code = null, string UserId = null)
        {
            return Code == null ? RedirectToAction("Error", "Home") : View();
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.UserId.ToString());
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirmation");
                }
            }
            return RedirectToAction("Error", "Home");
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action("ExternalLoginCallBack", "Account", new { ReturnUrl = returnUrl });
            var properties = _signinManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallBack(string? returnUrl, string? remoteError)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"error from external provder: {remoteError}");
                return View(nameof(Login));
            }
            var info = await _signinManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Login));
            }
            var result = await _signinManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            if (result.Succeeded)
            {
                //if user have an account
                await _signinManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnUrl);
            }
            //if two factor is enabled.
            else if (result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticationCode", new { ReturnUrl = returnUrl });
            }
            else
            {
                //if user doesnt have an account
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var _email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var _name = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = _email, Name = _name });
            }
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string? ReturnUrl)
        {
            ReturnUrl = ReturnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                //Get info about the user from external login provider
                var info = await _signinManager.GetExternalLoginInfoAsync();
                if (info == null) { return RedirectToAction("Error", "Home"); }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name, DateCreated = DateTime.Now };
                //create an user
                var result = await _userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await _signinManager.SignInAsync(user, isPersistent: false);
                        await _signinManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(ReturnUrl);
                    }
                    AddError(result);
                }
            }
            ViewData["ReturnUrl"] = ReturnUrl;
            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            //0 - issuer, 1 - email, 2 - secret
            string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits6";
            //getting user global user
            var user = await _userManager.GetUserAsync(User);
            //reseting any previously registered authentications
            await _userManager.ResetAuthenticatorKeyAsync(user);
            //
            var token = await _userManager.GetAuthenticatorKeyAsync(user);

            string authenticationUri = string.Format(authenticatorUriFormat, _urlEncoder.Encode("identityStep"), _urlEncoder.Encode(user.Email), token);
            var model = new TwoFactorAuthenticationViewModel { Token = token,QRCodeURL = authenticationUri };

            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> DisableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index),"Home");
        }
        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null) { return RedirectToAction("Error", "Home"); }
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                    return RedirectToAction(nameof(AuthenticationConfirmation));
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code is not valid.");
                    return View(model);
                }
            }
            return View(model);
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult AuthenticationConfirmation()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticationCode(bool rememberMe, string ReturnUrl)
        {
            //check if user using twofactor
            var user = await _signinManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToAction("Error", "Home");
            }
            ViewData["returnUrl"] = ReturnUrl;
            return View(new VerifyAuthenticationViewModel { returnUrl = ReturnUrl, rememberMe = rememberMe });
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> VerifyAuthenticationCode(VerifyAuthenticationViewModel model)
        {
            model.returnUrl = model.returnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signinManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.rememberMe, false);

            if (result.Succeeded)
            {
                return LocalRedirect(model.returnUrl);
            }
            else if (result.IsLockedOut)
            {

                string ErrorMessage = "locked";
                ModelState.AddModelError(string.Empty, ErrorMessage);
                return View(model);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid Code");
                return View(model);
            }
        }
        private void AddError(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }


    }
}
