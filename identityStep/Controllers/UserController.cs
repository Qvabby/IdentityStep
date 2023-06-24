using identityStep.Data;
using identityStep.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace identityStep.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }
        public IActionResult Index()
        {
            var userList = _db.aplicationUsers.ToList();
            var userRoles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach (var user in userList)
            {
                var role = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(r => r.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }

        [HttpGet]
        public IActionResult Edit(string id)
        {
            var usertoedit = _db.aplicationUsers.FirstOrDefault(u => u.Id == id);
            if (usertoedit == null)
            {
                return NotFound();
            }
            var userroles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userroles.FirstOrDefault(x => x.UserId == usertoedit.Id);
            if (role != null)
            {
                usertoedit.RoleId = roles.FirstOrDefault(x => x.Id == role.RoleId).Id;
            }
            usertoedit.RoleList = _db.Roles.Select(x => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Text = x.Name, Value = x.Id });
            return View(usertoedit);
        }
        [HttpPost]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            //if user isnot valid
            if (!ModelState.IsValid) { return View(user); }
            //getting user to edit
            var usertoedit = await _db.aplicationUsers.FirstOrDefaultAsync(x => x.Id == user.Id);
            //checking if its valid
            if (usertoedit == null)
            {
                TempData[SD.Error] = "User Not Found";
            }
            //get user role
            var userRole = await _db.UserRoles.FirstOrDefaultAsync(u => u.UserId == usertoedit.Id);
            if (userRole != null)
            {
                var previousRoleName = await _db.Roles.Where(x => x.Id == userRole.RoleId).Select(x => x.Name).FirstOrDefaultAsync();
                await _userManager.RemoveFromRoleAsync(usertoedit, previousRoleName);
            }
            //add new role
            await _userManager.AddToRoleAsync(usertoedit, _db.Roles.FirstOrDefault(x => x.Id == user.RoleId).Name);
            usertoedit.Name = user.Name;

            await _db.SaveChangesAsync();

            TempData[SD.Success] = "User has been edited successfully";
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        public async Task<IActionResult> Delete(string id)
        {
            var usertodelete = await _db.aplicationUsers.FirstOrDefaultAsync(x => x.Id == id);
            if (usertodelete == null) { return NotFound(); }
            _db.aplicationUsers.Remove(usertodelete);
            await _db.SaveChangesAsync();
            TempData[SD.Success] = "User successfully deleted";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public IActionResult LockUnlock()
        {
            return RedirectToAction(nameof(Index));
        }


        [Authorize(Roles = "Admin")]

        [HttpPost]
        public async Task<IActionResult> LockUnlock(string userid)
        {
            var user = await _db.aplicationUsers.FirstOrDefaultAsync(x => x.Id == userid);
            if (user == null) { return NotFound(); };
            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                //user is locked
                // clicking this action will unlock
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User has been unlocked successfully";
            }
            else
            {
                //lock user
                user.LockoutEnd = DateTime.Now.AddYears(100);
                TempData[SD.Success] = "User has been locked successfully";
            }
            _db.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userid)
        {
            var user = await _db.aplicationUsers.FirstOrDefaultAsync(x => x.Id == userid);
            if (user == null) { return NotFound(); };
            var existinguserclaims = await _userManager.GetClaimsAsync(user);
            var model = new UserClaimViewModel()
            {
                UserId = user.Id
            };

            foreach (Claim claim in ClaimsStore.claimlist)
            {
                UserClaim userClaim = new UserClaim()
                {
                    Claimtype = claim.Type,
                };
                if (existinguserclaims.Any(x => x.Type == claim.Type))
                {
                    userClaim.isSelected = true;
                }
                model.Claims.Add(userClaim);
            }
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ManageUserClaims(UserClaimViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) { return NotFound(); }

            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error while adding claims";
                return View(model);
            }
            result = await _userManager.AddClaimsAsync(user, model.Claims.Where(x => x.isSelected).Select(x => new Claim(x.Claimtype, x.isSelected.ToString())));

            TempData[SD.Success] = "Claims Successfully added.";
            return RedirectToAction(nameof(Index));
        }
    }
}
