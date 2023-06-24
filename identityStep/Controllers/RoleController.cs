using identityStep.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace identityStep.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            var Roles = _db.Roles.ToList();
            return View(Roles);
        }

        [HttpGet]
        
        public IActionResult Upsert(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                //create
                View();
            }
            else
            {
                //update
                var role = _db.Roles.FirstOrDefault(r => r.Id == id);
                if (role == null) { return View(); }
                View(role);
            }
            return View();
        }
        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public async Task<IActionResult> Upsert(IdentityRole role)
        {
            if (await _roleManager.RoleExistsAsync(role.Name))
            {
                //error
                TempData[SD.Error] = "Role Already Exists";
                return RedirectToAction(nameof(Index));
            }
            else if (string.IsNullOrWhiteSpace(role.Id))
            {
                //create

                await _roleManager.CreateAsync(new IdentityRole
                {
                    Name = role.Name,
                });
                TempData[SD.Success] = "Role Created Successfully";
            }
            else
            {
                //update

                var roletoupdate = await _db.Roles.FirstOrDefaultAsync(r => r.Id == role.Id);
                if (roletoupdate == null) { TempData[SD.Error] = "Role Not Found"; return RedirectToAction(nameof(Index)); }
                roletoupdate.Name = role.Name;
                roletoupdate.NormalizedName = role.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(roletoupdate);
                TempData[SD.Success] = "Role Updated Successfully";

            }
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public async Task<IActionResult> Delete (string id)
        {
            var roletodelete = await _db.Roles.FirstOrDefaultAsync(s => s.Id == id);
            if (roletodelete == null)
            {
                TempData[SD.Error] = "Role Not Found"; return RedirectToAction(nameof(Index));
            }
            var userrolesforthisrole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if (userrolesforthisrole >= 1)
            {
                TempData[SD.Error] = "Can't delete this role because there are users asigned to this role."; return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(roletodelete);
            TempData[SD.Success] = "Role Deleted Successfully";
            return RedirectToAction(nameof(Index));
        }

    }
}
