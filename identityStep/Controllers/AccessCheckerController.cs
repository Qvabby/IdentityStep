using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace identityStep.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        [AllowAnonymous]
        /// <summary>
        /// Accessible by everyone, even for guests.
        /// </summary>
        /// <returns>View</returns>
        public IActionResult AllAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by Logged in users.
        /// </summary>
        /// <returns>View</returns>
        public IActionResult AuthorizedAccess()
        {
            return View();
        }


        /// <summary>
        /// Accessible by User with User role.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Roles = "User")]
        public IActionResult UserAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by User with Admin role.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Policy = "Admin")]
        public IActionResult AdminAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by User or with Admin role.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Roles = "User,Admin")]
        public IActionResult UserOrAdminAccess()
        {
            return View();
        }
        /// <summary>
        /// Accessible by User and with Admin role.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Policy = "UserAndAdmin")]
        public IActionResult UserAndAdminAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by Admin Users with Create Claim.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Policy = "AdminCreate")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by Admin Users with Create Edit Delete Claims.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Policy = "AdminCreateDeleteEdit")]
        public IActionResult Admin_CreateEditDeleteAccess()
        {
            return View();
        }

        /// <summary>
        /// Accessible by Admin Users with Create Edit Delete Claims.
        /// </summary>
        /// <returns>View</returns>
        [Authorize(Policy = "AdminAllOrSuper")]
        public IActionResult Admin_CreateEditDeleteAccessOr_SuperAdmin()
        {
            return View();
        }
        [Authorize(Policy = "AdminWithMoreThan1000Days")]
        public IActionResult SpecialPage()
        {
            return View();
        }
        [Authorize(Policy = "FirstNameAuth")]
        public IActionResult FirstNameAuth()
        {
            return View();
        }
    }
}
