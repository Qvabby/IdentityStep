using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations.Schema;

namespace identityStep.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
        //not mapped = not needed in database table
        [NotMapped]
        public string RoleId { get; set; }
        [NotMapped]
        public string? Role { get; set; }
        [NotMapped]
        public IEnumerable<SelectListItem>? RoleList { get; set; }

        public DateTime DateCreated { get; set; }
    }
}
