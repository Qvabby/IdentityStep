using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace identityStep.Helpers
{
    public class HelperMethods
    {
        public bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
        {
            return context.User.IsInRole("Admin") &&
                        context.User.HasClaim(x => x.Type == "Create" && x.Value == "True") &&
                        context.User.HasClaim(x => x.Type == "Edit" && x.Value == "True") &&
                        context.User.HasClaim(x => x.Type == "Edit" && x.Value == "True") ||
                        context.User.IsInRole("SuperAdmin");
        }


    }
}
