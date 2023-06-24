using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace identityStep.Authorize
{
    public class AdminWithMoreThan1000DaysHandler : AuthorizationHandler<AdminWithMoreThan1000DaysRequirement>
    {
        private readonly INumberOfDaysForAccount _numberOfDaysForAccount;
        public AdminWithMoreThan1000DaysHandler(INumberOfDaysForAccount inu)
        {
            _numberOfDaysForAccount = inu;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMoreThan1000DaysRequirement requirement)
        {
            if (!context.User.IsInRole("Admin"))
            {
                return Task.CompletedTask;
            }
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var numberOfDay = _numberOfDaysForAccount.Get(userId);
            if (numberOfDay >= requirement.Days)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
