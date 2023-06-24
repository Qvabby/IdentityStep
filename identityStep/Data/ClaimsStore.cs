using System.Security.Claims;

namespace identityStep.Data
{
    public static class ClaimsStore
    {
        public static List<Claim> claimlist = new List<Claim>()
        {
            new Claim("Create","Create"),
            new Claim("Edit","Edit"),
            new Claim("Delete","Delete"),
        };
    }
}
