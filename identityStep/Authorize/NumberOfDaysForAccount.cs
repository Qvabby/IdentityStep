using identityStep.Data;

namespace identityStep.Authorize
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _context;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _context = db;
        }
        public int Get(string UserId)
        {
            var user = _context.aplicationUsers.FirstOrDefault(x => x.Id == UserId);
            if (user != null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
