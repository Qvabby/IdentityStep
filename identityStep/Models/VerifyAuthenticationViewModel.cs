using System.ComponentModel;

namespace identityStep.Models
{
    public class VerifyAuthenticationViewModel
    {
        public string Code { get; set; }

        public string? returnUrl { get; set; }

        [DisplayName("Remember Me?")]
        public bool rememberMe { get; set; }
    }
}
