using System.ComponentModel.DataAnnotations;

namespace identityStep.Models
{
    public class ForgotPasswordViewModel
    {
        [Required]
        public string Email { get; set; }
    }
}
