namespace identityStep.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        //used to log in
        public string Code { get; set; }
        //used to register
        public string Token { get; set; }

        public string? QRCodeURL { get; set; }
    }
}
