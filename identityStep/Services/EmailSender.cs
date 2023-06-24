using identityStep.Interfaces;
using System.Net;
using System.Net.Mail;

namespace identityStep.Services
{
    public class EmailSender : ICustomEmailSender
    {
        public readonly IConfiguration configuration;
        public EmailSender(IConfiguration con)
        {
            configuration = con;
        }
        public Task SendEmailAsync(string email, string subject, string message)
        {
            var options = configuration.GetSection("Credentials").Get<EmailSenderOptions>();
            var client = new SmtpClient("smtp.office365.com", 587) { EnableSsl = true, UseDefaultCredentials = false, Credentials = new NetworkCredential(options.Email, options.Password) };
            var MailMessage = new MailMessage(from: options.Email, to: email,subject,message);
            MailMessage.IsBodyHtml = true;
            return client.SendMailAsync(MailMessage);
        }
        
    }
}
