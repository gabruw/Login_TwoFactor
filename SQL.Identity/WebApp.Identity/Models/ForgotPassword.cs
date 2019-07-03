using System.ComponentModel.DataAnnotations;

namespace WebApp.Identity.Models
{
    public class ForgotPassword
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}