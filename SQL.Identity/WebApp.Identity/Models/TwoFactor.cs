using System.ComponentModel.DataAnnotations;

namespace WebApp.Identity.Models
{
    public class TwoFactor
    {
        [Required]
        public string Token { get; set; }
    }
}