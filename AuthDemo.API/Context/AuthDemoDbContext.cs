using AuthDemo.API.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.API.Context
{
    public class AuthDemoDbContext : IdentityDbContext
    {
        public AuthDemoDbContext(DbContextOptions options) : base(options)
        {
            
        }

        public DbSet<ExtendedIdentityUser> ExtendedIdentityUsers { get; set; }

        public DbSet<Employee>? Employees { get; set; }
    }
}
