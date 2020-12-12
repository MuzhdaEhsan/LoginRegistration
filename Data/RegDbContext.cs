using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

//Importing Entity Framework (you have to use the nu-get package manager here).
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
//Importing from the models folder.
using LoginRegistration.Models;

namespace LoginRegistration.Data
{
    public class RegDbContext: IdentityDbContext<LogUser>
    {
        //Constructor
        public RegDbContext(DbContextOptions<RegDbContext> options)
       : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            //You can make customizations here.
        }

    }
}
