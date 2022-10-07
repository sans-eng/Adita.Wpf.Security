using Adita.Security.Claims;
using Adita.Security.Principal;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Windows;
using ApplicationIdentity = Adita.Security.Claims.ApplicationIdentity;

namespace Adita.Wpf.Security.Samples
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            ApplicationIdentity applicationIdentity = new("password");
            applicationIdentity.AddClaim(new(ClaimTypes.Role, "Admin"));

            ApplicationPrincipal applicationPrincipal = new(applicationIdentity);
            AppDomain.CurrentDomain.SetThreadPrincipal(applicationPrincipal);
        }
    }
}
