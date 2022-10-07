using Adita.Security.Principal;
using Adita.Wpf.Security.Authorization;
using System.Security.Claims;
using System.Windows;
using System.Windows.Controls;

namespace Adita.Wpf.Security.Test.Authorization
{
    [TestClass]
    public class AuthorizeTest
    {
        [ClassInitialize]
        public static void Initialize(TestContext context)
        {
            Adita.Security.Claims.ApplicationIdentity applicationIdentity = new("password");
            applicationIdentity.AddClaim(new(ClaimTypes.Role, "Admin"));

            ApplicationPrincipal applicationPrincipal = new(applicationIdentity);

            AppDomain.CurrentDomain.SetThreadPrincipal(applicationPrincipal);
        }

        [STATestMethod]
        public void CanAcceptAuthorizeIsEnabled()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "Admin");
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.Disabling);

            Assert.IsTrue(textBox.IsEnabled);
        }

        [STATestMethod]
        public void CanAcceptAuthorizeCollapsing()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "Admin");
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.Collapsing);

            Assert.IsTrue(textBox.Visibility == Visibility.Visible);
        }

        [STATestMethod]
        public void CanAcceptAuthorizeThrowException()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "Admin");
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.ThrowException);

            Assert.IsTrue(textBox.IsEnabled);
            Assert.IsTrue(textBox.Visibility == Visibility.Visible);
        }

        [STATestMethod]
        public void CanRefuseAuthorizeIsEnabled()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "User");
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.Disabling);

            Assert.IsFalse(textBox.IsEnabled);
        }

        [STATestMethod]
        public void CanRefuseAuthorizeCollapsing()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "User");
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.Collapsing);

            Assert.IsFalse(textBox.Visibility == Visibility.Visible);
        }

        [STATestMethod]
        public void CanRefuseAuthorizeThrowException()
        {
            TextBox textBox = new();

            Authorize.SetRoles(textBox, "User");

            _ = Assert.ThrowsException<UnauthorizedAccessException>(() =>
            Authorize.SetRefusalMethod(textBox, AuthorizationRefusalMethod.ThrowException)
            );
        }
    }
}
