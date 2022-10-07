//MIT License

//Copyright (c) 2022 Adita

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

using System;
using System.Threading;
using System.Windows;

namespace Adita.Wpf.Security.Authorization
{
    /// <summary>
    /// Represents an authorize class that controls <see cref="UIElement"/> behaviors such as <see cref="UIElement.Visibility"/>
    /// based on role-based authorization.
    /// </summary>
    /// <remarks>
    /// This class will authorize only when <see cref="RolesProperty"/> or <see cref="RefusalMethodProperty"/> changed
    /// or at startup of application.
    /// </remarks>
    public class Authorize : UIElement
    {
        #region Dependency properties
        /// <summary>
        /// Identifies the Roles property.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "<Pending>")]
        public static DependencyProperty RolesProperty =
            DependencyProperty.RegisterAttached("Roles", typeof(string), typeof(Authorize), new PropertyMetadata(string.Empty, OnRolesChanged));

        /// <summary>
        /// Identifies the RefusalMethod property.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "<Pending>")]
        public static DependencyProperty RefusalMethodProperty =
            DependencyProperty.RegisterAttached("RefusalMethod", typeof(AuthorizationRefusalMethod), typeof(Authorize),
                new PropertyMetadata(AuthorizationRefusalMethod.Disabling, OnRefusalMethodChanged));
        #endregion Dependency properties

        #region Dependency property accessors
        /// <summary>
        /// Gets a semicolon delimited list of roles from specified <paramref name="uiElement"/>.
        /// </summary>
        /// <param name="uiElement">An <see cref="UIElement"/> to get the roles from.</param>
        /// <returns>A semicolon delimited list of roles.</returns>
        public static string GetRoles(UIElement uiElement)
        {
            return (string)uiElement.GetValue(RolesProperty);
        }
        /// <summary>
        /// Sets a semicolon delimited list of roles to specified <paramref name="uiElement"/>.
        /// </summary>
        /// <param name="uiElement">An <see cref="UIElement"/> to set the roles to.</param>
        /// <param name="roles">A semicolon delimited list of roles.</param>
        public static void SetRoles(UIElement uiElement, string roles)
        {
            uiElement.SetValue(RolesProperty, roles);
        }
        /// <summary>
        /// Gets an <see cref="AuthorizationRefusalMethod"/> of specified <paramref name="uiElement"/>.
        /// </summary>
        /// <param name="uiElement">An <see cref="UIElement"/> to get the <see cref="AuthorizationRefusalMethod"/> from.</param>
        /// <returns>The <see cref="AuthorizationRefusalMethod"/> that stored on specified <paramref name="uiElement"/>.</returns>
        public static AuthorizationRefusalMethod GetRefusalMethod(UIElement uiElement)
        {
            return (AuthorizationRefusalMethod)uiElement.GetValue(RefusalMethodProperty);
        }
        /// <summary>
        /// Sets specified <paramref name="refusalMethod"/> to specified <paramref name="uiElement"/>.
        /// </summary>
        /// <param name="uiElement">An <see cref="UIElement"/> to set <paramref name="refusalMethod"/> to.</param>
        /// <param name="refusalMethod">A <see cref="AuthorizationRefusalMethod"/> to set.</param>
        public static void SetRefusalMethod(UIElement uiElement, AuthorizationRefusalMethod refusalMethod)
        {
            uiElement.SetValue(RefusalMethodProperty, refusalMethod);
        }
        #endregion Dependency property accessors

        #region Dependency property changed event handlers
        private static void OnRolesChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
        {
            if (dependencyObject is not UIElement uiElement)
            {
                return;
            }

            if (args.NewValue is not string newRoles)
            {
                return;
            }

            AuthorizationRefusalMethod authorizationRefusalMethod = GetRefusalMethod(uiElement);
            AuthorizeAction(newRoles, authorizationRefusalMethod, uiElement);
        }
        private static void OnRefusalMethodChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
        {
            if (dependencyObject is not UIElement uiElement)
            {
                return;
            }

            if (args.NewValue is not AuthorizationRefusalMethod refusalMethod)
            {
                return;
            }

            string roles = GetRoles(uiElement);
            AuthorizeAction(roles, refusalMethod, uiElement);
        }
        #endregion Dependency property changed event handlers

        #region Private methods
        private static void AuthorizeAction(string roles, AuthorizationRefusalMethod refusalMethod, UIElement uiElement)
        {
            if (roles is null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            if (uiElement is null)
            {
                throw new ArgumentNullException(nameof(uiElement));
            }

            bool isAuthorized = IsInRoles(roles);
            SetAuthorization(isAuthorized, refusalMethod, uiElement);
        }

        private static bool IsInRoles(string roles)
        {
            if (roles is null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            if (Thread.CurrentPrincipal?.Identity != null)
            {
                if (string.IsNullOrWhiteSpace(roles) && Thread.CurrentPrincipal.Identity.IsAuthenticated)
                {
                    return true;
                }

                foreach (var role in roles.Split(';'))
                {
                    if (Thread.CurrentPrincipal.IsInRole(role))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static void SetAuthorization(bool isAuthorized, AuthorizationRefusalMethod refusalMethod, UIElement uiElement)
        {
            if (uiElement is null)
            {
                throw new ArgumentNullException(nameof(uiElement));
            }

            switch (refusalMethod)
            {
                case AuthorizationRefusalMethod.Disabling:
                    uiElement.IsEnabled = isAuthorized;
                    break;
                case AuthorizationRefusalMethod.Collapsing:
                    uiElement.Visibility = isAuthorized ? Visibility.Visible : Visibility.Collapsed;
                    break;
                case AuthorizationRefusalMethod.ThrowException:
                    if (!isAuthorized)
                    {
                        throw new UnauthorizedAccessException("Permission denied to access specified resources.");
                    }
                    break;
            }
        }
        #endregion Private methods
    }
}
