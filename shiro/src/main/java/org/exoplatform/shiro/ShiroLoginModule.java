/*
 * Copyright (C) 2012 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.exoplatform.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/14/12
 *
 * A login module enabling integrate GateIn authentication with Shiro infrastructure
 *
 */
public class ShiroLoginModule implements LoginModule
{

   private ShiroService shiroService;

   private CallbackHandler cbHandler;

   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
   {
      String portalContainer = options.get("portalContainerName").toString();
      PortalContainer pc = RootContainer.getInstance().getPortalContainer(portalContainer);

      shiroService = (ShiroService)pc.getComponentInstanceOfType(ShiroService.class);
      cbHandler = callbackHandler;
   }

   @Override
   public boolean login() throws LoginException
   {
      return true;
   }

   @Override
   public boolean commit() throws LoginException
   {
      String username = null;
      String password = null;

      try
      {
         NameCallback nameCb = new NameCallback("Username");
         PasswordCallback pwdCb = new PasswordCallback("Password", false);
         cbHandler.handle(new Callback[]{nameCb, pwdCb});
         username = nameCb.getName();
         password = new String(pwdCb.getPassword());
      }
      catch (UnsupportedCallbackException unsupportedEx)
      {
      }
      catch (IOException ioEx)
      {
      }
      if (username != null && password != null)
      {
         org.apache.shiro.subject.Subject shiroSubject = shiroService.createSubject(username);
         try
         {
            shiroSubject.login(new UsernamePasswordToken(username, password));
            return true;
         }
         catch (AuthenticationException authEx)
         {
            return false;
         }
      }
      else
      {
         return false;
      }
   }

   @Override
   public boolean abort() throws LoginException
   {
      return true;
   }

   @Override
   public boolean logout() throws LoginException
   {
      //Do nothing as cleaning work has been done as org.apache.shiro.subject.Subject.logout() is called
      return true;
   }
}
