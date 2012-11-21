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
package org.exoplatform.shiro.realm;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.component.ComponentRequestLifecycle;
import org.exoplatform.container.component.RequestLifeCycle;
import org.exoplatform.services.organization.OrganizationService;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/20/12
 */
public class GateInCredentialMatcher implements CredentialsMatcher
{
   private OrganizationService orgService;

   public GateInCredentialMatcher()
   {
      PortalContainer pc = PortalContainer.getInstanceIfPresent();
      orgService = (OrganizationService)pc.getComponentInstanceOfType(OrganizationService.class);
   }

   @Override
   public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info)
   {
      if (token instanceof UsernamePasswordToken && info instanceof GateInAuthInfo)
      {
         return _doCredentialsMatch((UsernamePasswordToken)token, (GateInAuthInfo)info);
      }
      else
      {
         return false;
      }
   }

   private boolean _doCredentialsMatch(UsernamePasswordToken token, GateInAuthInfo info)
   {
      boolean success = false;
      try
      {
         startTransaction();
         success = orgService.getUserHandler().authenticate(info.getUser(), info.getCredentials().toString());
      }
      catch (Exception ex)
      {
         //TODO: Add logging here
      }
      finally
      {
         endTransaction();
      }

      return success;
   }

   private void startTransaction()
   {
      if(orgService instanceof ComponentRequestLifecycle)
      {
         RequestLifeCycle.begin((ComponentRequestLifecycle)orgService);
      }
   }

   private void endTransaction()
   {
      if(orgService instanceof ComponentRequestLifecycle)
      {
         RequestLifeCycle.end();
      }
   }
}
