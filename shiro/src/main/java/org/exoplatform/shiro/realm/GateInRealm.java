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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.component.ComponentRequestLifecycle;
import org.exoplatform.container.component.RequestLifeCycle;
import org.exoplatform.services.organization.Membership;
import org.exoplatform.services.organization.OrganizationService;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/20/12
 */
public class GateInRealm extends AuthorizingRealm
{
   private OrganizationService orgService;

   public GateInRealm()
   {
      super();

      PortalContainer pc = PortalContainer.getInstanceIfPresent();
      orgService = (OrganizationService)pc.getComponentInstanceOfType(OrganizationService.class);
   }

   @Override
   protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
   {
      if (token instanceof UsernamePasswordToken)
      {
         UsernamePasswordToken tmp = (UsernamePasswordToken)token;
         return new GateInAuthInfo(tmp.getUsername(), new String(tmp.getPassword()));
      }
      else
      {
         throw new IllegalArgumentException("AuthenticationToken of type " + token.getClass().getCanonicalName() + " is not supported");
      }
   }

   @Override
   protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
   {
      String username = (String)getAvailablePrincipal(principals);

      try
      {
         startTransaction();
         Collection memberships = orgService.getMembershipHandler().findMembershipsByUser(username);

         Set<String> roles = new HashSet<String>();
         for(Object obj : memberships)
         {
            Membership m = (Membership) obj;
            roles.add(m.getGroupId());
         }

         return new SimpleAuthorizationInfo(roles);
      }
      catch (Exception ex)
      {
      }
      finally
      {
         endTransaction();
      }
      return null;
   }

   @Override
   public String getName()
   {
      return "gatein-realm";
   }

   private void startTransaction()
   {
      if (orgService instanceof ComponentRequestLifecycle)
      {
         RequestLifeCycle.begin((ComponentRequestLifecycle)orgService);
      }
   }

   private void endTransaction()
   {
      if (orgService instanceof ComponentRequestLifecycle)
      {
         RequestLifeCycle.end();
      }
   }
}
