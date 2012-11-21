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
package org.gatein.portal.portlet.shiro;

import org.apache.shiro.subject.Subject;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.shiro.ShiroService;
import java.io.IOException;
import java.io.Writer;
import javax.portlet.GenericPortlet;
import javax.portlet.PortletConfig;
import javax.portlet.PortletException;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/20/12
 */
public class ShiroPortlet extends GenericPortlet
{

   private ShiroService shiroService;

   @Override
   public void init(PortletConfig config) throws PortletException
   {
      super.init(config);
      PortalContainer pc = PortalContainer.getInstanceIfPresent();
      shiroService = (ShiroService)pc.getComponentInstanceOfType(ShiroService.class);
   }

   @Override
   protected void doView(RenderRequest request, RenderResponse response) throws PortletException, IOException
   {
      String remoteUser = request.getRemoteUser();
      if (remoteUser == null)
      {
         Writer w = response.getWriter();
         w.write("You need to authenticate the GateIn portal to test ShiroPortlet");
         w.flush();
      }
      else
      {
         Subject s = shiroService.getSubject(remoteUser);
         if (s == null || !s.isAuthenticated())
         {
            throw new RuntimeException("GateIn authentication succeed but Shiro authentication failed");
         }
         else
         {
            printAuthenticationInfo(request, response, s);
            printAuthorization(request, response, s);
         }
      }
   }

   private void printAuthenticationInfo(RenderRequest req, RenderResponse resp, Subject shiroSubject) throws IOException
   {
      resp.getWriter().write("You have login successfully to Shiro\n");
   }

   private final String[] ROLES = new String[]{"/platform/administrators", "/organization/management/executive-board", "/platform/users"};

   private void printAuthorization(RenderRequest req, RenderResponse resp, Subject shiroSubject) throws IOException
   {
      Writer w = resp.getWriter();
      w.write("User has roles: \n");
      for(String role : ROLES)
      {
         if(shiroSubject.hasRole(role))
         {
            w.write(role + "\n");
         }
      }
   }
}
