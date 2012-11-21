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
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.Factory;
import org.exoplatform.services.organization.OrganizationService;
import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/14/12
 */
public class ShiroService implements RememberMeManager
{
   private final ConcurrentMap<String, Subject> subjects;

   private final SecurityManager sm;

   /**
    *  Declare OrganizationService in constructor param to ensure the service exists by the time
    * Shiro SecurityManager is initialized
    */
   public ShiroService(OrganizationService orgService) throws Exception
   {
      subjects = new ConcurrentHashMap<String, Subject>();

      InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("shiro.ini");
      Ini config = new Ini();
      config.load(in);

      Factory<SecurityManager> factory = new IniSecurityManagerFactory(config);
      sm = factory.getInstance();
      //Hardcode for the moment
      ((DefaultSecurityManager)sm).setRememberMeManager(this);
   }

   private Subject storeSubject(String username, Subject subject)
   {
      return subjects.put(username, subject);
   }

   public Subject getSubject(String username)
   {
      return subjects.get(username);
   }

   public void removeSubject(String username)
   {
      subjects.remove(username);
   }

   public Subject createSubject()
   {
      return new Subject.Builder(sm).buildSubject();
   }

   @Override
   public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext)
   {
      return null;
   }

   @Override
   public void forgetIdentity(SubjectContext subjectContext)
   {
   }

   @Override
   public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info)
   {
      storeSubject(((UsernamePasswordToken)token).getUsername(), subject);
   }

   @Override
   public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae)
   {
   }

   @Override
   public void onLogout(Subject subject)
   {

   }
}
