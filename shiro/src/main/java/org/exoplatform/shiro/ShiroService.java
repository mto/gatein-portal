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
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/14/12
 */
public class ShiroService
{
   private final ConcurrentMap<String, Subject> subjects;

   private final SecurityManager sm;

   public ShiroService() throws Exception
   {
      subjects = new ConcurrentHashMap<String, Subject>();

      InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("shiro.ini");
      Ini config = new Ini();
      config.load(in);

      Factory<SecurityManager> factory = new IniSecurityManagerFactory(config);
      sm = factory.getInstance();
   }

   private Subject storeSubject(String username, Subject subject)
   {
      return subjects.putIfAbsent(username, subject);
   }

   public Subject getSubject(String username)
   {
      return subjects.get(username);
   }

   public void removeSubject(String username)
   {
      subjects.remove(username);
   }

   public Subject createSubject(String username)
   {
      return new GateInSubject(new Subject.Builder(sm).buildSubject(), username);
   }

   class GateInSubject extends SubjectDecorator
   {
      private String username;

      public GateInSubject(Subject _decorated, String _username)
      {
         super(_decorated);
         username = _username;
      }

      @Override
      public void login(AuthenticationToken token) throws AuthenticationException
      {
         super.login(token);
         ShiroService.this.storeSubject(username, this);
      }

      @Override
      public void logout()
      {
         super.logout();
         ShiroService.this.removeSubject(username);
      }
   }
}
