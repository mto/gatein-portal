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
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.ExecutionException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 11/14/12
 */
public abstract class SubjectDecorator implements Subject
{
   private Subject decorated;

   public SubjectDecorator(Subject _decorated)
   {
      decorated = _decorated;
   }

   @Override
   public Object getPrincipal()
   {
      return decorated.getPrincipal();
   }

   @Override
   public PrincipalCollection getPrincipals()
   {
      return decorated.getPrincipals();
   }

   @Override
   public boolean isPermitted(String permission)
   {
      return decorated.isPermitted(permission);
   }

   @Override
   public boolean isPermitted(Permission permission)
   {
      return decorated.isPermitted(permission);
   }

   @Override
   public boolean[] isPermitted(String... permissions)
   {
      return decorated.isPermitted(permissions);
   }

   @Override
   public boolean[] isPermitted(List<Permission> permissions)
   {
      return decorated.isPermitted(permissions);
   }

   @Override
   public boolean isPermittedAll(String... permissions)
   {
      return decorated.isPermittedAll(permissions);
   }

   @Override
   public boolean isPermittedAll(Collection<Permission> permissions)
   {
      return decorated.isPermittedAll(permissions);
   }

   @Override
   public void checkPermission(String permission) throws AuthorizationException
   {
      decorated.checkPermission(permission);
   }

   @Override
   public void checkPermission(Permission permission) throws AuthorizationException
   {
      decorated.checkPermission(permission);
   }

   @Override
   public void checkPermissions(String... permissions) throws AuthorizationException
   {
      decorated.checkPermissions(permissions);
   }

   @Override
   public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException
   {
      decorated.checkPermissions(permissions);
   }

   @Override
   public boolean hasRole(String roleIdentifier)
   {
      return decorated.hasRole(roleIdentifier);
   }

   @Override
   public boolean[] hasRoles(List<String> roleIdentifiers)
   {
      return decorated.hasRoles(roleIdentifiers);
   }

   @Override
   public boolean hasAllRoles(Collection<String> roleIdentifiers)
   {
      return decorated.hasAllRoles(roleIdentifiers);
   }

   @Override
   public void checkRole(String roleIdentifier) throws AuthorizationException
   {
      decorated.checkRole(roleIdentifier);
   }

   @Override
   public void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException
   {
      decorated.checkRoles(roleIdentifiers);
   }

   @Override
   public void checkRoles(String... roleIdentifiers) throws AuthorizationException
   {
      decorated.checkRoles(roleIdentifiers);
   }

   @Override
   public void login(AuthenticationToken token) throws AuthenticationException
   {
      decorated.login(token);
   }

   @Override
   public boolean isAuthenticated()
   {
      return decorated.isAuthenticated();
   }

   @Override
   public boolean isRemembered()
   {
      return decorated.isRemembered();
   }

   @Override
   public Session getSession()
   {
      return decorated.getSession();
   }

   @Override
   public Session getSession(boolean create)
   {
      return decorated.getSession(create);
   }

   @Override
   public void logout()
   {
      decorated.logout();
   }

   @Override
   public <V> V execute(Callable<V> callable) throws ExecutionException
   {
      return decorated.execute(callable);
   }

   @Override
   public void execute(Runnable runnable)
   {
      decorated.execute(runnable);
   }

   @Override
   public <V> Callable<V> associateWith(Callable<V> callable)
   {
      return decorated.associateWith(callable);
   }

   @Override
   public Runnable associateWith(Runnable runnable)
   {
      return decorated.associateWith(runnable);
   }

   @Override
   public void runAs(PrincipalCollection principals) throws NullPointerException, IllegalStateException
   {
      decorated.runAs(principals);
   }

   @Override
   public boolean isRunAs()
   {
      return decorated.isRunAs();
   }

   @Override
   public PrincipalCollection getPreviousPrincipals()
   {
      return decorated.getPreviousPrincipals();
   }

   @Override
   public PrincipalCollection releaseRunAs()
   {
      return decorated.releaseRunAs();
   }
}
