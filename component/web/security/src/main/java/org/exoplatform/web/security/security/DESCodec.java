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
package org.exoplatform.web.security.security;

import org.exoplatform.commons.utils.PropertyManager;
import org.gatein.common.io.IOTools;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date 6/14/12
 */
public class DESCodec extends AbstractCodec
{
   private final static Logger LOG = LoggerFactory.getLogger(DESCodec.class);

   private final static String ALGORITHM = "DES";

   //Among there KeyStore types {jks, jceks, pkcs12}, only jceks supports loading/storing symmetric key
   private final static String KEYSTORE_TYPE = "JCEKS";

   private final Cipher encrypter;

   private final Cipher decrypter;

   public DESCodec() throws Exception
   {
      String keyAlias = PropertyManager.getProperty("gatein.codec.keyAlias");
      String keyFile = PropertyManager.getProperty("gatein.codec.keyFile");
      char[] password = PropertyManager.getProperty("gatein.codec.keyPassword").toCharArray();

      encrypter = Cipher.getInstance(ALGORITHM);
      decrypter = Cipher.getInstance(ALGORITHM);

      SecretKey secretKey = loadSecretKey(keyAlias, keyFile, password);
      encrypter.init(Cipher.ENCRYPT_MODE, secretKey);
      decrypter.init(Cipher.DECRYPT_MODE, secretKey);
   }

   private SecretKey loadSecretKey(String keyAlias, String keyFile, char[] password) throws Exception
   {
      File f = new File(keyFile);
      if(!f.exists())
      {
         throw new IllegalArgumentException("File " + keyFile + " does not exist!");
      }

      KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
      InputStream in = new FileInputStream(f);
      boolean loadSuccess = true;
      try
      {
         keyStore.load(in, password);
      }
      catch(Exception ex)
      {
         LOG.warn("Error while loading keyStore from file " + keyFile, ex);
         loadSuccess = false;
      }
      finally
      {
         IOTools.safeClose(in);
      }

      if (loadSuccess)
      {
         KeyStore.Entry entry = keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(password));
         LOG.info("Found Secret key stored in " + keyFile);
         return ((KeyStore.SecretKeyEntry)entry).getSecretKey();
      }
      else
      {
         LOG.info("File " + keyFile + " is empty, new key would be generated and stored");
         keyStore.load(null, password);
         KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
         SecretKey secretKey = keyGen.generateKey();
         LOG.debug("Storing the newly generated SecretKey");
         keyStore.setEntry(keyAlias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(password));
         OutputStream out = new FileOutputStream(f);
         try
         {
            keyStore.store(out, password);
         }
         finally
         {
            IOTools.safeClose(out);
         }
         return secretKey;
      }
   }

   @Override
   public String getName()
   {
      return "DES Algorithm Codec";
   }

   @Override
   public String encode(String plainInput)
   {
      try
      {
         return new String(encrypter.doFinal(plainInput.getBytes()));
      }
      catch(RuntimeException uncheckedEx)
      {
         throw uncheckedEx;
      }
      catch(Exception checkedEx)
      {
         throw new RuntimeException(checkedEx);
      }
   }

   @Override
   public String decode(String encodedInput)
   {
      try
      {
         return new String(decrypter.doFinal(encodedInput.getBytes()));
      }
      catch(RuntimeException uncheckedEx)
      {
         throw uncheckedEx;
      }
      catch(Exception checkedEx)
      {
         throw new RuntimeException(checkedEx);
      }
   }
}
