/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.Properties;


/**
 *
 * @author maber01
 */
public interface CryptographyManagerConfiguration
{
  //public Properties getProperties();
  //public void saveProperties();
  public PasswordProvider getPasswordProvider();
  public long getPreferredKeyID();
  public void setPreferredKeyID( long id );
  
  public String getPublicKeyRingFileName();
  public String getSecretKeyRingFileName();
  
  public void deleteStoredEncryptedPassword( long id );
  public String getStoredEncryptedPassword( long id );
  public void setStoredEncryptedPassword( long id, String encryptedpassword );
  
}
