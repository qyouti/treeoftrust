/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import javax.swing.tree.DefaultMutableTreeNode;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author maber01
 */
public class SecretKeyNode extends CryptoNode
{
  PGPSecretKey seckey;
  public SecretKeyNode( CryptographyManager cryptoman, PGPSecretKey seckey )
  {
    super( cryptoman );
    this.seckey = seckey;
    setUserObject( seckey );
  }

  public PGPSecretKey getSecretKey()
  {
    return seckey;
  }
  
  public boolean hasWindowsPassword()
  {
    return cryptoman.hasWindowsPassword(seckey);
  }
  
  public String toString()
  {
    return seckey.getUserIDs().next();
  }
}
