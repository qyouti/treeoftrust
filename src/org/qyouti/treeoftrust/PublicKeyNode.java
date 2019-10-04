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
public class PublicKeyNode extends CryptoNode
{
  PGPPublicKey pubkey;
  public PublicKeyNode( CryptographyManager cryptoman, PGPPublicKey pubkey )
  {
    super( cryptoman );
    this.pubkey = pubkey;
    setUserObject( pubkey );
  }

  public PGPPublicKey getPublicKey()
  {
    return pubkey;
  }
    
  public String toString()
  {
    return pubkey.getUserIDs().next();
  }
}
