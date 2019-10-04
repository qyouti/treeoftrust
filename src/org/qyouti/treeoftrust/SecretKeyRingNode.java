/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import javax.swing.tree.DefaultMutableTreeNode;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author maber01
 */
public class SecretKeyRingNode extends CryptoNode
{
  PGPSecretKeyRing seckeyring;
  public SecretKeyRingNode( CryptographyManager cryptoman, PGPSecretKeyRing seckeyring )
  {
    super( cryptoman );
    this.seckeyring = seckeyring;
    setUserObject( seckeyring );
  }
  
  public String toString()
  {
    return "Collection of Secret Keys";
  }
}
