/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import javax.swing.tree.DefaultMutableTreeNode;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 *
 * @author maber01
 */
public class PublicKeyRingNode extends CryptoNode
{
  PGPPublicKeyRing pubkeyring;
  public PublicKeyRingNode( CryptographyManager cryptoman, PGPPublicKeyRing pubkeyring )
  {
    super( cryptoman );
    this.pubkeyring = pubkeyring;
    setUserObject( pubkeyring );
  }
  
  public String toString()
  {
    return "Collection of Public Keys";
  }
}
