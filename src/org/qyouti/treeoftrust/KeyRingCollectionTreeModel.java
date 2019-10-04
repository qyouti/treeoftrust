/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

/**
 *
 * @author maber01
 */
public class KeyRingCollectionTreeModel extends DefaultTreeModel
{ 
  CryptographyManager cryptoman;
  PGPSecretKeyRingCollection seckeyringcoll;
  PGPPublicKeyRingCollection pubkeyringcoll;
  boolean mine;
          
  public KeyRingCollectionTreeModel( CryptographyManager cryptoman, PGPSecretKeyRingCollection seckeyringcoll, PGPPublicKeyRingCollection pubkeyringcoll, boolean mine )
  {
    super( new DefaultMutableTreeNode() );
    this.cryptoman = cryptoman;
    this.pubkeyringcoll = pubkeyringcoll;
    this.seckeyringcoll = seckeyringcoll;
    this.mine = mine;
    if ( mine )
      initMine();
    else
      initOthers();
  }

  private void initMine()
  {
    DefaultMutableTreeNode root = (DefaultMutableTreeNode)getRoot();
    Iterator<PGPSecretKeyRing> keyringiter = seckeyringcoll.getKeyRings();
    while ( keyringiter.hasNext() )
    {
      PGPSecretKeyRing keyring = keyringiter.next();
      SecretKeyRingNode keyringnode = new SecretKeyRingNode( cryptoman, keyring );
      Iterator<PGPSecretKey> keyit = keyring.getSecretKeys();
      for ( int i=0; keyit.hasNext(); i++ )
      {
        PGPSecretKey key = keyit.next();
        SecretKeyNode keynode = new SecretKeyNode( cryptoman, key );
        if ( i==0 )
        {
          if ( keyit.hasNext() )
          {
            root.add( keyringnode );
            keyringnode.add( keynode );
          }
          else
            root.add( keynode );
        }
        else
          keyringnode.add( keynode );
      }
    }
  }
  
  private void initOthers()
  {
    DefaultMutableTreeNode root = (DefaultMutableTreeNode)getRoot();
    Iterator<PGPPublicKeyRing> keyringiter = pubkeyringcoll.getKeyRings();
    while ( keyringiter.hasNext() )
    {
      PGPPublicKeyRing keyring = keyringiter.next();
      PublicKeyRingNode keyringnode = new PublicKeyRingNode( cryptoman, keyring );
      Iterator<PGPPublicKey> keyit = keyring.getPublicKeys();
      ArrayList<PGPPublicKey> shortlist = new ArrayList<>();
      while ( keyit.hasNext() )
      {
        PGPPublicKey key = keyit.next();
        PGPSecretKey seckey=null;
        try
        {
          seckey = seckeyringcoll.getSecretKey( key.getKeyID() );
        }
        catch (PGPException ex)
        {
          Logger.getLogger(KeyRingCollectionTreeModel.class.getName()).log(Level.SEVERE, null, ex);
          continue;
        }
        if ( seckey == null )
          shortlist.add(key);
      }
      
      keyit = shortlist.iterator();
      for ( int i=0; keyit.hasNext(); i++ )
      {
        PGPPublicKey key = keyit.next();
        PublicKeyNode keynode = new PublicKeyNode( cryptoman, key );
        if ( i==0 )
        {
          if ( keyit.hasNext() )
          {
            root.add( keyringnode );
            keyringnode.add( keynode );
          }
          else
            root.add( keynode );
        }
        else
          keyringnode.add( keynode );
      }
    }
  }
  
  
}
