/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
/**
 *
 * @author maber01
 */
public class TreeOfTrustStore
{
  public final static String NOTATION_NAME_TREENAME = "treename@github.com/qyouti/treeoftrust";
  public final static String NOTATION_NAME_ROLE = "role@github.com/qyouti/treeoftrust";
  
  public final static String ROLE_CREATOR    = "CREATOR";
  public final static String ROLE_CONTROLLER = "CONTROLLER";
  public final static String ROLE_MEMBER     = "MEMBER";
  
  PGPPublicKeyRingCollection keyringcollection;
  final HashMap<String,TreeOfTrust> trees = new HashMap<>();
  
  public void setPublicKeyRingCollection( PGPPublicKeyRingCollection keyringcollection )
          throws TreeOfTrustException
  {
    this.keyringcollection = keyringcollection;
    parseKeyRingCollection();
  }
  
  public Collection<TreeOfTrust> getTrees()
  {
    return trees.values();
  }
  
  private void parseSignature( PGPPublicKeyRing keyring, PGPPublicKey pubkey, PGPSignature sig, String treename )
  {
    TreeOfTrustNode node = new TreeOfTrustNode();
    node.treename = treename;
    node.publickeyring = keyring;
    node.publickey = pubkey;
    node.signature = sig;
    node.id = pubkey.getKeyID();
    node.signerid = sig.getKeyID();

    NotationData[] notations;
    notations = sig.getHashedSubPackets().getNotationDataOccurrences();
    for ( NotationData nd : notations )
    {
      if ( NOTATION_NAME_ROLE.equals( nd.getNotationName() ) )
        node.role = nd.getNotationValue();
    }
    
    TreeOfTrust tree = trees.get( treename );
    if ( tree == null )
    {
      tree = new TreeOfTrust( this, treename );
      trees.put(treename, tree);
    }
    tree.addNode(node);
  }
  
  private void parseSignatures( PGPPublicKeyRing keyring, PGPPublicKey pubkey )
  {
    Iterator sigit = pubkey.getSignatures();
    PGPSignature signature=null;
    NotationData[] notations;
    
    while ( sigit.hasNext() )
    {
      Object objsig = sigit.next();
      if ( !(objsig instanceof PGPSignature) )
        continue;        
      signature = (PGPSignature)objsig;
      notations = signature.getHashedSubPackets().getNotationDataOccurrences();
      for ( NotationData nd : notations )
      {
        if ( NOTATION_NAME_TREENAME.equals( nd.getNotationName() ) )
          parseSignature( keyring, pubkey, signature, nd.getNotationValue() );
      }
    }
  }
  
  private void parseKeyRingCollection()
          throws TreeOfTrustException
  {
    Iterator<PGPPublicKeyRing> keyringit = keyringcollection.getKeyRings();
    PGPPublicKeyRing keyring;
    PGPPublicKey pubkey;
    while ( keyringit.hasNext() )
    {
      keyring = keyringit.next();
      
      // first test
      Iterator<PGPPublicKey> keyit = keyring.getPublicKeys();
      if ( !keyit.hasNext() )
        continue;
      pubkey = keyit.next();
      if ( keyit.hasNext() )
        continue;

      // only keyrings with one key get here - no sub-keys
      parseSignatures( keyring, pubkey );
    }
    
    for ( TreeOfTrust tree : trees.values() )
      tree.reviewNodes();
    
    // one clear root?
//    boolean foundroot = false;
//    for ( TreeOfTrustNode n : nodelist )
//    {
//      if ( n.)
//    }
    
  }
  
  
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    
    sb.append("Number of trees: ");
    sb.append( trees.size() );
    sb.append('\n');
    for ( TreeOfTrust tree : trees.values() )
      sb.append( tree.toString() );
    sb.append("End of List\n");
    return sb.toString();
  }
  
}
