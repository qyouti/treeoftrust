/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
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
public class TreeOfTrust
{
  public final static String NOTATION_NAME_TREEOFTRUST = "treeoftrust@github.com/qyouti/treeoftrust";
  
  
  PGPPublicKeyRingCollection keyringcollection;
  final ArrayList<TreeOfTrustListener> listeners = new ArrayList<>();
  ArrayList<TreeOfTrustNode> nodelist;
  
  public void setPublicKeyRingCollection( PGPPublicKeyRingCollection keyringcollection )
          throws TreeOfTrustException
  {
    this.keyringcollection = keyringcollection;
    parseKeyRingCollection();
  }
  
  
  private boolean parseSignature( TreeOfTrustNode node )
  {
    Iterator sigit = node.publickey.getSignatures();
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
        if ( NOTATION_NAME_TREEOFTRUST.equals( nd.getNotationName() ) && "true".equalsIgnoreCase( nd.getNotationValue() ) )
        {
          if ( node.signature != null )
            node.signature = null;
          else
            node.signature = signature;
        }
      }
    }
    
    if ( node.signature != null )
    {
      node.signerid = signature.getKeyID();
      node.onesignature = TestStatus.TRUE;
      return true;
    }
    
    node.onesignature = TestStatus.FALSE;
    node.supported = TestStatus.FALSE;
    return false;
  }
  
  private void parseKeyRingCollection()
          throws TreeOfTrustException
  {
    // Start by making list of nodes...
    nodelist = new ArrayList<>();
    TreeOfTrustNode currentnode;
    Iterator<PGPPublicKeyRing> keyringit = keyringcollection.getKeyRings();
    while ( keyringit.hasNext() )
    {
      currentnode = new TreeOfTrustNode();
      currentnode.publickeyring = keyringit.next();
      nodelist.add(currentnode);
      
      // first test
      Iterator<PGPPublicKey> keyit = currentnode.publickeyring.getPublicKeys();
      if ( !keyit.hasNext() )
      {
        currentnode.onekey = TestStatus.FALSE;
        currentnode.supported = TestStatus.FALSE;
        continue;
      }
      currentnode.publickey = keyit.next();
      if ( keyit.hasNext() )
      {
        currentnode.onekey = TestStatus.FALSE;
        currentnode.supported = TestStatus.FALSE;
        continue;
      }
      
      currentnode.id = currentnode.publickey.getKeyID();
      
      if ( !parseSignature( currentnode ) )
        continue;
      
      
      currentnode.supported = TestStatus.TRUE;
    }
    
    // one clear root?
//    boolean foundroot = false;
//    for ( TreeOfTrustNode n : nodelist )
//    {
//      if ( n.)
//    }
    
    
    notifyListeners();
  }
  
  
  public String toString()
  {
    StringBuilder sb = new StringBuilder();
    
    sb.append("Number of nodes: ");
    sb.append( nodelist.size() );
    sb.append('\n');
    for ( TreeOfTrustNode node : nodelist )
    {
      StringBuilder line = new StringBuilder();
      line.append( node.id );
      while ( line.length() < 24 ) line.append( ' ' );
      line.append( node.publickey.getUserIDs().next() );
      while ( line.length() < 50 ) line.append( ' ' );
      line.append( "Supported? ");
      line.append( node.supported );
      while ( line.length() < 70 ) line.append( ' ' );
      line.append( "signer " );
      line.append( node.signerid );      
      line.append("\n");
      sb.append(line);
    }
    sb.append("End of List\n");
    return sb.toString();
  }
  
  public void addListener( TreeOfTrustListener l )
  {
    listeners.add(l);
  }
  
  public void removeListener( TreeOfTrustListener l )
  {
    listeners.remove(l);
  }
  
  private void notifyListeners()
  {
    for ( TreeOfTrustListener l : listeners )
      l.treeOfTrustChanged(this);
  }
}
