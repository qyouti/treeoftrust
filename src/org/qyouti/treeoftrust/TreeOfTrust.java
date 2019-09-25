/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;


/**
 *
 * @author maber01
 */
public class TreeOfTrust
{
  TreeOfTrustStore store;
  String name;
  
  final ArrayList<TreeOfTrustListener> listeners = new ArrayList<>();
  final ArrayList<TreeOfTrustNode> nodelist = new ArrayList<>();


  public TreeOfTrust( TreeOfTrustStore store, String name )
  {
    this.store = store;
    this.name = name;
  }

  public void addNode( TreeOfTrustNode node )
  {
    nodelist.add(node);
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
      line.append( Long.toHexString(node.id) );
      while ( line.length() < 20 ) line.append( ' ' );
      line.append( "signer " );
      line.append( Long.toHexString(node.signerid) );
      while ( line.length() < 46 ) line.append( ' ' );
      line.append( "role " );
      line.append( node.role );     
      while ( line.length() < 65 ) line.append( ' ' );
      line.append( "Supported? ");
      line.append( node.supported );
      while ( line.length() < 88 ) line.append( ' ' );
      line.append( node.publickey.getUserIDs().next() );
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
