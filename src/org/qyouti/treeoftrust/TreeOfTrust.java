/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;


/**
 *
 * @author maber01
 */
public class TreeOfTrust extends DefaultTreeModel
{
  TreeOfTrustStore store;
  String name;
  
  final ArrayList<TreeOfTrustNode> nodelist        = new ArrayList<>();

  public TreeOfTrust( TreeOfTrustStore store, String name )
  {
    super(null);
    this.store = store;
    this.name = name;
  }

  public void addNode( TreeOfTrustNode node )
  {
    nodelist.add(node);
  }
  
  public void reviewNodes()
  {
    // find root
    ArrayList<TreeOfTrustNode> roots = new ArrayList<>();
    for ( TreeOfTrustNode node : nodelist )
      if ( TreeOfTrustStore.ROLE_CREATOR.equals( node.role ) )
        roots.add( node );
    
    if ( roots.size() != 1 )
      return;
    
    setRoot( roots.get(0) );
    nodelist.remove( roots.get(0) );
    
    findChildren( roots.get(0) );
  }
  
  public void findChildren( TreeOfTrustNode parent )
  {
    for ( TreeOfTrustNode node : nodelist )
      if ( node.signerid == parent.id )
        parent.add(node);
    
    for ( int i=0; i< parent.getChildCount(); i++ )
      nodelist.remove( parent.getChildAt(i) );

    for ( int i=0; i< parent.getChildCount(); i++ )
      findChildren( (TreeOfTrustNode)parent.getChildAt(i) );
  }
  
  public String nodeToString( int depth, TreeOfTrustNode node )
  {
    StringBuilder sb = new StringBuilder();
    for ( int i=0; i<depth; i++ )
      sb.append(" ");
    sb.append( node.toString() );
    for ( int i=0; i<node.getChildCount(); i++ )
      sb.append( nodeToString( depth+1, (TreeOfTrustNode)node.getChildAt(i) ) );
    return sb.toString();
  }
  
  
  public String toString()
  {
    return name;
  }

  
  public String toDetailedString()
  {
    StringBuilder sb = new StringBuilder();
    
    sb.append("Tree: \n");
    sb.append( nodeToString(0,(TreeOfTrustNode)getRoot() ) );
    sb.append("Unattached nodes: ");
    sb.append( nodelist.size() );
    sb.append('\n');
    for ( TreeOfTrustNode node : nodelist )
      sb.append( node.toString() );
    sb.append("End of List\n");
    return sb.toString();
  }
  
  
}
