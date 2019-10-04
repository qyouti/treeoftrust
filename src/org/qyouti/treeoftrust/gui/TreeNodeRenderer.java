/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust.gui;

import java.awt.Component;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.TreeCellRenderer;
import org.qyouti.treeoftrust.SecretKeyNode;
import org.qyouti.treeoftrust.TreeOfTrustNode;

/**
 *
 * @author jon
 */
public class TreeNodeRenderer extends DefaultTreeCellRenderer
{
  ImageIcon keyicon, keypairicon;
  
  public TreeNodeRenderer()
  {
    super();
    keyicon = new ImageIcon(TreeNodeRenderer.class.getResource("/org/qyouti/treeoftrust/gui/res/key.png"));    
    keypairicon = new ImageIcon(TreeNodeRenderer.class.getResource("/org/qyouti/treeoftrust/gui/res/keypair.png"));    
    setClosedIcon(keyicon);
    setOpenIcon(keyicon);
    setLeafIcon(keyicon);
  }
  
  
  
  
  @Override
  public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus)
  {
    ImageIcon icon=keyicon;
    if ( value instanceof SecretKeyNode )
      icon = keypairicon;
    setClosedIcon(icon);
    setOpenIcon(icon);
    setLeafIcon(icon);      
    return super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
  }
  
}
