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
import org.qyouti.treeoftrust.TreeOfTrustNode;

/**
 *
 * @author jon
 */
public class TreeNodeRenderer extends DefaultTreeCellRenderer
{
  ImageIcon keyicon;
  
  public TreeNodeRenderer()
  {
    super();
    keyicon = new ImageIcon(TreeNodeRenderer.class.getResource("/org/qyouti/treeoftrust/gui/res/key.png"));    
    this.setClosedIcon(keyicon);
    this.setOpenIcon(keyicon);
    this.setLeafIcon(keyicon);
  }
  
  
  
  
  @Override
  public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus)
  {
    super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
    //this.setText( value.toString() );
    return this;
  }
  
}
