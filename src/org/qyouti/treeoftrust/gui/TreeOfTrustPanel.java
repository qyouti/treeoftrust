/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust.gui;

import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.TreePath;
import org.qyouti.treeoftrust.TreeOfTrust;
import org.qyouti.treeoftrust.TreeOfTrustNode;

/**
 *
 * @author jon
 */
public class TreeOfTrustPanel extends javax.swing.JPanel
        implements TreeSelectionListener
{

  TreeOfTrust treeoftrust;
  TreeOfTrustNodePanel nodepanel;
  
  /**
   * Creates new form TreeOfTrustPanel
   */
  public TreeOfTrustPanel()
  {
    initComponents();
    nodepanel = new TreeOfTrustNodePanel();
    treenodelscrollpanel.setViewportView(nodepanel);
    tree.addTreeSelectionListener( this );
  }

  public TreeOfTrust getTreeoftrust()
  {
    return treeoftrust;
  }

  public void setTreeoftrust( TreeOfTrust treeoftrust )
  {
    this.treeoftrust = treeoftrust;
    tree.setModel( treeoftrust );
    tree.setCellRenderer( new TreeNodeRenderer() );
  }

  @Override
  public void valueChanged(TreeSelectionEvent e)
  {
    System.out.println( "Select " + e.getPath() );
    TreePath p = e.getPath();
    if ( p == null || !(p.getLastPathComponent() instanceof TreeOfTrustNode) )
      nodepanel.setTreeOfTrustNode( null );
    else
      nodepanel.setTreeOfTrustNode( (TreeOfTrustNode)p.getLastPathComponent() );
  }
  
  
  
  /**
   * This method is called from within the constructor to initialize the form.
   * WARNING: Do NOT modify this code. The content of this method is always
   * regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents()
  {

    splitpane = new javax.swing.JSplitPane();
    leftpanel = new javax.swing.JPanel();
    treescrollpane = new javax.swing.JScrollPane();
    tree = new javax.swing.JTree();
    jPanel2 = new javax.swing.JPanel();
    keylabel = new javax.swing.JLabel();
    treenodelscrollpanel = new javax.swing.JScrollPane();

    setLayout(new java.awt.BorderLayout());

    splitpane.setDividerLocation(250);
    splitpane.setDividerSize(16);

    leftpanel.setLayout(new java.awt.BorderLayout());

    treescrollpane.setViewportView(tree);

    leftpanel.add(treescrollpane, java.awt.BorderLayout.CENTER);

    jPanel2.setLayout(new java.awt.BorderLayout());

    keylabel.setText("Keys");
    jPanel2.add(keylabel, java.awt.BorderLayout.CENTER);

    leftpanel.add(jPanel2, java.awt.BorderLayout.NORTH);

    splitpane.setLeftComponent(leftpanel);
    splitpane.setRightComponent(treenodelscrollpanel);

    add(splitpane, java.awt.BorderLayout.CENTER);
  }// </editor-fold>//GEN-END:initComponents


  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JPanel jPanel2;
  private javax.swing.JLabel keylabel;
  private javax.swing.JPanel leftpanel;
  private javax.swing.JSplitPane splitpane;
  private javax.swing.JTree tree;
  private javax.swing.JScrollPane treenodelscrollpanel;
  private javax.swing.JScrollPane treescrollpane;
  // End of variables declaration//GEN-END:variables

}
