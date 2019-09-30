/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust.gui;

import java.awt.Component;
import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.tree.TreeCellRenderer;
import org.qyouti.treeoftrust.TreeOfTrustNode;

/**
 *
 * @author jon
 */
public class TreeOfTrustNodePanel extends javax.swing.JPanel
{  
  /**
   * Creates new form TreeOfTrustNodePanel
   */
  public TreeOfTrustNodePanel()
  {
    initComponents();
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
    java.awt.GridBagConstraints gridBagConstraints;

    namelabel = new javax.swing.JLabel();
    idlabel = new javax.swing.JLabel();

    setOpaque(false);

    namelabel.setText("name");

    idlabel.setText("id");

    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
    this.setLayout(layout);
    layout.setHorizontalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addComponent(namelabel, javax.swing.GroupLayout.DEFAULT_SIZE, 473, Short.MAX_VALUE)
      .addComponent(idlabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
    );
    layout.setVerticalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addGroup(layout.createSequentialGroup()
        .addComponent(namelabel)
        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
        .addComponent(idlabel)
        .addContainerGap())
    );
  }// </editor-fold>//GEN-END:initComponents


  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JLabel idlabel;
  private javax.swing.JLabel namelabel;
  // End of variables declaration//GEN-END:variables

  public void setTreeOfTrustNode( TreeOfTrustNode node )
  {
    namelabel.setText("");
    idlabel.setText("");
    if ( node == null )
      return;
    namelabel.setText(node.getSubjectUserId());
    idlabel.setText( Long.toHexString(node.getId()));
    doLayout();
  }
}