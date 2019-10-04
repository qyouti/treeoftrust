/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import javax.swing.tree.DefaultMutableTreeNode;

/**
 *
 * @author maber01
 */
public class CryptoNode extends DefaultMutableTreeNode
{
  CryptographyManager cryptoman;

  public CryptoNode(CryptographyManager cryptoman)
  {
    this.cryptoman = cryptoman;
  }
}
