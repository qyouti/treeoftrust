/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import javax.swing.tree.DefaultMutableTreeNode;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

/**
 *
 * @author maber01
 */
public class TreeOfTrustNode extends DefaultMutableTreeNode
{
  String treename;
  PGPPublicKeyRing publickeyring;
  PGPPublicKey publickey;
  PGPSignature signature;
  long id;
  long signerid;
  String role;
  
  TestStatus supported          = TestStatus.DONTKNOW;
  TestStatus onekey             = TestStatus.DONTKNOW;
  TestStatus onesignature       = TestStatus.DONTKNOW;
  TestStatus intree             = TestStatus.DONTKNOW;
  TestStatus validsignature     = TestStatus.DONTKNOW;
  TestStatus root               = TestStatus.DONTKNOW;

  public long getId()
  {
    return id;
  }

  public long getSignerid()
  {
    return signerid;
  }

  public String getRole()
  {
    return role;
  }

  public String getSubjectUserId()
  {
    return publickey.getUserIDs().next();
  }

  public String toString()
  {
    StringBuilder line = new StringBuilder();
    line.append( Long.toHexString(id) );
    line.append( " " );
    line.append( publickey.getUserIDs().next() );
    return line.toString();
  }

  public String toStringDetail()
  {
    StringBuilder line = new StringBuilder();
    line.append( Long.toHexString(id) );
    while ( line.length() < 20 ) line.append( ' ' );
    line.append( "signer " );
    line.append( Long.toHexString(signerid) );
    while ( line.length() < 46 ) line.append( ' ' );
    line.append( "role " );
    line.append( role );     
    while ( line.length() < 65 ) line.append( ' ' );
    line.append( "Supported? ");
    line.append( supported );
    while ( line.length() < 88 ) line.append( ' ' );
    line.append( publickey.getUserIDs().next() );
    line.append("\n");
    return line.toString();
  }
}
