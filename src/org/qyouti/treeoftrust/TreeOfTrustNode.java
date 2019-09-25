/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

/**
 *
 * @author maber01
 */
public class TreeOfTrustNode
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
  
  TreeOfTrustNode parent=null;
  final ArrayList<TreeOfTrustNode> children=new ArrayList<>();
}
