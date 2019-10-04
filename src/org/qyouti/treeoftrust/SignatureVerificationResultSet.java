/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.swing.table.AbstractTableModel;

/**
 * Note this:
 * https://superuser.com/questions/706677/combining-gpg-key-signatures-into-one-key-file
 * This class represents the results of checking multiple signatures using a single user
 * configured collection of key rings. The key ring
 * @author maber01
 */
public class SignatureVerificationResultSet
        extends AbstractTableModel
{
  boolean verified;
  private ArrayList<SignatureVerificationResult> resultsinorder = new ArrayList<>();
  private HashMap<Long,SignatureVerificationResult> results = new HashMap<>();

  public void add( SignatureVerificationResult result )
  {
    resultsinorder.add(result);
    results.put(result.keyid, result);
  }
  
  public SignatureVerificationResult getSignatureVerificationResultAt( int n )
  {
    if ( n<0 || n>= resultsinorder.size() )
      return null;
    return resultsinorder.get(n);
  }
  
  public SignatureVerificationResult get( long keyid )
  {
    return results.get(keyid);
  }
  
  
  @Override
  public int getRowCount()
  {
    return resultsinorder.size();
  }

  @Override
  public int getColumnCount()
  {
    return 3;
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex)
  {
    if ( rowIndex < 0 || rowIndex >=getRowCount() || columnIndex<0 || columnIndex>=getColumnCount() )
      return null;
    
    SignatureVerificationResult result = resultsinorder.get(rowIndex);
    switch ( columnIndex )
    {
      case 0:
        return result.keyalias;
      case 1:
        return result.trustedkey;
      case 2:
        return result.verified;
    }
    return null;
  }

  @Override
  public Class<?> getColumnClass(int columnIndex)
  {
    switch ( columnIndex )
    {
      case 0:
        return String.class;
      case 1:
        return Boolean.class;
      case 2:
        return Boolean.class;
    }
    return null;
  }

  @Override
  public String getColumnName(int column)
  {
    switch ( column )
    {
      case 0:
        return "Signer Name";
      case 1:
        return "Trusted Key";
      case 2:
        return "Verified";
    }
    return null;
  }
  
  
}
