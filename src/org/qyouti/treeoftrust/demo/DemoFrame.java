/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust.demo;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.qyouti.treeoftrust.CryptographyManager;
import org.qyouti.treeoftrust.gui.TreeOfTrustPanel;
import org.qyouti.treeoftrust.CryptographyManagerConfiguration;
import org.qyouti.treeoftrust.CryptographyManagerException;
import org.qyouti.treeoftrust.PasswordProvider;
import org.qyouti.treeoftrust.TreeOfTrustException;
import org.qyouti.treeoftrust.TreeOfTrustStore;

/**
 *
 * @author maber01
 */
public class DemoFrame
        extends javax.swing.JFrame
        implements CryptographyManagerConfiguration, PasswordProvider
{
  CryptographyManager cryptoman;
  TreeOfTrustPanel treepanel;
  Properties p;
  String secringfilename = "demo/bob_secring.gpg";
  String pubringfilename = "demo/bob_pubring.gpg";
  String propsfilename   = "demo/bob_prefs.xml";
  String treefilename    = "demo/treeoftrust_pubring.gpg";
  PGPPublicKeyRingCollection treecoll;
  TreeOfTrustStore treestore;
  
  /**
   * Creates new form DemoFrame
   */
  public DemoFrame()
  {
    initComponents();
    this.setTitle("TreeOfTrust Demo");
    
    p = new Properties();
    loadProperties();
    cryptoman = new CryptographyManager( this );
    try
    {
      cryptoman.init();
      treecoll = cryptoman.loadPublicKeyRingCollection(treefilename);
      treestore = new TreeOfTrustStore();
      treestore.setPublicKeyRingCollection(treecoll);
      System.out.println( treestore.toString() );
      treepanel = new TreeOfTrustPanel();
      
      treepanel.setTreeoftrust( treestore.getTrees().iterator().next() );
      teamtabpanel.add( treepanel, java.awt.BorderLayout.CENTER );
    } catch (CryptographyManagerException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    } catch (TreeOfTrustException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    
  }

  private void loadProperties()
  {
    FileInputStream in=null;
    try
    {
      in = new FileInputStream( propsfilename );
      p.loadFromXML(in);
    } catch (IOException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    }
    finally
    {
      try
      {
        if ( in != null )
          in.close();
      } catch (IOException ex)
      {
        Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
      }
    }    
  }
  
  private void saveProperties()
  {
    FileOutputStream out = null;
    try
    {
      out = new FileOutputStream( propsfilename );
      p.storeToXML(out, "Demo");
    } catch (IOException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    } finally
    {
      try
      {
        if ( out != null )
          out.close();
      } catch (IOException ex)
      {
        Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
  }
  
  @Override
  public PasswordProvider getPasswordProvider()
  {
    return this;
  }

  @Override
  public long getPreferredKeyID()
  {
    String value = p.getProperty("org.qyouti.demo.preferredkeyid");
    if ( value == null ) return 0L;
    return Long.parseLong(value,16);
  }

  @Override
  public void setPreferredKeyID(long id)
  {
    p.setProperty("org.qyouti.demo.preferredkeyid",Long.toHexString(id) );
    saveProperties();
  }

  @Override
  public String getPublicKeyRingFileName()
  {
    return pubringfilename;
  }

  @Override
  public String getSecretKeyRingFileName()
  {
    return secringfilename;
  }

  private String getPropertyNameFromID( long id )
  {
    return "org.qyouti.demo.password_" + Long.toHexString(id);
  }
  
  @Override
  public void deleteStoredEncryptedPassword(long id)
  {
    p.remove( getPropertyNameFromID(id) );
    saveProperties();
  }

  @Override
  public String getStoredEncryptedPassword(long id)
  {
    return p.getProperty( getPropertyNameFromID(id) );
  }

  @Override
  public void setStoredEncryptedPassword(long id, String encryptedpassword)
  {
    p.setProperty( getPropertyNameFromID(id), encryptedpassword );
    saveProperties();
  }

  @Override
  public char[] getUserSuppliedPassword()
  {
    JPanel panel = new JPanel();
    JLabel label = new JLabel("Enter the password for your private key:");
    JPasswordField pass = new JPasswordField();
    panel.setLayout(new FlowLayout() );
    pass.setMinimumSize( new Dimension(200,30) );
    pass.setPreferredSize( pass.getMinimumSize() );
    pass.setSize( pass.getMinimumSize() );
    panel.add(label);
    panel.add(pass);
    panel.doLayout();
    String[] options = new String[]{"O.K.", "Cancel"};
    int option = JOptionPane.showOptionDialog(null, panel, "Enter Password",
                             JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                             null, options, options[1]);
    if(option == 0) // pressing OK button
      return pass.getPassword();
    return null;
  }

  
  
  
  
  /**
   * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
   * content of this method is always regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents()
  {

    jTabbedPane1 = new javax.swing.JTabbedPane();
    jPanel1 = new javax.swing.JPanel();
    jPanel2 = new javax.swing.JPanel();
    teamtabpanel = new javax.swing.JPanel();
    jMenuBar1 = new javax.swing.JMenuBar();
    jMenu1 = new javax.swing.JMenu();
    newteammenuitem = new javax.swing.JMenuItem();
    openteammenuitem = new javax.swing.JMenuItem();
    jSeparator1 = new javax.swing.JPopupMenu.Separator();
    exitmenuitem = new javax.swing.JMenuItem();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

    javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
    jPanel1.setLayout(jPanel1Layout);
    jPanel1Layout.setHorizontalGroup(
      jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addGap(0, 697, Short.MAX_VALUE)
    );
    jPanel1Layout.setVerticalGroup(
      jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addGap(0, 299, Short.MAX_VALUE)
    );

    jTabbedPane1.addTab("My Keys", jPanel1);

    javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
    jPanel2.setLayout(jPanel2Layout);
    jPanel2Layout.setHorizontalGroup(
      jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addGap(0, 697, Short.MAX_VALUE)
    );
    jPanel2Layout.setVerticalGroup(
      jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
      .addGap(0, 299, Short.MAX_VALUE)
    );

    jTabbedPane1.addTab("Other People's Keys", jPanel2);

    teamtabpanel.setLayout(new java.awt.BorderLayout());
    jTabbedPane1.addTab("Team", teamtabpanel);

    getContentPane().add(jTabbedPane1, java.awt.BorderLayout.CENTER);

    jMenu1.setText("File");

    newteammenuitem.setText("New Team");
    jMenu1.add(newteammenuitem);

    openteammenuitem.setText("Open Team");
    jMenu1.add(openteammenuitem);
    jMenu1.add(jSeparator1);

    exitmenuitem.setText("Exit");
    jMenu1.add(exitmenuitem);

    jMenuBar1.add(jMenu1);

    setJMenuBar(jMenuBar1);

    pack();
  }// </editor-fold>//GEN-END:initComponents

  /**
   * @param args the command line arguments
   */
  public static void main(String args[])
  {
    /* Set the Nimbus look and feel */
    //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
    /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
     */
    try
    {
      for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels())
      {
        if ("Nimbus".equals(info.getName()))
        {
          javax.swing.UIManager.setLookAndFeel(info.getClassName());
          break;
        }
      }
    }
    catch (ClassNotFoundException ex)
    {
      java.util.logging.Logger.getLogger(DemoFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (InstantiationException ex)
    {
      java.util.logging.Logger.getLogger(DemoFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (IllegalAccessException ex)
    {
      java.util.logging.Logger.getLogger(DemoFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (javax.swing.UnsupportedLookAndFeelException ex)
    {
      java.util.logging.Logger.getLogger(DemoFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    //</editor-fold>

    /* Create and display the form */
    java.awt.EventQueue.invokeLater(new Runnable()
    {
      public void run()
      {
        new DemoFrame().setVisible(true);
      }
    });
  }

  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JMenuItem exitmenuitem;
  private javax.swing.JMenu jMenu1;
  private javax.swing.JMenuBar jMenuBar1;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JPanel jPanel2;
  private javax.swing.JPopupMenu.Separator jSeparator1;
  private javax.swing.JTabbedPane jTabbedPane1;
  private javax.swing.JMenuItem newteammenuitem;
  private javax.swing.JMenuItem openteammenuitem;
  private javax.swing.JPanel teamtabpanel;
  // End of variables declaration//GEN-END:variables


}
