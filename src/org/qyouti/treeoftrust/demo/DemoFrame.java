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
import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.qyouti.treeoftrust.CryptographyManager;
import org.qyouti.treeoftrust.gui.TreeOfTrustPanel;
import org.qyouti.treeoftrust.CryptographyManagerConfiguration;
import org.qyouti.treeoftrust.CryptographyManagerException;
import org.qyouti.treeoftrust.KeyRingCollectionTreeModel;
import org.qyouti.treeoftrust.PasswordProvider;
import org.qyouti.treeoftrust.TreeOfTrust;
import org.qyouti.treeoftrust.TreeOfTrustException;
import org.qyouti.treeoftrust.TreeOfTrustStore;
import org.qyouti.treeoftrust.gui.KeyRingCollectionPanel;

/**
 *
 * @author maber01
 */
public class DemoFrame
        extends javax.swing.JFrame
        implements CryptographyManagerConfiguration, PasswordProvider, ListSelectionListener

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
  
  KeyRingCollectionTreeModel mykeys;
  KeyRingCollectionPanel mykeyspanel;

  KeyRingCollectionTreeModel otherpeopleskeys;
  KeyRingCollectionPanel otherpeopleskeyspanel;
  
  /**
   * Creates new form DemoFrame
   */
  public DemoFrame()
  {
    initComponents();
    this.setTitle("TreeOfTrust Demo");
    this.setSize(900, 500);
    
    p = new Properties();
    loadProperties();
    cryptoman = new CryptographyManager( this );
    try
    {
      cryptoman.init();
      
      mykeys = cryptoman.getSecretKeyTreeModel();
      mykeyspanel = new KeyRingCollectionPanel();
      mykeyspanel.setKeyRingCollectionTreeModel( mykeys );
      mykeystabpanel.add( mykeyspanel, java.awt.BorderLayout.CENTER );
      
      otherpeopleskeys = cryptoman.getPublicKeyTreeModel();
      otherpeopleskeyspanel = new KeyRingCollectionPanel();
      otherpeopleskeyspanel.setKeyRingCollectionTreeModel( otherpeopleskeys );
      otherskeystabpanel.add( otherpeopleskeyspanel, java.awt.BorderLayout.CENTER );
      
      treecoll = cryptoman.loadPublicKeyRingCollection(treefilename);
      treestore = new TreeOfTrustStore();
      treestore.setPublicKeyRingCollection(treecoll);
      System.out.println( treestore.toString() );
      
      DefaultListModel listmodel = new DefaultListModel();
      for ( TreeOfTrust tree : treestore.getTrees() )
        listmodel.addElement( tree );
      
      teamlist.setModel( listmodel );
      teamlist.addListSelectionListener( this );
      
    } catch (CryptographyManagerException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    } catch (TreeOfTrustException ex)
    {
      Logger.getLogger(DemoFrame.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    
  }

  @Override
  public void valueChanged(ListSelectionEvent e)
  {
    if ( e.getSource() == teamlist )
    {
      teamsidepanel.removeAll();
      Object o = teamlist.getSelectedValue();
      if ( o != null && o instanceof TreeOfTrust )
      {
        TreeOfTrust tree = (TreeOfTrust)o;
        treepanel = new TreeOfTrustPanel();
        treepanel.setTreeoftrust( tree );
        teamsidepanel.add( treepanel, java.awt.BorderLayout.CENTER );      
      }
      teamsidepanel.validate();
      teamsidepanel.repaint();
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
    mykeystabpanel = new javax.swing.JPanel();
    jPanel3 = new javax.swing.JPanel();
    jLabel2 = new javax.swing.JLabel();
    otherskeystabpanel = new javax.swing.JPanel();
    jPanel4 = new javax.swing.JPanel();
    jLabel3 = new javax.swing.JLabel();
    teamtabpanel = new javax.swing.JPanel();
    jPanel5 = new javax.swing.JPanel();
    jLabel4 = new javax.swing.JLabel();
    jSplitPane1 = new javax.swing.JSplitPane();
    jPanel1 = new javax.swing.JPanel();
    jScrollPane1 = new javax.swing.JScrollPane();
    teamlist = new javax.swing.JList<>();
    jPanel2 = new javax.swing.JPanel();
    jLabel1 = new javax.swing.JLabel();
    teamsidepanel = new javax.swing.JPanel();
    jMenuBar1 = new javax.swing.JMenuBar();
    jMenu1 = new javax.swing.JMenu();
    newteammenuitem = new javax.swing.JMenuItem();
    openteammenuitem = new javax.swing.JMenuItem();
    jSeparator1 = new javax.swing.JPopupMenu.Separator();
    exitmenuitem = new javax.swing.JMenuItem();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    setMaximumSize(new java.awt.Dimension(1000, 600));

    mykeystabpanel.setLayout(new java.awt.BorderLayout());

    jPanel3.setBorder(javax.swing.BorderFactory.createEmptyBorder(8, 8, 8, 8));
    jPanel3.setLayout(new java.awt.BorderLayout());

    jLabel2.setText("<html>\n<body>\n<p>This tab lists key pairs that are stored in your own secret key store. A key pair consists of a private key and a matching public key.  The private key must be kept secret and is never shared with any other person but other people can establish that you own the private key with the help of your public key.  You will usually have just one key pair but you can have many if you want.</p>\n</body>\n</html>");
    jPanel3.add(jLabel2, java.awt.BorderLayout.CENTER);

    mykeystabpanel.add(jPanel3, java.awt.BorderLayout.NORTH);

    jTabbedPane1.addTab("My Key Pairs", mykeystabpanel);

    otherskeystabpanel.setLayout(new java.awt.BorderLayout());

    jPanel4.setBorder(javax.swing.BorderFactory.createEmptyBorder(8, 8, 8, 8));
    jPanel4.setLayout(new java.awt.BorderLayout());

    jLabel3.setText("<html>\n<body>\n<p>This tab lists public keys that are stored in your own public key store. \nThese are public keys that belong to other people - those people will have the complete key pairs\nstored safely in their own secret key stores.  Each public key will have one or more signatures\nthat describe the key.  The signatures can be used to determine that the public key has not been\ntampered with.</p>\n</body>\n</html>");
    jPanel4.add(jLabel3, java.awt.BorderLayout.CENTER);

    otherskeystabpanel.add(jPanel4, java.awt.BorderLayout.NORTH);

    jTabbedPane1.addTab("Public Keys I Trust", otherskeystabpanel);

    teamtabpanel.setLayout(new java.awt.BorderLayout());

    jPanel5.setBorder(javax.swing.BorderFactory.createEmptyBorder(8, 8, 8, 8));
    jPanel5.setLayout(new java.awt.BorderLayout());

    jLabel4.setText("<html>\n<body>\n<p>This tab shows the teams stored in a shared team file.  For each team there are\na number of public keys listed. One person creates the team and can add more members.\nIf a member is listed as a team 'controller' that person can also add members.</p>\n</body>\n</html>");
    jPanel5.add(jLabel4, java.awt.BorderLayout.CENTER);

    teamtabpanel.add(jPanel5, java.awt.BorderLayout.NORTH);

    jPanel1.setLayout(new java.awt.BorderLayout());

    teamlist.setModel(new javax.swing.AbstractListModel<String>()
    {
      String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
      public int getSize() { return strings.length; }
      public String getElementAt(int i) { return strings[i]; }
    });
    jScrollPane1.setViewportView(teamlist);

    jPanel1.add(jScrollPane1, java.awt.BorderLayout.CENTER);

    jLabel1.setText("Team Names");
    jPanel2.add(jLabel1);

    jPanel1.add(jPanel2, java.awt.BorderLayout.NORTH);

    jSplitPane1.setLeftComponent(jPanel1);

    teamsidepanel.setLayout(new java.awt.BorderLayout());
    jSplitPane1.setRightComponent(teamsidepanel);

    teamtabpanel.add(jSplitPane1, java.awt.BorderLayout.CENTER);

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
  private javax.swing.JLabel jLabel1;
  private javax.swing.JLabel jLabel2;
  private javax.swing.JLabel jLabel3;
  private javax.swing.JLabel jLabel4;
  private javax.swing.JMenu jMenu1;
  private javax.swing.JMenuBar jMenuBar1;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JPanel jPanel2;
  private javax.swing.JPanel jPanel3;
  private javax.swing.JPanel jPanel4;
  private javax.swing.JPanel jPanel5;
  private javax.swing.JScrollPane jScrollPane1;
  private javax.swing.JPopupMenu.Separator jSeparator1;
  private javax.swing.JSplitPane jSplitPane1;
  private javax.swing.JTabbedPane jTabbedPane1;
  private javax.swing.JPanel mykeystabpanel;
  private javax.swing.JMenuItem newteammenuitem;
  private javax.swing.JMenuItem openteammenuitem;
  private javax.swing.JPanel otherskeystabpanel;
  private javax.swing.JList<String> teamlist;
  private javax.swing.JPanel teamsidepanel;
  private javax.swing.JPanel teamtabpanel;
  // End of variables declaration//GEN-END:variables



}
