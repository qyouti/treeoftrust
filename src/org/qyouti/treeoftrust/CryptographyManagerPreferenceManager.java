/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.qyouti.treeoftrust;

import java.util.prefs.Preferences;

/**
 *
 * @author maber01
 */
public interface CryptographyManagerPreferenceManager
{
  public Preferences getPreferences();
  public void savePreferences();
}
