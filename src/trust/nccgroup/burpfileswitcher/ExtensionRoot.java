package trust.nccgroup.burpfileswitcher;

import burp.*;

import javax.swing.*;
import java.awt.*;

public class ExtensionRoot implements IBurpExtender {

  public static IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;

  public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    callbacks.setExtensionName("File Switcher");

    FileSwitcherTab fst = new FileSwitcherTab(callbacks);
//    fst.postInit();
    callbacks.customizeUiComponent(fst);
    callbacks.addSuiteTab(fst);

    new Thread(new Runnable() {
      void wait1() {
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) { }
      }

      @Override
      public void run() {
        Component p = fst.getParent();
        while (p == null) {
          wait1();
          p = fst.getParent();
        }
        fst.postInit();
      }
    }).start();

    callbacks.registerProxyListener(new FileSwitcherInterceptor(callbacks));

    callbacks.registerContextMenuFactory(new SendToFileSwitcher(callbacks, fst));
  }


}

