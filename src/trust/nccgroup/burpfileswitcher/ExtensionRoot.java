package trust.nccgroup.burpfileswitcher;

import burp.*;

public class ExtensionRoot implements IBurpExtender {

  public static IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;

  public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    callbacks.setExtensionName("File Switcher");

    FileSwitcherTab fst = new FileSwitcherTab(callbacks);

    callbacks.customizeUiComponent(fst);
    callbacks.addSuiteTab(fst);

    callbacks.registerHttpListener(new FileSwitcherInterceptor(callbacks));

    callbacks.registerContextMenuFactory(new SendToFileSwitcher(callbacks, fst));
  }


}

