/*
Copyright 2018-2022 NCC Group

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

