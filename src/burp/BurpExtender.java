package burp;

import trust.nccgroup.burpfileswitcher.ExtensionRoot;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ExtensionRoot exr = new ExtensionRoot();
        exr.registerExtenderCallbacks(callbacks);
    }
}
