package trust.nccgroup.burpfileswitcher;

import burp.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SendToFileSwitcher implements IContextMenuFactory {

  private final IBurpExtenderCallbacks callbacks;
  private final IExtensionHelpers helpers;
  private final FileSwitcherTab fileSwitcherTab;

  public SendToFileSwitcher(IBurpExtenderCallbacks _callbacks, FileSwitcherTab _fileSwitcherTab) {
    callbacks = _callbacks;
    helpers = callbacks.getHelpers();
    fileSwitcherTab = _fileSwitcherTab;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    List<JMenuItem> menu = new ArrayList<>();
    ActionListener listener;
    final int toolFlag = invocation.getToolFlag();

    if (toolFlag == -1) {
      return null;
    }

    final IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();

    listener = new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        new Thread(() -> {
          final FileSwitcherTableModel fstm = fileSwitcherTab.getFileSwitchers().getFileSwitcherTableModel();
          int successes = 0;
          for (IHttpRequestResponse requestResponse : requestResponses) {
            final URL u;
            {
              IRequestInfo ireqi = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
              u = ireqi.getUrl();
            }
            String comment = requestResponse.getComment();
            String data = "";

            byte[] res = requestResponse.getResponse();
            if (res != null) {
              IResponseInfo iresi = helpers.analyzeResponse(res);
              int pos = iresi.getBodyOffset();
              byte[] body = new byte[res.length - pos];
              System.arraycopy(res, pos, body, 0, body.length);
              try {
                data = new String(body, StandardCharsets.UTF_8);
              } catch (Throwable t) {
                callbacks.issueAlert("[FileSwitcher] Failed to decode response as UTF-8.");
              }
            }
            FileSwitch fs = new FileSwitch(FileManager.getKey(u), comment);
            fs.data = data;
            fstm.add(fs);
            successes += 1;
          }
          if (successes > 0) {
            fstm.fireTableDataChanged();
            fileSwitcherTab.highlight();
          }
        }
        ).start();
      }
    };

    JMenuItem item = new JMenuItem("Send to File Switcher", null);
    item.addActionListener(listener);
    menu.add(item);
    return menu;
  }
}
