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

import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class FileSwitcherInterceptor implements IProxyListener {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;

  byte[] crlf = "\r\n".getBytes(StandardCharsets.UTF_8);
  private static final Pattern crlf_matcher = Pattern.compile("\\r\\n|\\n|\\r", Pattern.MULTILINE);

  public FileSwitcherInterceptor(IBurpExtenderCallbacks _callbacks) {
    callbacks = _callbacks;
    helpers = callbacks.getHelpers();
  }

  @Override
  public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
//    if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
//      return;
//    }

    IHttpRequestResponse messageInfo = message.getMessageInfo();

    byte[] orig_req = messageInfo.getRequest();
    IRequestInfo ireqi = helpers.analyzeRequest(messageInfo.getHttpService(), orig_req);
    if (!"get".equals(ireqi.getMethod().toLowerCase())) {
      return;
    }

    String orig_req_str = new String(orig_req, StandardCharsets.UTF_8);
    String first_line = orig_req_str.substring(0, orig_req_str.indexOf("\r\n"));
    if (!messageIsRequest && first_line.contains("#fileswitcher-http2 HTTP/1.1")) {
      String orig_res_str = new String(messageInfo.getResponse(), StandardCharsets.UTF_8);
      String new_res_str = orig_res_str.replace("HTTP/1.1", "HTTP/2");
      messageInfo.setResponse(new_res_str.getBytes(StandardCharsets.UTF_8));
      return;
    }

    FileManager fm = FileManager.getInstance();
    URL u = ireqi.getUrl();

    FileSwitch fs = fm.getFileSwitch(u);
    if (fs == null) {
      return;
    }

    if (messageIsRequest) {
      if (fs.remote_uri != null && !"".equals(fs.remote_uri)) {
        try {
          IHttpService orig_httpservice = messageInfo.getHttpService();
          URI nu = new URI(fs.remote_uri);
          IHttpService new_httpservice = new HttpService(nu);
          //String orig_req_str = new String(orig_req, StandardCharsets.UTF_8);
          String new_req_str = orig_req_str.replace("GET " + u.getPath(), "GET " + nu.getRawPath() + "?" + nu.getRawQuery());
          boolean ish2 = first_line.contains(" HTTP/2");

          if (ish2) {
            new_req_str = new_req_str.replace(" HTTP/2", "#fileswitcher-http2 HTTP/1.1");
          }

          //IHttpRequestResponse nres = callbacks.makeHttpRequest(new_httpservice, orig_req_str.getBytes(StandardCharsets.UTF_8), false);
          //messageInfo.setResponse(nres.getResponse());

          messageInfo.setHttpService(new_httpservice);
          messageInfo.setRequest(new_req_str.getBytes(StandardCharsets.UTF_8));

          return;
        } catch (Throwable t) {
          t.printStackTrace();
          return;
        }
      }

      String req_s = new String(orig_req, StandardCharsets.UTF_8);
      String[] lines = crlf_matcher.split(req_s, -1);

      List<byte[]> nlines = new ArrayList<>(lines.length);
      nlines.add(lines[0].getBytes(StandardCharsets.UTF_8));
      for (int i=1; i < lines.length; i++) {
        String line = lines[i].toLowerCase(Locale.US);
        if (!line.startsWith("if-")) {
          nlines.add(lines[i].getBytes(StandardCharsets.UTF_8));
        }
      }

      int nrl = 0;
      for (byte[] b : nlines) {
        nrl += b.length + 2;
      }
      nrl -= 2;

      int pos = 0;
      byte[] new_req = new byte[nrl];
      byte[] b;
      for (int i=0; i < nlines.size()-1; i++) {
        b = nlines.get(i);
        System.arraycopy(b, 0, new_req, pos, b.length);
        pos += b.length;
        System.arraycopy(crlf, 0, new_req, pos, crlf.length);
        pos += crlf.length;
      }
      b = nlines.get(nlines.size()-1);
      System.arraycopy(b, 0, new_req, pos, b.length);

      messageInfo.setRequest(new_req);
      return;
    }

    byte[] orig_res = messageInfo.getResponse();

    if (fs.remote_uri != null && !"".equals(fs.remote_uri)) {
      return;
    }

    byte[] alt = fs.getRawData();
    if (alt == null) {
      return;
    }

    IResponseInfo iresi = helpers.analyzeResponse(orig_res);
    int bp = iresi.getBodyOffset();
    byte[] head = new byte[bp];
    try {
      System.arraycopy(orig_res, 0, head, 0, bp);
    } catch (IndexOutOfBoundsException ioobe) {
      return;
    }

    String head_s = new String(head, StandardCharsets.UTF_8);
    String[] lines = crlf_matcher.split(head_s, -1);


    List<byte[]> nlines = new ArrayList<>(lines.length);
    if (iresi.getStatusCode() != 304) {
      nlines.add(lines[0].getBytes(StandardCharsets.UTF_8));
    } else {
      nlines.add("HTTP/1.1 200 OK".getBytes(StandardCharsets.UTF_8));
    }
    for (int i=1; i < lines.length; i++) {
      String line = lines[i].toLowerCase(Locale.US);
      if (line.startsWith("content-length:")) {
        nlines.add(
          String.format("%s: %d", lines[i].split(":")[0], alt.length)
            .getBytes(StandardCharsets.UTF_8)
        );
      } else {
        nlines.add(lines[i].getBytes(StandardCharsets.UTF_8));
      }
    }

    int nrl = alt.length;
    for (byte[] b : nlines) {
      nrl += b.length + 2;
    }
    nrl -= 2;

    int pos = 0;
    byte[] new_res = new byte[nrl];
    byte[] b;
    for (int i=0; i < nlines.size()-1; i++) {
      b = nlines.get(i);
      System.arraycopy(b, 0, new_res, pos, b.length);
      pos += b.length;
      System.arraycopy(crlf, 0, new_res, pos, crlf.length);
      pos += crlf.length;
    }
    b = nlines.get(nlines.size()-1);
    System.arraycopy(b, 0, new_res, pos, b.length);
    pos += b.length;

    System.arraycopy(alt, 0, new_res, pos, alt.length);
    messageInfo.setResponse(new_res);
  }
}
