package trust.nccgroup.burpfileswitcher;

import burp.IHttpService;

import java.net.URI;

public class HttpService implements IHttpService {
  private String host;
  private int port;
  private String protocol;

  public HttpService(String _host, int _port, String _protocol) {
    host = _host;
    port = _port;
    protocol = _protocol;
  }

  public HttpService(URI u) {
    host = u.getHost();
    port = u.getPort();
    protocol = u.getScheme();
    if (port == -1) {
      if ("http".equals(protocol)) {
        port = 80;
      } else if ("https".equals(protocol)) {
        port = 443;
      } else {
        System.out.println("unknown protocol: " + protocol);
      }
    }
  }

  @Override
  public String getHost() {
    return host;
  }

  @Override
  public int getPort() {
    return port;
  }

  @Override
  public String getProtocol() {
    return protocol;
  }
}
