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
