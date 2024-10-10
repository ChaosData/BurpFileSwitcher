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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FileManager {

  private Map<String, FileSwitch> map = new ConcurrentHashMap<>();

  private static FileManager fm = null;

  public static FileManager getInstance() {
    return getInstance(BurpFileSwitcher.extensionName);
  }
  public static synchronized FileManager getInstance(String pluginpath) {
    if (fm != null) {
      return fm;
    }

    fm = new FileManager();
    return fm;
  }

  void clear() {
    map.clear();
  }


  public static String getKey(String uri) {
    if ("".equals(uri)) {
      return null;
    }
    try {
      URL u = new URL(uri);
      return getKey(u);
    } catch (MalformedURLException e) {
      String msg = "invalid URI: " + uri;
      if (ExtensionRoot.callbacks != null) {
        ExtensionRoot.callbacks.issueAlert(msg);
      } else {
        System.err.println(msg);
      }
      return null;
    }
  }

  public static String getKey(String origin, String path) {
    String key = origin + path;
    return key;
  }

  public static String getKey(URL u) {
    String origin = u.getProtocol() + "://" + u.getHost();
    int port = u.getPort();
    if (port == -1) {
      switch (u.getProtocol()) {
        case "http": {
          port = 80;
          break;
        }
        case "https": {
          port = 443;
          break;
        }
        default: {
          String msg = "invalid protocol: " + u.getProtocol();
          if (ExtensionRoot.callbacks != null) {
            ExtensionRoot.callbacks.issueAlert(msg);
          } else {
            System.err.println(msg);
          }
        }
      }
    }
    origin += ":" + port;

    String path = u.getPath();
    String key = getKey(origin, path);
    return key;
  }

  public FileSwitch getFileSwitch(String key) {
    FileSwitch fs = map.getOrDefault(key, null);
    if (fs != null) {
      if (!fs.isEnabled) {
        return null;
      }
      return fs;
    }
    return null;
  }

  public FileSwitch getFileSwitch(URL u) {
    return getFileSwitch(getKey(u));
  }

  public byte[] getFile(String key) {
    FileSwitch fs = map.getOrDefault(key, null);
    if (fs != null) {
      if (!fs.isEnabled) {
        return null;
      }
      return fs.getRawData();
    }
    return null;
  }

  public byte[] getFile(String origin, String path) {
    return getFile(getKey(origin, path));
  }

  public byte[] getFile(URL u) {
    return getFile(getKey(u));
  }

  public void setFile(String key, FileSwitch fs) {
    map.put(key, fs);
  }

  public void setFile(String origin, String path, FileSwitch fs) {
    setFile(getKey(origin, path), fs);
  }

  public void setFile(URL u, FileSwitch fs) {
    setFile(getKey(u), fs);
  }

  public FileSwitch removeFile(String key) {
    return map.remove(key);
  }

}
