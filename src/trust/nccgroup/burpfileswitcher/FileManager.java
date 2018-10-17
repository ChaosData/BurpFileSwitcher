package trust.nccgroup.burpfileswitcher;

import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FileManager {

  private Map<String, byte[]> map = new ConcurrentHashMap<>();

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


  public byte[] getFile(String key) {
    return map.getOrDefault(key, null);
  }

  public byte[] getFile(String origin, String path) {
    return getFile(getKey(origin, path));
  }

  public byte[] getFile(URL u) {
    return getFile(getKey(u));
  }

  public void setFile(String key, byte[] data) {
    map.put(key, data);
  }

  public void setFile(String origin, String path, byte[] data) {
    setFile(getKey(origin, path), data);
  }

  public void setFile(URL u, byte[] data) {
    setFile(getKey(u), data);
  }

}
