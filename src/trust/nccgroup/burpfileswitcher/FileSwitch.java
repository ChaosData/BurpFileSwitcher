package trust.nccgroup.burpfileswitcher;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class FileSwitch {

  public boolean isEnabled;
  private String uri;
  private transient String uri_key;
  private String data;
  private transient byte[] raw_data;
  public String remote_uri;
  public String comment;

  public FileSwitch(String _uri, String _remote_uri, String _comment) {
    isEnabled = true;
    uri = _uri;
    uri_key = FileManager.getKey(uri);
    data = "";
    raw_data = data.getBytes(StandardCharsets.UTF_8);
    remote_uri = _remote_uri;
    comment = _comment;
  }

  public void setUri(String _uri) {
    uri = _uri;
    uri_key = FileManager.getKey(uri);
  }

  public String getUri() {
    return uri;
  }

  public String getUriKey() {
    return uri_key;
  }

  public void setData(String _data) {
    data = _data;
    raw_data = data.getBytes(StandardCharsets.UTF_8);
  }

  public String getData() {
    return data;
  }

  public byte[] getRawData() {
    return raw_data;
  }

}
