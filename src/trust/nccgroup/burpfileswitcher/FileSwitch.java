package trust.nccgroup.burpfileswitcher;

public class FileSwitch {

  public boolean isEnabled;
  public String uri;
  public String data;
  public String comment;

  public FileSwitch(String _uri, String _comment) {
    uri = _uri;
    comment = _comment;
    data = "";
    isEnabled = true;
  }

}
