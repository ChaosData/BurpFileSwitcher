package trust.nccgroup.burpfileswitcher;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class FileSwitcherTableModel extends AbstractTableModel {

  private final IBurpExtenderCallbacks callbacks;
  private final static Gson gson = new Gson();

  private String[] columnNames = {
    "Enabled",
    "uri",
    "Comment",
  };

  FileSwitcherTableModel(IBurpExtenderCallbacks _callbacks) {
    super();
    callbacks = _callbacks;
  }

  private List<FileSwitch> fileSwitches = new ArrayList<>();


  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public int getRowCount() {
    return fileSwitches.size();
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    FileSwitch tempFS = fileSwitches.get(row);
    switch (col) {
      case 0:
        return tempFS.isEnabled;
      case 1:
        return tempFS.uri;
      case 2:
        return tempFS.comment;
      default:
        return null;
    }
  }

  @Override
  public Class getColumnClass(int column) {
    Object o = getValueAt(0, column);
    if (null == o) {
      return Void.class;
    }
    return o.getClass();
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return ("Enabled".equals(getColumnName(column)));
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    FileSwitch tempFS = fileSwitches.get(row);
    switch (col) {
      case 0:
        tempFS.isEnabled = (Boolean)value;
        break;
      case 1:
        tempFS.uri = (String)value;
        break;
      case 2:
        tempFS.comment = (String)value;
        break;
      default:
        break;
    }
    fileSwitches.set(row, tempFS);
    save();
  }

  FileSwitch getFileSwitcher(int selectedRow) {
    return fileSwitches.get(selectedRow);
  }

  public void add(FileSwitch f) {
    fileSwitches.add(f);
    save();
  }

  void updateFileSwitcher(int selectedRow, FileSwitch f) {
    fileSwitches.set(selectedRow, f);
    save();
  }

  void deleteFileSwitcher(int selectedRow) {
    fileSwitches.remove(selectedRow);
    save();
  }

  private void copyToFileManager() {
    FileManager fm = FileManager.getInstance();
    fm.clear();
    for (FileSwitch fs : fileSwitches) {
      try {
        fm.setFile(new URL(fs.uri), fs.data.getBytes(StandardCharsets.UTF_8));
      } catch (MalformedURLException e) {
        callbacks.issueAlert("Invalid URL: " + fs.uri);
      }
    }
  }

  void save() {
    copyToFileManager();

    String to_persist = gson.toJson(fileSwitches);
    callbacks.saveExtensionSetting(
      BurpFileSwitcher.extensionName, to_persist
    );
  }

  void load() {
    String persisted = callbacks.loadExtensionSetting(
      BurpFileSwitcher.extensionName
    );

    if (persisted == null) {
      return;
    }

    fileSwitches = gson.fromJson(persisted, new TypeToken<List<FileSwitch>>(){}.getType());
    fireTableDataChanged();

    copyToFileManager();
  }
}
