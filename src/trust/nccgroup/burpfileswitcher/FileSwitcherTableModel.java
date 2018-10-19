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
    "URI",
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
        return tempFS.getUri();
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
        FileManager.getInstance().removeFile(tempFS.getUriKey());
        tempFS.setUri((String)value);
        add(tempFS, false);
        break;
      case 2:
        tempFS.comment = (String)value;
        break;
      default:
        break;
    }
    save();
  }

  FileSwitch get(int selectedRow) {
    FileSwitch fs = fileSwitches.get(selectedRow);
    if (fs == null) {
      System.out.println("FileSwitcherTableModel::get: invalid row " + selectedRow);
    }
    return fs;
  }

  public void add(FileSwitch f) {
    add(f, true);
  }

  public void add(FileSwitch f, boolean save) {
    FileSwitch popped = FileManager.getInstance().removeFile(f.getUriKey());
    if (popped != null) {
      List<Integer> l = new ArrayList<>();
      // should be only one, but check anyway
      for (int i=0; i<fileSwitches.size(); i++) {
        if (popped.getUriKey().equals(fileSwitches.get(i).getUriKey())) {
          l.add(i);
        }
      }
      for (int i : l) {
        delete(i, false);
      }
    }

    fileSwitches.add(f);
    FileManager.getInstance().setFile(f.getUriKey(), f);
    save();
  }

  void update(int selectedRow, FileSwitch _f) {
    FileSwitch fs = fileSwitches.get(selectedRow);
    FileManager.getInstance().removeFile(fs.getUriKey());
    fs.isEnabled = _f.isEnabled;
    fs.setUri(_f.getUri());
    fs.comment = _f.comment;
    fs.setData(_f.getData());
    add(fs, false);
    save();
  }

  void delete(int selectedRow) {
    delete(selectedRow, true);
  }

  void delete(int selectedRow, boolean save) {
    FileSwitch fs = fileSwitches.remove(selectedRow);
    FileManager.getInstance().removeFile(fs.getUriKey());
    if (save) {
      save();
    }
  }

  private void copyToFileManager() {
    FileManager fm = FileManager.getInstance();
    fm.clear();
    for (FileSwitch fs : fileSwitches) {
      fm.setFile(fs.getUriKey(), fs);
    }
  }

  void save() {
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
    for (FileSwitch fs : fileSwitches) {
      if (fs.getUri() != null) {
        fs.setUri(fs.getUri());
      }
      if (fs.getData() != null) {
        fs.setData(fs.getData());
      }
    }
    fireTableDataChanged();
    copyToFileManager();
  }
}
