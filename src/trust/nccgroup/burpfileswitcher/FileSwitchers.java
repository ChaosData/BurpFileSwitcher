package trust.nccgroup.burpfileswitcher;

import burp.IBurpExtenderCallbacks;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

public class FileSwitchers {

  private final FileSwitcherTab parent;
  private final IBurpExtenderCallbacks callbacks;

  // FileSwitchers UI
  private JPanel fileSwitchersPanel;
  private JScrollPane fileSwitcherScrollPane;
  private JTable fileSwitcherTable;
  private JButton addFileSwitcherButton;
  private JPanel fileSwitchersButtonPanel;
  private JButton editFileSwitcherButton;
  private JButton deleteFileSwitcherButton;

  // FileSwitchers popup UI
  private JPanel fileSwitcherPanel;
  private JTextField fileSwitcherUriTextField;
  private JTextField fileSwitcherRemoteUriTextField;
  private JTextField fileSwitcherCommentTextField;
  private JLabel fileSwitcherUriLabel;
  private JLabel fileSwitcherRemoteUriLabel;
  private JLabel fileSwitcherCommentLabel;

  // FileSwitchers Data Store
  private FileSwitcherTableModel fileSwitcherTableModel;

  public FileSwitchers(FileSwitcherTab _parent, IBurpExtenderCallbacks _callbacks) {
    parent = _parent;
    callbacks = _callbacks;

    createUI();
  }

  public JTable getFileSwitcherTable() { return fileSwitcherTable; }
  public FileSwitcherTableModel getFileSwitcherTableModel() { return fileSwitcherTableModel; }
  public JPanel getUI() { return fileSwitchersPanel; }

  public void save() {
    fileSwitcherTableModel.save();
  }

  public void load() {
    fileSwitcherTableModel.load();
  }


  private void createUI() {
    GridBagConstraints c;
    fileSwitcherPanel = new JPanel();
    fileSwitcherPanel.setLayout(new GridBagLayout());
    fileSwitcherPanel.setPreferredSize(BurpFileSwitcher.dialogDimension);

    c = new GridBagConstraints();

    fileSwitcherUriTextField = new JTextField();
    fileSwitcherRemoteUriTextField = new JTextField();
    fileSwitcherCommentTextField = new JTextField();

    fileSwitcherUriTextField.setPreferredSize(BurpFileSwitcher.textFieldDimension);
    fileSwitcherCommentTextField.setPreferredSize(BurpFileSwitcher.textFieldDimension);

    fileSwitcherUriLabel = new JLabel("URI: ");
    fileSwitcherRemoteUriLabel = new JLabel("Remote URI: ");
    fileSwitcherCommentLabel = new JLabel("Comment: ");

    c.anchor = GridBagConstraints.WEST;
    c.gridx = 0;
    c.gridy = 0;
    fileSwitcherPanel.add(fileSwitcherUriLabel, c);
    c.gridy = 1;
    fileSwitcherPanel.add(fileSwitcherRemoteUriLabel, c);
    c.gridy = 2;
    fileSwitcherPanel.add(fileSwitcherCommentLabel, c);

    c.anchor = GridBagConstraints.EAST;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.gridx = 1;
    c.gridy = 0;
    fileSwitcherPanel.add(fileSwitcherUriTextField, c);
    c.gridy = 1;
    fileSwitcherPanel.add(fileSwitcherRemoteUriTextField, c);
    c.gridy = 2;
    fileSwitcherPanel.add(fileSwitcherCommentTextField, c);

    // FileSwitch Buttons
    addFileSwitcherButton = new JButton("Add");
    addFileSwitcherButton.setPreferredSize(BurpFileSwitcher.buttonDimension);
    addFileSwitcherButton.setMinimumSize(BurpFileSwitcher.buttonDimension);
    addFileSwitcherButton.setMaximumSize(BurpFileSwitcher.buttonDimension);

    // Add New FileSwitch
    addFileSwitcherButton.addActionListener(e -> {
      int result = JOptionPane.showConfirmDialog(
          parent, //BurpExtender.getParentTabbedPane(),
          fileSwitcherPanel,
          "Add File",
          JOptionPane.OK_CANCEL_OPTION,
          JOptionPane.PLAIN_MESSAGE);
      if (result == JOptionPane.OK_OPTION) {
        if (fileSwitcherUriTextField.getText() != null && !"".equals(fileSwitcherUriTextField.getText())) {
          FileSwitch newFileSwitch = new FileSwitch(
            fileSwitcherUriTextField.getText(),
            fileSwitcherRemoteUriTextField.getText(),
            fileSwitcherCommentTextField.getText()
          );
          fileSwitcherTableModel.add(newFileSwitch);
          fileSwitcherTableModel.fireTableDataChanged();
          parent.loadFile(newFileSwitch);
        }
      }
      resetFileSwitcherDialog();
    });

    editFileSwitcherButton = new JButton("Edit");
    editFileSwitcherButton.setPreferredSize(BurpFileSwitcher.buttonDimension);
    editFileSwitcherButton.setMinimumSize(BurpFileSwitcher.buttonDimension);
    editFileSwitcherButton.setMaximumSize(BurpFileSwitcher.buttonDimension);

    // Edit selected FileSwitch
    editFileSwitcherButton.addActionListener(e -> {
      int selectedRow = fileSwitcherTable.getSelectedRow();
      if (selectedRow != -1) {
        FileSwitch tempFileSwitcher = fileSwitcherTableModel.get(selectedRow);

        fileSwitcherUriTextField.setText(tempFileSwitcher.getUri());
        fileSwitcherRemoteUriTextField.setText(tempFileSwitcher.remote_uri);
        fileSwitcherCommentTextField.setText(tempFileSwitcher.comment);

        int result = JOptionPane.showConfirmDialog(
            parent, //BurpExtender.getParentTabbedPane(),
            fileSwitcherPanel,
            "Edit File",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
          FileSwitch newFileSwitcher = new FileSwitch(
              fileSwitcherUriTextField.getText(),
              fileSwitcherRemoteUriTextField.getText(),
              fileSwitcherCommentTextField.getText()
          );
          fileSwitcherTableModel.update(selectedRow, newFileSwitcher);
          fileSwitcherTableModel.fireTableDataChanged();
        }
        resetFileSwitcherDialog();
      }
    });

    deleteFileSwitcherButton = new JButton("Remove");
    deleteFileSwitcherButton.setPreferredSize(BurpFileSwitcher.buttonDimension);
    deleteFileSwitcherButton.setMinimumSize(BurpFileSwitcher.buttonDimension);
    deleteFileSwitcherButton.setMaximumSize(BurpFileSwitcher.buttonDimension);

    //Delete FileSwitch
    deleteFileSwitcherButton.addActionListener(e -> {
      int selectedRow = fileSwitcherTable.getSelectedRow();
      if (selectedRow != -1) {
        fileSwitcherTableModel.delete(selectedRow);
        fileSwitcherTableModel.fireTableDataChanged();
        parent.clearFile();
      }
    });

    fileSwitchersButtonPanel = new JPanel();
    fileSwitchersButtonPanel.setLayout(new GridBagLayout());
    fileSwitchersButtonPanel.setPreferredSize(BurpFileSwitcher.buttonPanelDimension);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_END;
    c.gridx = 0;
    c.weightx = 1;

    fileSwitchersButtonPanel.add(addFileSwitcherButton, c);
    fileSwitchersButtonPanel.add(editFileSwitcherButton, c);
    fileSwitchersButtonPanel.add(deleteFileSwitcherButton, c);
    fileSwitcherTableModel = new FileSwitcherTableModel(callbacks);
    fileSwitcherTable = new JTable(fileSwitcherTableModel);
    fileSwitcherTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    ListSelectionModel lsm = fileSwitcherTable.getSelectionModel();
    lsm.addListSelectionListener(new ListSelectionListener() {
      @Override
      public void valueChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
          return;
        }

        int viewRow = fileSwitcherTable.getSelectedRow();
        if (viewRow >= 0) {
          parent.loadFile(fileSwitcherTableModel.get(viewRow));
          return;
        }

//        int f = e.getFirstIndex();
//        int l = e.getLastIndex();
//
//        for (int i=f; i <= l; i++) {
//          if (lsm.isSelectedIndex(i)) {
//            parent.loadFile(fileSwitcherTableModel.get(i));
//            break;
//          }
//        }
      }
    });

    fileSwitcherTable.getColumnModel().getColumn(0).setMaxWidth(75);
    fileSwitcherTable.getColumnModel().getColumn(0).setMinWidth(75);
    fileSwitcherScrollPane = new JScrollPane(fileSwitcherTable);
    fileSwitcherScrollPane.setMinimumSize(BurpFileSwitcher.tableDimension);

    // Panel containing fileSwitcher options
    fileSwitchersPanel = new JPanel();
    fileSwitchersPanel.setLayout(new GridBagLayout());

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.PAGE_START;
    c.gridx = 0;
    fileSwitchersPanel.add(fileSwitchersButtonPanel, c);

    c.fill = GridBagConstraints.BOTH;
    c.weightx = 1;
    c.weighty = 1;
    c.gridx = 1;
    fileSwitchersPanel.add(fileSwitcherScrollPane, c);
  }

  private void resetFileSwitcherDialog() {
    fileSwitcherUriTextField.setText("");
    fileSwitcherRemoteUriTextField.setText("");
    fileSwitcherCommentTextField.setText("");
  }

}
