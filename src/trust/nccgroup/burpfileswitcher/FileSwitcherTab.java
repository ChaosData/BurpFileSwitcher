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

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.TextEditorPane;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextArea;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class FileSwitcherTab extends JPanel implements ITab {

  private final IBurpExtenderCallbacks callbacks;
  private JButton button;
  private JSplitPane splitPane;

  public TextEditorPane editor;

  private final FileSwitchers fs;
  private boolean firstResize = true;

  private FileSwitch selectedFileSwitch = null;

  private FileSwitcherEditor fse;

  FileSwitcherTab(IBurpExtenderCallbacks _callbacks) {
    callbacks = _callbacks;
    fs = new FileSwitchers(this, callbacks);
    fse = new FileSwitcherEditor(callbacks);
    //fse = new FileSwitcherEditor();
    initComponents();

//    button.addActionListener((e) -> {
//      if (selectedFileSwitch != null) {
//        selectedFileSwitch.data = editor.getText();
//        selectedFileSwitch.raw_data = selectedFileSwitch.data.getBytes(StandardCharsets.UTF_8);
//        fs.save();
//      }
//    });
    fs.load();
  }

  public void postInit() {
    fse.postInit();
    this.editor = fse.getEditor();
  }

  public FileSwitchers getFileSwitchers() {
    return fs;
  }

  public void highlight() {
    JTabbedPane parentTabbedPane = (JTabbedPane) getUiComponent().getParent();
    if (parentTabbedPane != null) {
      for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
        if (parentTabbedPane.getComponentAt(i).equals(this)) {
          parentTabbedPane.setBackgroundAt(i, new Color(0xff6633));
          Timer timer = new Timer(3000, e -> {
            for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
              if (parentTabbedPane.getComponentAt(j).equals(this)) {
                parentTabbedPane.setBackgroundAt(j, Color.BLACK);
                break;
              }
            }
          });
          timer.setRepeats(false);
          timer.start();
          break;
        }
      }
    }
  }

  private void initComponents() {

    splitPane = new JSplitPane();
    splitPane.addComponentListener(new ComponentAdapter(){
      @Override
      public void componentResized(ComponentEvent e) {
        if(firstResize){
          splitPane.setDividerLocation(0.5);
          splitPane.setResizeWeight(0.5);
          firstResize = false;
        }
      }
    });

    JScrollPane left_scroll = new JScrollPane();
    button = new JButton();
    setLayout(new BorderLayout());
    left_scroll.setViewportView(fs.getUI());
    splitPane.setLeftComponent(left_scroll);

    //note: this is needed to fix a weird bug w/ burp causing key events to drop
    //UIManager.put("RTextAreaUI.actionMap", null);

    UIManager.put("RSyntaxTextAreaUI.actionMap", null);
    JTextComponent.removeKeymap("RTextAreaKeymap");

    //editor = new TextEditorPane(RTextArea.INSERT_MODE, true);
    //editor.setDirty(false);

    /*
    editor.addPropertyChangeListener(TextEditorPane.DIRTY_PROPERTY, new PropertyChangeListener() {
      @Override
      public void propertyChange(PropertyChangeEvent evt) {
        boolean dirty = (Boolean)evt.getNewValue();
        if (dirty) {
          if (selectedFileSwitch != null) {
            selectedFileSwitch.setData(editor.getText());
            fs.save();
          }
          editor.setDirty(false);
        }
      }
    });
    */

//    editor.setCodeFoldingEnabled(false);

//    RTextScrollPane editor_pane = new RTextScrollPane(editor, true);
//    editor.setEnabled(true);
//    editor.setTabSize(2);
//    editor.setTabsEmulated(true);
//    editor_pane.setEnabled(true);

    /*
    editor.addKeyListener(new KeyListener() {
      @Override
      public void keyTyped(KeyEvent e) {
        switch (e.getKeyChar()) {
          case ' ': {
            try {
              editor.getDocument().insertString(editor.getCaretPosition(), " ", null);
            } catch (BadLocationException e1) {
              e1.printStackTrace();
            }
            break;
          }
//          case (char)0xa: {
//            try {
//              editor.getDocument().insertString(editor.getCaretPosition(), (String)editor.getLineSeparator(), null);
//            } catch (BadLocationException e1) {
//              e1.printStackTrace();
//            }
//            break;
//          }
//          case (char)0xd: {
//            try {
//              editor.getDocument().insertString(editor.getCaretPosition(), (String)editor.getLineSeparator(), null);
//            } catch (BadLocationException e1) {
//              e1.printStackTrace();
//            }
//            break;
//          }
        }

//        System.out.println(e);
//        int i = e.getKeyChar();
//        System.out.println(i);

      }

      @Override
      public void keyPressed(KeyEvent e) {
      }

      @Override
      public void keyReleased(KeyEvent e) {
      }
    });
    */

//    LookAndFeel laf = UIManager.getLookAndFeel();
//
//    try {
//      UIManager.setLookAndFeel(InterceptingLookAndFeel.getInstance(laf));
//    } catch (Exception e) {
//      e.printStackTrace();
//    }

//    editor.setFont(new Font(Font.MONOSPACED, editor.getFont().getStyle(), 12));
//    Theme theme;
//    try {
//      theme = Theme.load(getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
//      theme.apply(editor);
//    } catch (IOException e) {
//      e.printStackTrace();
//    }

//    editor.setEditable(false);
//    callbacks.customizeUiComponent(editor);
//    callbacks.customizeUiComponent(editor_pane);

    //splitPane.setRightComponent(editor_pane);
    splitPane.setRightComponent(fse);



    add(splitPane, BorderLayout.CENTER);

//    button.setText("Save");
//    add(button, BorderLayout.SOUTH);
  }


  @Override
  public String getTabCaption() {
    return "File Switcher";
  }

  @Override
  public Component getUiComponent() {
    return this;
  }

  void loadFile(FileSwitch fileSwitcher) {
    if (selectedFileSwitch != null)  {
      selectedFileSwitch.setData(editor.getText());
      fs.save();
    }

    if (fileSwitcher == null) {
      System.out.println("FileSwitcherTab::loadFile: null");
      return;
    }

    selectedFileSwitch = fileSwitcher;

    if (selectedFileSwitch.remote_uri != null && !"".equals(selectedFileSwitch.remote_uri)) {
      editor.setEnabled(false);
      editor.setText("Using remote URI: " + selectedFileSwitch.remote_uri);
      return;
    }

    editor.setText(selectedFileSwitch.getData());
    editor.setDirty(false);

    int rpos = selectedFileSwitch.getUriKey().lastIndexOf('.');
    String ext = "js";
    if (rpos != -1) {
      ext = selectedFileSwitch.getUriKey().substring(rpos+1);
    }

    switch (ext) {
      case "html": {
        editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
        break;
      }
      case "js": {
        editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        break;
      }
      case "json": {
        editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        break;
      }
      case "css": {
        editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CSS);
        break;
      }
      default: {
        editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
      }
    }
    editor.setEditable(true);
  }

  void clearFile() {
    editor.setEditable(false);
    editor.setText("");
    editor.setDirty(false);
    selectedFileSwitch = null;
  }

}
