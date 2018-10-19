package trust.nccgroup.burpfileswitcher;

import burp.IBurpExtenderCallbacks;
import org.fife.rsta.ui.CollapsibleSectionPanel;
import org.fife.rsta.ui.SizeGripIcon;
import org.fife.rsta.ui.search.*;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.function.Supplier;

public class FileSwitcherEditor extends JPanel implements SearchListener {

  private final IBurpExtenderCallbacks callbacks;

  private CollapsibleSectionPanel csp;
  //private RSyntaxTextArea textArea;
  private TextEditorPane textArea;
  private ReplaceToolBar replaceToolBar;
  private LocalStatusBar statusBar;

  public FileSwitcherEditor(IBurpExtenderCallbacks _callbacks) {
    super(new BorderLayout());

    callbacks = _callbacks;

  }

  public TextEditorPane getEditor() {
    return textArea;
  }

  public void postInit() {
    replaceToolBar = new ReplaceToolBar(this);
    csp = new CollapsibleSectionPanel();
    statusBar = new LocalStatusBar();


    this.add(csp);


    int ctrl = getToolkit().getMenuShortcutKeyMask();
    int shift = InputEvent.SHIFT_MASK;
    KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_H, ctrl|shift);
    Action a = csp.addBottomComponent(ks, replaceToolBar);
    a.putValue(Action.NAME, "Show Replace Search Bar");
    a.actionPerformed(null);

    //textArea = new RSyntaxTextArea(25, 80);
    //note: this cannot be constructed in the FSE constructor or everything breaks...
    textArea = new TextEditorPane(RTextArea.INSERT_MODE, true);
    textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVA);
    textArea.setCodeFoldingEnabled(true);
    textArea.setMarkOccurrences(true);
    textArea.setTabSize(2);
    textArea.setTabsEmulated(true);
    textArea.setFont(new Font(Font.MONOSPACED, textArea.getFont().getStyle(), 12));
    try {
      Theme theme = Theme.load(getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
      theme.apply(textArea);
    } catch (IOException e) {
      e.printStackTrace();
    }

    RTextScrollPane sp = new RTextScrollPane(textArea);
    csp.add(sp);

    ErrorStrip errorStrip = new ErrorStrip(textArea);
    this.add(errorStrip, BorderLayout.LINE_END);

    this.add(statusBar, BorderLayout.SOUTH);
  }

  @Override
  public void searchEvent(SearchEvent e) {
    SearchEvent.Type type = e.getType();
    SearchContext context = e.getSearchContext();
    SearchResult result = null;

    switch (type) {
      default: // Prevent FindBugs warning later
      case MARK_ALL:
        result = SearchEngine.markAll(textArea, context);
        break;
      case FIND:
        result = SearchEngine2.find(textArea, context);
        if (!result.wasFound()) {
          UIManager.getLookAndFeel().provideErrorFeedback(textArea);
        }
        break;
      case REPLACE:
        result = SearchEngine2.replace(textArea, context);
        if (!result.wasFound()) {
          UIManager.getLookAndFeel().provideErrorFeedback(textArea);
        }
        break;
      case REPLACE_ALL:
        result = SearchEngine.replaceAll(textArea, context);
        String text = "" + result.getCount() + " occurrences replaced.";
        statusBar.setLabel(text);
//        JOptionPane.showMessageDialog(null, result.getCount() +
//          " occurrences replaced.");
        break;
    }

    String text = null;
    if (result.wasFound()) {
      text = "Text found; occurrences marked: " + result.getMarkedCount();
    }
    else if (type==SearchEvent.Type.MARK_ALL) {
      if (result.getMarkedCount()>0) {
        text = "Occurrences marked: " + result.getMarkedCount();
      }
      else {
        text = "";
      }
    }
    else {
      text = "Text not found";
    }
    statusBar.setLabel(text);

  }

  @Override
  public String getSelectedText() {
    return textArea.getSelectedText();
  }

  public static class LocalStatusBar extends JPanel {
    private JLabel label;

    LocalStatusBar() {
      label = new JLabel("Ready");
      setLayout(new BorderLayout());
      add(label, BorderLayout.LINE_START);
      add(new JLabel(new SizeGripIcon()), BorderLayout.LINE_END);
    }

    void setLabel(String label) {
      this.label.setText(label);
    }
  }


}
