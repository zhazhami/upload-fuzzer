package burp;

import java.util.ArrayList;
import java.util.List;

import java.awt.*;
import java.awt.event.*;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.JMenuItem;


public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditor requestViewer;
    private JTabbedPane tabs;
    private int tab_count=0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Upload fuzzer");
        callbacks.registerContextMenuFactory(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                tabs = new JClosableTabbedPane();
                callbacks.customizeUiComponent(tabs);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "Upload fuzzer";
    }

    @Override
    public Component getUiComponent()
    {
        return tabs;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
        JMenuItem menu = new JMenuItem("Send to Upload Fuzzer");
        menu.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                tab_count++;
                FuzzerPanel new_tab = new FuzzerPanel(callbacks,invocation.getSelectedMessages()[0],tab_count+"");
                tabs.add(new_tab,tab_count+"");
            }
        });
        listMenuItems.add(menu);
        return listMenuItems;
    }
}

