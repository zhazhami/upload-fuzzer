package burp;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import java.lang.System;
import java.io.PrintWriter;


public class FuzzerPanel extends JTabbedPane{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public IHttpRequestResponse message;
    PrintWriter stdout;
    public JLabel host = new JLabel("Host: ");
    public JLabel port = new JLabel("Port: ");
    public JTextField ehost = new JTextField(20);
    public JTextField eport = new JTextField(10);
    public JCheckBox https = new JCheckBox();
    public JLabel usehttps = new JLabel("Use HTTPS");
    public ITextEditor content;
    public int[][] fname_pos = new int[100][2];
    public int[] content_type_pos = new int[2];
    public int fname_cnt = 0;
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

    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        System.arraycopy(src, begin, bs, 0, count);
        return bs;
    }

    public FuzzerPanel(IBurpExtenderCallbacks cb,IHttpRequestResponse m,String n) {
        num = n;
        message = m;
        callbacks = cb;
        helpers = callbacks.getHelpers();
        content = callbacks.createTextEditor();
        content.setText(message.getRequest());
        ehost.setText(message.getHttpService().getHost());
        eport.setText(message.getHttpService().getPort()+"");
        boolean ishttps = false;
        if(message.getHttpService().getProtocol()=="https")ishttps=true;
        https.setSelected(ishttps);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.print("hehe");
        initComponents();
    }

    static String num;

    private void initComponents() {
        JPanel target = new JPanel(new CardLayout(20,10));
        JPanel _target = new JPanel();
        target.add(_target);
        _target.setLayout(new BoxLayout(_target,BoxLayout.Y_AXIS));
        _target.setPreferredSize(new Dimension(200,0));
        JPanel target_title = new JPanel();
        target_title.setLayout(new FlowLayout(FlowLayout.LEFT));
        JLabel _title = new JLabel("Attack Target");
        _title.setFont(new Font("Nimbus",1,17));
        _title.setForeground(new Color(255,102,51));
        target_title.add(_title);

        JPanel hostPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hostPanel.add(host);
        hostPanel.add(ehost);
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        portPanel.add(port);
        portPanel.add(eport);
        JPanel httpsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        portPanel.add(https);
        portPanel.add(usehttps);

        _target.add(target_title);
        _target.add(hostPanel);
        _target.add(portPanel);
        _target.add(httpsPanel);
        _target.add(Box.createVerticalStrut(500));
        this.add(target,"Target");

        JPanel positions = new JPanel();
        this.add(positions,"Positions");

        positions.setLayout(new BorderLayout(0, 20));
        JScrollPane b = new JScrollPane(content.getComponent());
        positions.add(b, BorderLayout.CENTER);

        JPanel left = new JPanel();
        left.setPreferredSize(new Dimension(50, 0));
        positions.add(left, BorderLayout.WEST);

        JPanel right = new JPanel(new CardLayout(10,0));
        JPanel _right = new JPanel();
        right.add(_right);
        _right.setLayout(new BoxLayout(_right,BoxLayout.Y_AXIS));
        _right.setPreferredSize(new Dimension(90,0));
        JButton add = new JButton("Add §");
        add.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                byte[] source = content.getText();
                int[] bounds = content.getSelectionBounds();
                fname_pos[fname_cnt][0] = bounds[0]+helpers.bytesToString(content.getSelectedText()).lastIndexOf(".")+1;
                fname_pos[fname_cnt][1] = bounds[1];
                byte[] s = new byte[fname_pos[fname_cnt][1]-fname_pos[fname_cnt][0]+2];
                s[0] = (byte)'$';
                s[s.length-1] = (byte)'$';
                System.arraycopy(source,fname_pos[fname_cnt][0],s,1,fname_pos[fname_cnt][1]-fname_pos[fname_cnt][0]);
                content.setText(Replace(content.getText(),fname_pos[fname_cnt],s));
                fname_pos[fname_cnt++][1]+=2;
            }
        });
        _right.add(add);
        add.setPreferredSize(new Dimension(100,30));
        JButton clear = new JButton("Clear");
        clear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                for(int i=0;i<fname_pos.length;i++) {
                    byte[] source = content.getText();
                    byte[] s = subBytes(source, fname_pos[i][0] + 1, fname_pos[i][1] - fname_pos[i][0] - 2);
                    content.setText(Replace(content.getText(), fname_pos[i], s));
                }
            }
        });
        clear.setPreferredSize(new Dimension(100,30));
        _right.add(clear);
//        JButton cnt_type = new JButton("Content-Type §");
//
//        _right.add(cnt_type);
        add.setPreferredSize(new Dimension(100,30));
        positions.add(right, BorderLayout.EAST);

        JPanel top = new JPanel(new CardLayout(50,10));
        JPanel _top = new JPanel(new BorderLayout());
        top.add(_top);
        JLabel positions_title = new JLabel("Payload Positions");
        positions_title.setFont(new Font("Nimbus",1,17));
        positions_title.setForeground(new Color(255,102,51));
        _top.add(positions_title,BorderLayout.WEST);
        JButton attack = new JButton("Attack");
        attack.setPreferredSize(new Dimension(80,30));

        attack.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFrame frame = new JFrame("Fuzzer attack " + num);
                int windowWidth = frame.getWidth(); //获得窗口宽
                int windowHeight = frame.getHeight(); //获得窗口高
                Toolkit kit = Toolkit.getDefaultToolkit(); //定义工具包
                Dimension screenSize = kit.getScreenSize(); //获取屏幕的尺寸
                int screenWidth = screenSize.width; //获取屏幕的宽
                int screenHeight = screenSize.height; //获取屏幕的高
                frame.setLocation(screenWidth/2-windowWidth/2-400, screenHeight/2-windowHeight/2-400);//设置窗口居中显示
                AttackPanel attackpanel = new AttackPanel(ehost.getText(),Integer.parseInt(eport.getText()),https.isSelected(),content.getText(),fname_pos,fname_cnt,callbacks);
                frame.add(attackpanel);
                frame.setSize(800, 600);
                frame.setVisible(true);
                attackpanel.start();
            }
        });
        _top.add(attack,BorderLayout.EAST);
        positions.add(top, BorderLayout.NORTH);

        JPanel bottom = new JPanel();
        positions.add(bottom, BorderLayout.SOUTH);
    }
}
