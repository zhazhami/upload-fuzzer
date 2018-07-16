package burp;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import java.lang.System;


public class FuzzerPanel extends JTabbedPane{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public IHttpRequestResponse message;
    public JLabel host = new JLabel("Host: ");
    public JLabel port = new JLabel("Port: ");
    public JTextField ehost = new JTextField(20);
    public JTextField eport = new JTextField(10);
    public ITextEditor content;
    public int[] pos = new int[2];
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

        _target.add(target_title);
        _target.add(hostPanel);
        _target.add(portPanel);
        _target.add(Box.createVerticalStrut(1000));
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
                pos[0] = bounds[0]+helpers.bytesToString(content.getSelectedText()).lastIndexOf(".")+1;
                pos[1] = bounds[1];
                byte[] s = new byte[pos[1]-pos[0]+2];
                s[0] = (byte)'$';
                s[s.length-1] = (byte)'$';
                System.arraycopy(source,pos[0],s,1,pos[1]-pos[0]);
                content.setText(Replace(content.getText(),pos,s));
                pos[1]+=2;
            }
        });
        _right.add(add);
        add.setPreferredSize(new Dimension(100,30));
        JButton clear = new JButton("Clear");
        clear.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                byte[] source = content.getText();
                byte[] s = subBytes(source,pos[0]+1,pos[1]-pos[0]-2);
                content.setText(Replace(content.getText(),pos,s));
            }
        });
        clear.setPreferredSize(new Dimension(100,30));
        _right.add(clear);
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
                AttackPanel attackpanel = new AttackPanel(ehost.getText(),Integer.parseInt(eport.getText()),content.getText(),pos,callbacks);
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
