package burp;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.geom.AffineTransform;
import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JTabbedPane;
import javax.swing.JToolTip;

/**
 * A JTabbedPane which has a close ('X') icon on each tab. To add a tab, use the
 * method addTab(String, Component) To have an extra icon on each tab (e.g. like
 * in JBuilder, showing the file type) use the method addTab(String, Component,
 * Icon). Only clicking the 'X' closes the tab.
 */
public class JClosableTabbedPane extends JTabbedPane implements MouseListener {

    /**
     *
     */
    private static final long serialVersionUID = -6039997512110305471L;
    private double scaleRatio = 0.3;
    private HashMap<String, Component> maps = new HashMap<String, Component>();

    public JClosableTabbedPane() {
        // super();
        new JTabbedPane();
        addMouseListener(this);
    }

    public void addTab(String title, Component component) {
        this.addTab(title, component, null);
    }

    public void addTab(String title, Component component, Icon extraIcon) {
        super.addTab(title, new CloseTabIcon(extraIcon), component);
    }

    public void insertTab(String title, Icon icon, Component component,
                          String tip, int index) {
        tip = "tab" + component.hashCode();
        maps.put(tip, component);
        super.insertTab(title, icon, component, tip, index);
    }

    public void removeTabAt(int index) {
        Component component = getComponentAt(index);
        maps.remove("tab" + component.hashCode());
        super.removeTabAt(index);
    }

    public JToolTip createToolTip() {
        ImageToolTip tooltip = new ImageToolTip();
        tooltip.setComponent(this);
        return tooltip;
    }

    class ImageToolTip extends JToolTip {
        /**
         *
         */
        private static final long serialVersionUID = 2269468166311602352L;

        public Dimension getPreferredSize() {
            String tip = getTipText();
            Component component = maps.get(tip);
            if (component != null) {
                return new Dimension((int) (getScaleRatio() * component
                        .getWidth()), (int) (getScaleRatio() * component
                        .getHeight()));
            } else {
                return super.getPreferredSize();
            }
        }

        public void paintComponent(Graphics g) {
            String tip = getTipText();
            Component component = maps.get(tip);
            if (component instanceof JComponent) {
                JComponent jcomponent = (JComponent) component;
                Graphics2D g2d = (Graphics2D) g;
                AffineTransform at = g2d.getTransform();
                g2d.transform(AffineTransform.getScaleInstance(getScaleRatio(),
                        getScaleRatio()));
                ArrayList<JComponent> dbcomponents = new ArrayList<JComponent>();
                updateDoubleBuffered(jcomponent, dbcomponents);
                jcomponent.paint(g);
                resetDoubleBuffered(dbcomponents);
                g2d.setTransform(at);
            }
        }

        private void updateDoubleBuffered(JComponent component,
                                          ArrayList<JComponent> dbcomponents) {
            if (component.isDoubleBuffered()) {
                dbcomponents.add(component);
                component.setDoubleBuffered(false);
            }
            for (int i = 0; i < component.getComponentCount(); i++) {
                Component c = component.getComponent(i);
                if (c instanceof JComponent) {
                    updateDoubleBuffered((JComponent) c, dbcomponents);
                }
            }
        }

        private void resetDoubleBuffered(ArrayList<JComponent> dbcomponents) {
            for (JComponent component : dbcomponents) {
                component.setDoubleBuffered(true);
            }
        }
    }

    public double getScaleRatio() {
        return scaleRatio;
    }

    public void setScaleRatio(double scaleRatio) {
        this.scaleRatio = scaleRatio;
    }

    public void mouseClicked(MouseEvent e) {

        int tabNumber = getUI().tabForCoordinate(this, e.getX(), e.getY());
        if (tabNumber <= 0) {
            return;
        }
        Rectangle rect = ((CloseTabIcon) getIconAt(tabNumber)).getBounds();
        if (rect.contains(e.getX(), e.getY())) {
            // the tab is being closed
            this.removeTabAt(tabNumber);
        }
    }

    public void mouseEntered(MouseEvent e) {
    }

    public void mouseExited(MouseEvent e) {
    }

    public void mousePressed(MouseEvent e) {
    }

    public void mouseReleased(MouseEvent e) {
    }
}

/**
 * The class which generates the 'X' icon for the tabs. The constructor accepts
 * an icon which is extra to the 'X' icon, so you can have tabs like in
 * JBuilder. This value is null if no extra icon is required.
 */
class CloseTabIcon implements Icon {
    private int x_pos;
    private int y_pos;
    private int width;
    private int height;
    private Icon fileIcon;

    public CloseTabIcon(Icon fileIcon) {
        this.fileIcon = fileIcon;
        width = 16;
        height = 16;
    }

    public void paintIcon(Component c, Graphics g, int x, int y) {
        this.x_pos = x;
        this.y_pos = y;
        Color col = g.getColor();
        g.setColor(Color.gray);
        int y_p = y + 2;

        g.drawLine(x + 7, y_p + 4, x + 12, y_p + 9);
        g.drawLine(x + 12, y_p + 4, x + 7, y_p + 9);
        g.setColor(col);
        if (fileIcon != null) {
            fileIcon.paintIcon(c, g, x + width, y_p);
        }
    }

    public int getIconWidth() {
        return width + (fileIcon != null ? fileIcon.getIconWidth() : 0);
    }

    public int getIconHeight() {
        return height;
    }

    public Rectangle getBounds() {
        return new Rectangle(x_pos, y_pos, width, height);
    }
}
