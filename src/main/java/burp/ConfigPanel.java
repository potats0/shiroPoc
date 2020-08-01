package burp;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.unicodesec.keys;
import yso.payloads.Strings;
import yso.payloads.exploitType.EXP;
import yso.payloads.gadgets.ObjectGadget;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 配置窗口类，负责显示配置窗口，处理窗口消息
 */
public class ConfigPanel extends JDialog {
    private final JPanel mainPanel = new JPanel();
    private final JPanel topPanel = new JPanel();
    private final JPanel centerPanel = new JPanel();
    private final JPanel bottomPanel = new JPanel();

    private final JCheckBox cbBuiltInKeys = new JCheckBox("Built in Keys");
    private final JComboBox jcShiroKeys = new JComboBox();

    private final JCheckBox cbProvideKey = new JCheckBox("provide Keys");
    private final JTextField jtkey = new JTextField(Config.getshiroKey());
    private final JLabel jlGadges = new JLabel("avaliable Gadgets");
    private final JComboBox jcGadgets = new JComboBox();

    private final JLabel jlexp = new JLabel("avaliable Exploit");
    private final JComboBox jcexp = new JComboBox();

    private final JButton btSave = new JButton("Save");
    private final JButton btCancel = new JButton("Cancel");


    public ConfigPanel() {
        initGUI();
        initEvent();
        this.setTitle("Generate shiro Payload config");
    }


    /**
     * 初始化UI
     */
    private void initGUI() {
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        cbBuiltInKeys.setSelected(true);
        topPanel.add(cbBuiltInKeys);
        topPanel.add(jcShiroKeys);
        for (String key : keys.keys) {
            jcShiroKeys.addItem(key);
        }
        topPanel.add(cbProvideKey);
        topPanel.add(jtkey);
        topPanel.add(new JLabel(""));

        centerPanel.add(jlGadges);
        centerPanel.add(jcGadgets);
        final List<Class<? extends ObjectGadget>> payloadClasses =
                new ArrayList<Class<? extends ObjectGadget>>(ObjectGadget.Utils.getPayloadClasses());
        Collections.sort(payloadClasses, new Strings.ToStringComparator()); // alphabetize
        for (Class<? extends ObjectGadget> payloadClass : payloadClasses) {
            jcGadgets.addItem(payloadClass.getSimpleName());
        }
        centerPanel.add(jlexp);
        centerPanel.add(jcexp);
        final List<Class<? extends EXP>> expClasses =
                new ArrayList<Class<? extends EXP>>(EXP.Utils.getPayloadClasses());
        Collections.sort(payloadClasses, new Strings.ToStringComparator()); // alphabetize

        for (Class<? extends EXP> payloadClass : expClasses) {
            jcexp.addItem(payloadClass.getSimpleName());
        }


        bottomPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.add(btSave);
        bottomPanel.add(btCancel);

        mainPanel.setLayout(new BorderLayout());
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        this.setModal(true);
        this.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        this.add(mainPanel);
        //使配置窗口自动适应控件大小，防止部分控件无法显示
        this.pack();
        //居中显示配置窗口
        Dimension screensize = Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(screensize.width / 2 - this.getWidth() / 2, screensize.height / 2 - this.getHeight() / 2, this.getWidth(), this.getHeight());
    }


    /**
     * 初始化事件
     */
    private void initEvent() {
        cbBuiltInKeys.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (cbBuiltInKeys.isSelected()) {
                    cbProvideKey.setSelected(false);
                } else {
                    cbProvideKey.setSelected(true);
                }
            }
        });

        cbProvideKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (cbProvideKey.isSelected()) {
                    cbBuiltInKeys.setSelected(false);
                } else {
                    cbBuiltInKeys.setSelected(true);
                }
            }
        });

        btCancel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ConfigPanel.this.dispose();
            }
        });

        btSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String shiroKey;
                if (cbBuiltInKeys.isSelected()) {
                    shiroKey = (String) jcShiroKeys.getSelectedItem();
                } else {
                    shiroKey = jtkey.getText().trim();
                }
                if (Base64.decode(shiroKey).length != 16) {
                    JOptionPane.showConfirmDialog(ConfigPanel.this, String.format("Aes length must be 16bit, but Key length is %d", Base64.decode(shiroKey).length), "Warning", JOptionPane.CLOSED_OPTION, JOptionPane.WARNING_MESSAGE);
                    return;
                }
                Config.setshiroKey(shiroKey);
                Config.setpayloadType((String) jcGadgets.getSelectedItem());
                Config.setexploitType((String) jcexp.getSelectedItem());
                ConfigPanel.this.dispose();
            }
        });
    }

}
