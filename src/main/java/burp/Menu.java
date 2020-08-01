package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * 菜单类，负责显示菜单，处理菜单事件
 */
public class Menu implements IContextMenuFactory {
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu shicoMenu = new JMenu("Generate shiro Payload");
        JMenuItem payload = new JMenuItem("Generate shiro Payload");
        JMenuItem config = new JMenuItem("Config");
        shicoMenu.add(payload);
        shicoMenu.addSeparator();
        shicoMenu.add(config);

        //若数据包无法编辑，则将编码解码菜单项设置为禁用
        if(invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            config.setEnabled(false);
            payload.setEnabled(false);
        }

        payload.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try {
                    iReqResp.setRequest(GeneratePayload.generatePayload(iReqResp));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        config.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                try {
                    ConfigPanel panel = new ConfigPanel();
                    BurpExtender.callbacks.customizeUiComponent(panel);
                    panel.setVisible(true);
                }catch (Exception e){
                    e.printStackTrace(BurpExtender.stderr);
                }
            }
        });

        menus.add(shicoMenu);
        return menus;
    }
}