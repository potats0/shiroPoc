package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender,IHttpListener,IProxyListener {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private String extensionName = "Shiro Echo Tool";
    private String version ="0.0.1";
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(String.format("%s %s",extensionName,version));
        callbacks.registerContextMenuFactory(new Menu());
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        stdout = new PrintWriter(callbacks.getStdout(),true);
        stderr = new PrintWriter(callbacks.getStderr(),true);
        stdout.println(getBanner());
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    }


    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
    }


    /**
     * 插件Banner信息
     * @return
     */
    public String getBanner(){
        String bannerInfo =
                "[+]\n"
                        + "[+] ##############################################\n"
                        + "[+]    " + extensionName + " v" + version +"\n"
                        + "[+]    anthor: UnicodeSec potatso\n"
                        + "[+]    email:  unicodesec@outlook.com\n"
                        + "[+]    github: http://github.com/potats0\n"
                        + "[+] ##############################################";
        return bannerInfo;
    }
}
