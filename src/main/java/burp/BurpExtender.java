package burp;

import org.unicodesec.Version;
import org.unicodesec.poc;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IScannerCheck {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    private String extensionName = "Shiro Echo Tool";
    private String version = "0.0.5";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(String.format("%s %s", extensionName, version));
        callbacks.registerContextMenuFactory(new Menu());
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerScannerCheck(this);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
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
     *
     * @return
     */
    public String getBanner() {
        String bannerInfo =
                "[+]\n"
                        + Version.text
                        + "[+]\n"
                        + "[+] ##############################################\n"
                        + "[+]    " + extensionName + " v" + version + "\n"
                        + "[+]    anthor: UnicodeSec potatso\n"
                        + "[+]    email:  unicodesec@outlook.com\n"
                        + "[+]    github: http://github.com/potats0\n"
                        + "[+] ##############################################";
        return bannerInfo;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        String requestDomain = String.format("%s://%s:%d", httpService.getProtocol(), httpService.getHost(), httpService.getPort());

        if (UrlFilter.isRepeatUrl(requestDomain)) {
            return null;
        }

        UrlFilter.addUrlToFilter(requestDomain);
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        URL requestUrl = requestInfo.getUrl();

        if (UrlFilter.isRepeatUrl(requestUrl.toString())) {
            return null;
        }

        UrlFilter.addUrlToFilter(requestUrl.toString());
        IScanIssue issue = poc.shiroDetect(iHttpRequestResponse, helpers, callbacks);
        if (issue == null) {
            return null;
        }
        issues.add(issue);

        try {
            IScanIssue issueKey = poc.shiroKey(iHttpRequestResponse, helpers, callbacks);
            if (issueKey != null) {
                issues.add(issueKey);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return issues;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        if (iScanIssue.getIssueName().equals(iScanIssue1.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}
