package burp;

import org.unicodesec.keys;

public class Config {
    private static String shiroKey = keys.keys[0];
    private static String payloadType = "CommonsCollection2";
    private static String exploitType = "XraySysProp";


    public static String getshiroKey() {
        try{
            return BurpExtender.callbacks.loadExtensionSetting("shiroKey");
        }catch (Exception e){
            return Config.shiroKey;
        }

    }

    public static void setshiroKey(String shiroKey) {
        BurpExtender.callbacks.saveExtensionSetting("shiroKey", shiroKey);
    }

    public static String getpayloadType() {
        try{
            return BurpExtender.callbacks.loadExtensionSetting("payloadType");
        }catch (Exception e){
            return Config.payloadType;
        }
    }

    public static void setpayloadType(String payloadType) {
        BurpExtender.callbacks.saveExtensionSetting("payloadType", String.valueOf(payloadType));
    }

    public static String getexploitType() {
        try{
            return BurpExtender.callbacks.loadExtensionSetting("exploitType");
        }catch (Exception e){
            return Config.exploitType;
        }
    }

    public static void setexploitType(String exploitType) {
        BurpExtender.callbacks.saveExtensionSetting("exploitType", exploitType);
    }


}