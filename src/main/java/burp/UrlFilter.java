package burp;

import java.util.HashMap;

public class UrlFilter {
    private static HashMap<String, Boolean> url = new HashMap<>();

    public static boolean isRepeatUrl(String requestUrl){
        return url.containsKey(requestUrl);
    }

    public static void addUrlToFilter(String requestUrl){
        url.put(requestUrl, true);
    }
}
