package yso.payloads.gadgets;

import org.reflections.Reflections;
import yso.payloads.exploitType.EXP;

import java.lang.reflect.Modifier;
import java.util.Iterator;
import java.util.Set;


@SuppressWarnings("rawtypes")
public interface ObjectGadget<T> {

    /*
     * return armed payload object to be serialized that will execute specified
     * command on deserialization
     */
    public T getObject(EXP exploitType) throws Exception;

    public static class Utils {

        // get payload classes by classpath scanning
        public static Set<Class<? extends ObjectGadget>> getPayloadClasses() {
            final Reflections reflections = new Reflections(ObjectGadget.class.getPackage().getName());
            final Set<Class<? extends ObjectGadget>> payloadTypes = reflections.getSubTypesOf(ObjectGadget.class);
            for (Iterator<Class<? extends ObjectGadget>> iterator = payloadTypes.iterator(); iterator.hasNext(); ) {
                Class<? extends ObjectGadget> pc = iterator.next();
                if (pc.isInterface() || Modifier.isAbstract(pc.getModifiers())) {
                    iterator.remove();
                }
            }
            return payloadTypes;
        }


        @SuppressWarnings("unchecked")
        public static Class<? extends ObjectGadget> getPayloadClass(final String className) {
            Class<? extends ObjectGadget> clazz = null;
            try {
                clazz = (Class<? extends ObjectGadget>) Class.forName(className);
            } catch (Exception e1) {
            }
            if (clazz == null) {
                try {
                    return clazz = (Class<? extends ObjectGadget>) Class
                            .forName("yso.payloads.gadgets." + className);
                } catch (Exception e2) {
                }
            }
            if (clazz != null && !ObjectGadget.class.isAssignableFrom(clazz)) {
                clazz = null;
            }
            return clazz;
        }

    }
}
