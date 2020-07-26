package yso.payloads.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedElement;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface ArgsType {
    String[] value() default {};

    public static class Utils {
        public static String[] getArguments(AnnotatedElement annotated) {
            ArgsType args = annotated.getAnnotation(ArgsType.class);
            if (args != null && args.value() != null) {
                return args.value();
            } else {
                return new String[0];
            }
        }
    }

}
