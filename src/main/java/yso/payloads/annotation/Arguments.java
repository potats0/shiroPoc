package yso.payloads.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedElement;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Arguments {
    String[] value() default {};

    public static class Utils {
        public static String[] getArguments(AnnotatedElement annotated) {
            Arguments args = annotated.getAnnotation(Arguments.class);
            if (args != null && args.value() != null) {
                return args.value();
            } else {
                return new String[0];
            }
        }
    }

}
