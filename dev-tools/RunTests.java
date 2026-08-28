import java.lang.reflect.Method;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

public class RunTests {
    public static void main(String[] args) throws Exception {
        int totalPass = 0, totalFail = 0;
        List<String> failures = new ArrayList<>();
        for (String className : args) {
            Class<?> cls = Class.forName(className);
            Object instance = cls.getDeclaredConstructor().newInstance();
            int pass = 0, fail = 0;
            for (Method m : cls.getDeclaredMethods()) {
                boolean isTest = false;
                for (Annotation a : m.getAnnotations()) {
                    if (a.annotationType().getName().equals("org.junit.jupiter.api.Test")) isTest = true;
                }
                if (!isTest) continue;
                m.setAccessible(true);
                String display = m.getName();
                try {
                    for (Annotation a : m.getAnnotations()) {
                        if (a.annotationType().getName().equals("org.junit.jupiter.api.DisplayName")) {
                            Method v = a.annotationType().getMethod("value");
                            display = (String) v.invoke(a);
                        }
                    }
                } catch (Exception ignored) {}
                try {
                    m.invoke(instance);
                    pass++;
                    System.out.println("  PASS  " + className + "#" + m.getName() + "  [" + display + "]");
                } catch (Exception e) {
                    fail++;
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    System.out.println("  FAIL  " + className + "#" + m.getName() + "  [" + display + "]  -- " + cause.getMessage());
                    failures.add(className + "#" + m.getName() + ": " + cause.getMessage());
                }
            }
            System.out.println(className + ": " + pass + " passed, " + fail + " failed");
            totalPass += pass; totalFail += fail;
        }
        System.out.println("=== TOTAL: " + totalPass + " passed, " + totalFail + " failed ===");
        if (totalFail > 0) {
            for (String f : failures) System.out.println("FAILED: " + f);
            System.exit(1);
        }
    }
}
