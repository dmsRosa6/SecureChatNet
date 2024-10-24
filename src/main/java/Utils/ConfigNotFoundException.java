package Utils;

public class ConfigNotFoundException extends Exception{
    public ConfigNotFoundException(String message, Throwable throwable) {

        super(message, throwable);
    }

    public ConfigNotFoundException(String message) {

        super(message);
    }
}
