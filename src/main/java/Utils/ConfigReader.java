package Utils;

import java.io.*;
import java.util.HashMap;
import java.util.Scanner;

import static EncryptionTools.CryptoStuff.*;

public class ConfigReader {

    public static void writeToFile(File file, String username, String hashUsername, String publicKey, String algorithm) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file, true))) {
            String line = String.format("%s:%s:%s:%s", username, hashUsername, publicKey, algorithm);
            writer.write(line);
            writer.newLine();
        }
    }

    public static HashMap<String, String> getUserKeys(File config, String username) throws FileNotFoundException, ConfigNotFoundException {
        Scanner props = new Scanner(config);

        while (props.hasNextLine()) {
            String line = props.nextLine().trim();

            String[] parts = line.split(":", 4);

            if (parts.length == 4) {
                String configUsername = parts[0].trim();

                if (configUsername.equals(username)) {
                    // Found the matching username, read the configuration for this user
                    return readUserKeys(parts);
                }
            }
        }

        throw new ConfigNotFoundException("User not found: " + username);
    }

    private static HashMap<String, String> readUserKeys(String[] parts) {
        HashMap<String, String> userKeys = new HashMap<>();
        userKeys.put(USERNAME, parts[0].trim());
        userKeys.put(HASHED_USERNAME, parts[1].trim());
        userKeys.put(KEY, parts[2].trim());
        userKeys.put(SIGNATURE_ALG, parts[3].trim());
        return userKeys;
    }

    public static HashMap<String, String> read(File config, String id) throws FileNotFoundException, ConfigNotFoundException {
        Scanner props = new Scanner(config);

        while (props.hasNextLine()) {
            String configName = props.nextLine().trim();
            if (configName.equals(id)) {
                return readConfiguration(props);
            } else {
                while (props.hasNextLine()) {
                    String nextLine = props.nextLine().trim();
                    if (nextLine.isEmpty()) {
                        break;
                    }
                }
            }
        }

        throw new ConfigNotFoundException("Configuration not found: " + id);
    }

    private static HashMap<String, String> readConfiguration(Scanner props) {
        HashMap<String, String> configMap = new HashMap<>();
        String transformation = null;

        while (props.hasNextLine()) {
            String line = props.nextLine().trim();


            String[] parts = line.split(":", 2);

            if (parts.length == 2) {

                String key = parts[0].trim();
                String value = parts[1].trim();

                // Special handling for TRANSFORMATION key
                if (CONFIDENTIALITY.equals(key)) {
                    transformation = value;

                    String[] transformationParts = transformation.split("/");
                    if (transformationParts.length > 0) {
                        configMap.put(ALGORITHM, transformationParts[0]);
                    }
                }

                configMap.put(key, value);
            } else if (line.isEmpty()) {
                break;
            }
        }

        return configMap;
    }


}
