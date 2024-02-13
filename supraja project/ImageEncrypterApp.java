import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Font;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class ImageEncrypterApp {

    private static final String KEY_FILE = "key.txt";
    private static final int ITERATION_COUNT = 10000;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> createAndShowGUI());
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Image Encrypter");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setBackground(Color.BLACK);

        // Top Section
        JButton detailsButton = new JButton("Project Info");
        detailsButton.setBackground(Color.ORANGE);
        detailsButton.setForeground(Color.BLACK);
        detailsButton.addActionListener(e -> openDetailsPage());
        frame.getContentPane().add(detailsButton, BorderLayout.NORTH);

        // Center Section
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(Color.BLACK);

        // Text Label
        JLabel titleLabel = new JLabel("                        IMAGE ENCRYPTION ???");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 27));
        titleLabel.setForeground(Color.YELLOW);
        centerPanel.add(titleLabel, BorderLayout.NORTH);

        // Image Label
        ImageIcon imageIcon = new ImageIcon("th.jpeg");
        JLabel imageLabel = new JLabel(imageIcon);
        centerPanel.add(imageLabel, BorderLayout.CENTER);

        // Image Encryption Text
        JTextArea encryptionText = new JTextArea("This is where the image encryption text goes.");
        encryptionText.setFont(new Font("Arial", Font.PLAIN, frame.getHeight() / 4));
        encryptionText.setEditable(false);
        encryptionText.setBackground(Color.BLACK);
        encryptionText.setForeground(Color.YELLOW);
        centerPanel.add(encryptionText, BorderLayout.SOUTH);

        frame.getContentPane().add(centerPanel, BorderLayout.CENTER);

        // Bottom Section
        JPanel bottomPanel = new JPanel();
        JButton encryptButton = new JButton("Encrypt Image");
        JButton decryptButton = new JButton("Decrypt Image");

        encryptButton.addActionListener(e -> {
            try {
                encryptProcess();
            } catch (BadPaddingException | IllegalBlockSizeException e1) {
                e1.printStackTrace();
            }
        });

        decryptButton.addActionListener(e -> decryptProcess());

        setButtonStyles(encryptButton);
        setButtonStyles(decryptButton);

        bottomPanel.add(encryptButton);
        bottomPanel.add(decryptButton);
        frame.getContentPane().add(bottomPanel, BorderLayout.SOUTH);

        frame.setSize(800, 600);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static void setButtonStyles(JButton button) {
        button.setBackground(Color.YELLOW);
        button.setForeground(Color.BLACK);
    }

    private static void encryptProcess() throws BadPaddingException, IllegalBlockSizeException {
        String imagePath = showFileChooser();
        if (imagePath != null) {
            String password = getPassword();
            if (password != null && !password.isEmpty()) {
                try {
                    SecretKey key = generateKey();
                    writeKeyToFile(key, password);

                    // Placeholder: Implement image encryption using the key
                    encryptImage(imagePath, key);

                    JOptionPane.showMessageDialog(null, "Image encrypted successfully.", "Info",
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static void decryptProcess() {
        String imagePath = showFileChooser();
        if (imagePath != null) {
            String password = getPassword();
            if (password != null && !password.isEmpty()) {
                SecretKey key = loadKeyFromFile(password);

                if (key != null) {
                    // Placeholder: Implement image decryption using the key
                    decryptImage(imagePath, key);

                    JOptionPane.showMessageDialog(null, "Image decrypted successfully.", "Info",
                            JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(null, "Invalid password or key not found. Cannot decrypt.", "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private static String showFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile().getPath();
        }
        return null;
    }

    private static String getPassword() {
        return JOptionPane.showInputDialog(null, "Enter the password:");
    }

    private static void openDetailsPage() {
        String htmlPagePath = "index.html";
        try {
            Desktop.getDesktop().browse(URI.create(htmlPagePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static void writeKeyToFile(SecretKey key, String password) throws BadPaddingException, IllegalBlockSizeException {
        try (ObjectOutputStream keyFile = new ObjectOutputStream(new FileOutputStream(KEY_FILE))) {
            byte[] encryptedKey = encryptKey(key, password);
            keyFile.writeObject(encryptedKey);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey loadKeyFromFile(String password) {
        try (ObjectInputStream keyFile = new ObjectInputStream(new FileInputStream(KEY_FILE))) {
            byte[] encryptedKey = (byte[]) keyFile.readObject();
            return decryptKey(encryptedKey, password);
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void encryptImage(String filePath, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] fileData = Files.readAllBytes(Path.of(filePath));
            byte[] encryptedData = cipher.doFinal(fileData);

            Files.write(Path.of(filePath), encryptedData);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Encryption failed for " + filePath + ": " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static void decryptImage(String filePath, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            byte[] encryptedData = Files.readAllBytes(Path.of(filePath));
            byte[] decryptedData = cipher.doFinal(encryptedData);

            Files.write(Path.of(filePath), decryptedData);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Decryption failed for " + filePath + ": " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static byte[] encryptKey(SecretKey key, String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, getKeyFromPassword(password));
        return cipher.doFinal(key.getEncoded());
    }

    private static SecretKey decryptKey(byte[] encryptedKey, String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, getKeyFromPassword(password));
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, "AES");
    }

    private static SecretKey getKeyFromPassword(String password) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), password.getBytes(), ITERATION_COUNT, 128);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error deriving key from password", e);
        }
    }
}
