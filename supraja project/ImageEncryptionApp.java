import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;

public class ImageEncryptionApp {

    private static JLabel selectedImageLabel;
    private static BufferedImage selectedImage;
    private static BufferedImage originalImage;
    private static String encryptionPassword;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Image Encryption App");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setLayout(new BorderLayout());
            frame.getContentPane().setBackground(Color.BLACK);

            JPanel headingPanel = new JPanel(new FlowLayout(FlowLayout.CENTER)); // Centered
            headingPanel.setBackground(Color.BLACK);

            JLabel headingLabel = new JLabel("          Image Encryption!!!!        ");
            headingLabel.setFont(new Font("Arial", Font.BOLD, 40));
            headingLabel.setForeground(Color.WHITE);
            headingPanel.add(headingLabel);

            JButton projectInfoButton = new JButton("Project Info");
            projectInfoButton.setForeground(Color.BLACK);
            projectInfoButton.setBackground(new Color(255, 165, 0)); 
            projectInfoButton.setFont(new Font("Arial", Font.BOLD, 14)); 
            projectInfoButton.addActionListener(e -> openProjectInfoPage());

            Dimension buttonSize = new Dimension(120, 40);
            projectInfoButton.setPreferredSize(buttonSize);

            JPanel headerPanel = new JPanel(new BorderLayout());
            headerPanel.setBackground(Color.BLACK);
            headerPanel.add(projectInfoButton, BorderLayout.NORTH);
            headerPanel.add(headingPanel, BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10)); // Centered with some distance
            buttonPanel.setBackground(Color.BLACK);

            selectedImageLabel = new JLabel();
            selectedImageLabel.setHorizontalAlignment(JLabel.CENTER);
            selectedImageLabel.setForeground(Color.WHITE);

            JButton browseButton = new JButton("Browse");
            JButton encryptButton = new JButton("Encrypt");
            JButton decryptButton = new JButton("Decrypt");
            JButton exitButton = new JButton("Exit");

            Color yellowButtonColor = new Color(255, 215, 0); 
            browseButton.setBackground(yellowButtonColor);
            encryptButton.setBackground(yellowButtonColor);
            decryptButton.setBackground(yellowButtonColor);
            exitButton.setBackground(yellowButtonColor);

            Color blackTextColor = Color.BLACK;
            browseButton.setForeground(blackTextColor);
            encryptButton.setForeground(blackTextColor);
            decryptButton.setForeground(blackTextColor);
            exitButton.setForeground(blackTextColor);

            browseButton.setPreferredSize(buttonSize);
            encryptButton.setPreferredSize(buttonSize);
            decryptButton.setPreferredSize(buttonSize);
            exitButton.setPreferredSize(buttonSize);

            JPasswordField passwordField = new JPasswordField(10);
            setPlaceholder(passwordField, "Enter Password");

            browseButton.addActionListener(e -> {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.showOpenDialog(null);
                File selectedFile = fileChooser.getSelectedFile();
                if (selectedFile != null) {
                    originalImage = loadImage(selectedFile);
                    displayImage(originalImage, selectedImageLabel, frame);
                    selectedImageLabel.setText("");
                }
            });

            encryptButton.addActionListener(e -> {
                if (isPasswordEntered(passwordField)) {
                    if (originalImage != null) {
                        BufferedImage whiteImage = createWhiteImage(originalImage.getWidth(), originalImage.getHeight());
                        displayImage(whiteImage, selectedImageLabel, frame);
                        selectedImage = whiteImage;
                        encryptionPassword = new String(passwordField.getPassword());
                        passwordField.setText("");

                        // Save the encrypted image to the same file
                        saveImage(selectedImage, new File("image.jpg"));
                    }
                } else {
                    showPasswordPrompt("Please enter the password");
                }
            });

            decryptButton.addActionListener(e -> {
                if (isPasswordEntered(passwordField)) {
                    if (selectedImage != null) {
                        String enteredPassword = new String(passwordField.getPassword());
                        if (enteredPassword.equals(encryptionPassword)) {
                            displayImage(originalImage, selectedImageLabel, frame);

                            // Save the decrypted image to the same file
                            saveImage(originalImage, new File("image.jpg"));
                        } else {
                            showPasswordPrompt("Please enter the correct password");
                        }
                        passwordField.setText("");
                    }
                } else {
                    showPasswordPrompt("Please enter the password");
                }
            });

            exitButton.addActionListener(e -> System.exit(0));

            frame.add(headerPanel, BorderLayout.NORTH);
            frame.add(selectedImageLabel, BorderLayout.CENTER);
            buttonPanel.add(browseButton);
            buttonPanel.add(encryptButton);
            buttonPanel.add(decryptButton);
            buttonPanel.add(exitButton);
            buttonPanel.add(passwordField);
            frame.add(buttonPanel, BorderLayout.SOUTH);

            frame.setSize(800, 600);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }

    private static void openProjectInfoPage() {
        try {
            File indexHtmlFile = new File("index.html");
            Desktop.getDesktop().browse(indexHtmlFile.toURI());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static BufferedImage loadImage(File file) {
        try {
            return ImageIO.read(file);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void displayImage(BufferedImage image, JLabel label, JFrame frame) {
        int screenWidth = frame.getWidth();
        int screenHeight = frame.getHeight();
        int displayWidth = (int) (screenWidth * 0.25);
        int displayHeight = (int) (screenHeight * 0.25);

        Image scaledImage = image.getScaledInstance(displayWidth, displayHeight, Image.SCALE_SMOOTH);
        ImageIcon imageIcon = new ImageIcon(scaledImage);
        label.setIcon(imageIcon);
    }

    private static void setPlaceholder(JPasswordField passwordField, String placeholder) {
        passwordField.setEchoChar((char) 0);
        passwordField.setText(placeholder);

        passwordField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (String.valueOf(passwordField.getPassword()).equals(placeholder)) {
                    passwordField.setEchoChar('*');
                    passwordField.setText("");
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (String.valueOf(passwordField.getPassword()).isEmpty()) {
                    passwordField.setEchoChar((char) 0);
                    passwordField.setText(placeholder);
                }
            }
        });
    }

    private static boolean isPasswordEntered(JPasswordField passwordField) {
        String enteredPassword = String.valueOf(passwordField.getPassword());
        return enteredPassword != null && !enteredPassword.trim().isEmpty() && !enteredPassword.equals("Enter Password");
    }

    private static void showPasswordPrompt(String message) {
        JOptionPane.showMessageDialog(null, message);
    }

    private static BufferedImage createWhiteImage(int width, int height) {
        BufferedImage whiteImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = whiteImage.createGraphics();
        g2d.setColor(Color.WHITE);
        g2d.fillRect(0, 0, width, height);
        g2d.dispose();
        return whiteImage;
    }

    private static void saveImage(BufferedImage image, File outputFile) {
        try {
            ImageIO.write(image, "png", outputFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}