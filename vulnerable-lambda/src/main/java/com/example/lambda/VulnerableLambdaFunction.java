package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.sql.*;
import java.io.*;
import java.util.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.security.MessageDigest;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * DELIBERATELY VULNERABLE Lambda Function for Security Testing
 * DO NOT USE IN PRODUCTION
 */
public class VulnerableLambdaFunction implements RequestHandler<Map<String, String>, String> {
    
    // VULNERABILITY 1: Hardcoded credentials
    private static final String DB_URL = "jdbc:mysql://prod-db.example.com:3306/userdata";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "Admin123!@#";
    private static final String API_KEY = "sk-1234567890abcdef";
    
    // VULNERABILITY 2: Insecure random number generator
    private static Random random = new Random(12345); // Fixed seed
    
    // BUG 1: Resource leak - connection never closed
    private Connection dbConnection;
    
    @Override
    public String handleRequest(Map<String, String> input, Context context) {
        String userId = input.get("userId");
        String action = input.get("action");
        String xmlData = input.get("xmlData");
        String filePath = input.get("filePath");
        
        // BUG 2: Null pointer exceptions not handled
        String result = "";
        
        try {
            // VULNERABILITY 3: SQL Injection
            result = getUserData(userId);
            
            // VULNERABILITY 4: XXE (XML External Entity) vulnerability
            if (xmlData != null) {
                result += processXML(xmlData);
            }
            
            // VULNERABILITY 5: Path Traversal
            if (filePath != null) {
                result += readFile(filePath);
            }
            
            // VULNERABILITY 6: Command Injection
            if (action != null && action.equals("execute")) {
                String command = input.get("command");
                result += executeCommand(command);
            }
            
            // BUG 3: Insecure password hashing
            String password = input.get("password");
            if (password != null) {
                result += hashPassword(password);
            }
            
            // VULNERABILITY 7: SSRF (Server-Side Request Forgery)
            String url = input.get("url");
            if (url != null) {
                result += fetchURL(url);
            }
            
        } catch (Exception e) {
            // VULNERABILITY 8: Information disclosure in error messages
            return "Error: " + e.getMessage() + "\nStack trace: " + Arrays.toString(e.getStackTrace()) + 
                   "\nDB Connection: " + DB_URL + "\nAPI Key: " + API_KEY;
        }
        
        return result;
    }
    
    // VULNERABILITY 3: SQL Injection - no parameterized queries
    private String getUserData(String userId) throws SQLException {
        if (dbConnection == null) {
            dbConnection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        }
        
        // Direct string concatenation = SQL Injection
        String query = "SELECT * FROM users WHERE user_id = '" + userId + "'";
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        StringBuilder result = new StringBuilder();
        while (rs.next()) {
            // BUG 4: Exposing sensitive data
            result.append("User: ").append(rs.getString("username"))
                  .append(", SSN: ").append(rs.getString("ssn"))
                  .append(", Credit Card: ").append(rs.getString("credit_card"))
                  .append(", Password Hash: ").append(rs.getString("password_hash"));
        }
        
        // BUG 5: Resource leak - ResultSet and Statement never closed
        return result.toString();
    }
    
    // VULNERABILITY 4: XXE vulnerability
    private String processXML(String xmlData) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // XXE vulnerability - external entities enabled by default
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xmlData));
            org.w3c.dom.Document doc = builder.parse(is);
            return "XML processed: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "XML Error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 5: Path Traversal
    private String readFile(String filePath) {
        try {
            // No validation - allows reading any file with ../../../
            File file = new File("/tmp/" + filePath);
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            // BUG 6: Resource leak - reader never closed
            return content.toString();
        } catch (IOException e) {
            return "File error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 6: Command Injection
    private String executeCommand(String command) {
        try {
            // Direct execution without sanitization
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Command error: " + e.getMessage();
        }
    }
    
    // BUG 7: Insecure cryptography
    private String hashPassword(String password) {
        try {
            // VULNERABILITY 9: Using weak/deprecated hashing algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "Hash error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 7: SSRF
    private String fetchURL(String urlString) {
        try {
            // No validation - can access internal resources
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestProperty("Authorization", "Bearer " + API_KEY); // Leaking API key
            
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            // BUG 8: Resource leak
            return content.toString();
        } catch (Exception e) {
            return "URL fetch error: " + e.getMessage();
        }
    }
    
    // VULNERABILITY 10: Race condition
    private int counter = 0;
    
    public void incrementCounter() {
        // Not thread-safe in concurrent Lambda invocations
        counter++;
    }
    
    // BUG 9: Memory leak potential
    private static List<String> logMessages = new ArrayList<>();
    
    public void logMessage(String message) {
        // Unbounded growth
        logMessages.add(message);
    }
}