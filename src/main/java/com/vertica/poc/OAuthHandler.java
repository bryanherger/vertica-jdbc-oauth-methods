package com.vertica.poc;

import com.google.gson.Gson;
import org.apache.hc.client5.http.fluent.Content;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;

import java.awt.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;

// this class borrows a lot from https://github.com/snowflakedb/snowflake-jdbc/blob/master/src/main/java/net/snowflake/client/core/SessionUtilExternalBrowser.java
public class OAuthHandler {
    // set these to match your configuration
    String accessToken = "";
    String refreshToken = "";
    String host = "";
    String port = "";
    String dbName = "";
    String username = "";
    String password = "";
    String clientSecret = "";
    String clientId = "";
    String redirectUrl = "";
    String authUrl = "";
    String tokenUrl = "";
    String grant_type = "";
    String scope = "";
    String validateHost = "";

    public void init(String filename) throws Exception {
        Properties props = new Properties();
        props.load(new FileReader(filename));
        host = props.getProperty("host");
        port = props.getProperty("port");
        dbName = props.getProperty("dbName");
        username = props.getProperty("username");
        password = props.getProperty("password");
        clientSecret = props.getProperty("clientSecret");
        clientId = props.getProperty("clientId");
        //endpoint = props.getProperty("endpoint");
        //tokenUrl = "https://"+endpoint+"/oauth2/default/v1/token";
        tokenUrl = props.getProperty("tokenUrl");
        authUrl = props.getProperty("authUrl");
        redirectUrl = props.getProperty("redirectUrl");
        grant_type = props.getProperty("grant_type","password");
        scope = props.getProperty("scope","offline_access openid");
        validateHost = props.getProperty("validateHost","false");
    }
    private void returnToBrowser(Socket socket) throws Exception {
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        java.util.List<String> content = new ArrayList<String>();
        content.add("HTTP/1.0 200 OK");
        content.add("Content-Type: text/html");
        String responseText =
                    "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"/>"
                            + "<title>OAuth Response for Vertica JDBC</title></head>"
                            + "<body>Your identity was confirmed and propagated to "
                            + "Vertica JDBC driver. You can close this window now and go back "
                            + "where you started from.</body></html>";
        content.add(String.format("Content-Length: %s", responseText.length()));
        content.add("");
        content.add(responseText);

        for (int i = 0; i < content.size(); ++i) {
            if (i > 0) {
                out.print("\r\n");
            }
            out.print(content.get(i));
        }
        out.flush();
    }

    public void jdbcCurrentUser() throws Exception {
        // connect and run SELECT CURRENT_USER to verify OAuth succeeded
        Properties jdbcOptions = new Properties();
        jdbcOptions.put("oauthaccesstoken", accessToken);
        if (refreshToken != null) {
            jdbcOptions.put("oauthrefreshtoken", refreshToken);
        }

        // Put these options into static json config
        String jsonConfig = "{\"oauthtokenurl\" : \"" + tokenUrl + "\", " +
                "\"oauthclientid\" : \"" + clientId + "\", " +
                "\"oauthclientsecret\" : \"" + clientSecret + "\", " +
                "\"oauthvalidatehostname\" : \"" + validateHost + "\"" +
                //", " + "\"oauthscope\" : \"" + scope + "\"" +
                "}";
        //System.out.println(jsonConfig);
        jdbcOptions.put("oauthjsonconfig", jsonConfig);

        Connection c = DriverManager.getConnection(
                "jdbc:vertica://" + host + ":" + port + "/" + dbName, jdbcOptions);
        Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT CURRENT_USER;");
        while (rs.next()) {
            System.out.println("SELECT CURRENT_USER returned: " + rs.getString(1));
        }
    }

    public void doAuth(boolean interactive) throws Exception {
        if (interactive) {
            getTokenInteractive();
            System.out.println("INTERACTIVE (browser SSO) login");
        } else {
            // just get using stored username and password
            getTokenNonInteractive();
            System.out.println("NON-INTERACTIVE (user/pass API call) login");
        }
        // open JDBC connection
        jdbcCurrentUser();
    }

    // get the authorization code from browser login and callback, then exchange for access token
    public void getTokenInteractive() throws Exception {
        // open browser
        String stateUuid = UUID.randomUUID().toString();
        String oauthLoginUrl = authUrl+"?client_id="+clientId+"&response_type=code&scope="+scope+"&redirect_uri=http%3A%2F%2Flocalhost%3A32132&state="+stateUuid;
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(new URI(oauthLoginUrl));
        } else {
            throw new Exception("Can't run browser!");
        }
        // wait for callback
        int localPort = 32132;
        ServerSocket ssocket = new ServerSocket(
                32132, // free port
                0, // default number of connections
                InetAddress.getByName("localhost"));

        String authCode = "";
        while (true) {
            Socket socket = ssocket.accept(); // start accepting the request
            try {
                BufferedReader in =
                        new BufferedReader(new InputStreamReader(socket.getInputStream()));
                char[] buf = new char[16384];
                int strLen = in.read(buf);
                String[] rets = new String(buf, 0, strLen).split("\r\n");
                for (int i = 0; i < rets.length; i++) {
                    // GCP and Okta format the redirect differently, so we need to parse out to a Map
                    if (rets[i].contains("code=")) {
                        // probably should validate state also
                        String getCodes = rets[i].substring(6, rets[i].indexOf(' ',8));
                        System.err.println("::" + getCodes);
                        Map<String, String> getMap = new HashMap<>();
                        for (String getCode : getCodes.split("&")) {
                            String[] getTokens = getCode.split("=");
                            getMap.put(getTokens[0], getTokens[1]);
                            System.err.println("Map put|"+getTokens[0]+"|"+getTokens[1]+"|");
                        }
                        String verifyUuid = getMap.get("state");
                        authCode = getMap.get("code");
                        if (authCode == null || "".equalsIgnoreCase(authCode)) {
                            throw new Exception("Didn't get an authorization code from endpoint!");
                        }
                        //System.err.println("found codes|"+authCode+"|"+verifyUuid);
                        if (verifyUuid.equalsIgnoreCase(stateUuid)) {
                            System.err.println("state token is correct!");
                        } else {
                            throw new Exception("state token doesn't match!");
                        }
                        returnToBrowser(socket);
                        break;
                    }
                }
                break;
            } finally {
                socket.close();
            }
        }
        //System.err.println("-DONE-");
        //System.err.flush();
        // now exchange auth code for token
        String authBase64 = Base64.getEncoder().encodeToString((clientId+":"+clientSecret).getBytes(StandardCharsets.UTF_8));
        //System.err.println("authBase64:"+authBase64);
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .POST(BodyPublishers.ofString("grant_type=authorization_code&redirect_uri="+redirectUrl+"&code="+authCode))
                .setHeader("accept", "application/json")
                .setHeader("authorization", "Basic "+authBase64)
                .setHeader("content-type", "application/x-www-form-urlencoded")
                .build();

        HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
        System.err.println("body():"+response.body());
        Gson gson = new Gson();
        OAuthResponse oar = gson.fromJson(response.body(), OAuthResponse.class);
        //System.out.println(oar.access_token + "|" + oar.refresh_token);
        accessToken = oar.access_token;
        refreshToken = oar.refresh_token;
    }
    // go get the token directly with username/password
    public void getTokenNonInteractive() throws Exception {
        //String request = "curl --insecure -d \"client_id=\" -d \"client_secret=\" -d \"username=bud.abbott%40vertica.com\" -d \"password=\" -d \"grant_type=password\" -d \"scope=offline_access%20openid\" https://okta.com/oauth2/default/v1/token";
        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .POST(BodyPublishers.ofString("client_id="+clientId+"&client_secret="+clientSecret+"&username="+username+"&password="+password+"&grant_type="+grant_type+"&scope="+scope+""))
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        HttpResponse<String> hresponse = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.err.println("body():"+hresponse.body());
        //Content response = Request.get(request).execute().returnContent();
        /*Content response = Request.post(tokenUrl)
                .bodyForm(Form.form().add("client_id", clientId)
                        .add("client_secret", clientSecret)
                        .add("username", username)
                        .add("password", password)
                        .add("grant_type", grant_type)
                        .add("scope", scope)
                        .build())
                .execute().returnContent();*/
        //System.out.println(response.asString());
        //OAuthResponse oar = gson.fromJson(response.asString(), OAuthResponse.class);
        Gson gson = new Gson();
        OAuthResponse oar = gson.fromJson(hresponse.body(), OAuthResponse.class);
        //System.out.println(oar.access_token + "|" + oar.refresh_token);
        accessToken = oar.access_token;
        refreshToken = oar.refresh_token;
    }
}
