package com.vertica.poc;

import java.awt.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.hc.client5.http.fluent.Content;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;

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
    String endpoint = "";
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
        endpoint = props.getProperty("endpoint");
        tokenUrl = "https://"+endpoint+"/oauth2/default/v1/token";
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
                "\"oauthvalidatehostname\" : \"" + validateHost + "\", " +
                "\"oauthscope\" : \"" + scope + "\"" +
                "}";
        //System.out.println(jsonConfig);
        jdbcOptions.put("oauthjsonconfig", jsonConfig);

        Connection c = DriverManager.getConnection(
                "jdbc:vertica://" + host + ":" + port + "/" + dbName, jdbcOptions);
        Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT CURRENT_USER;");
        while (rs.next()) {
            System.out.println("CURRENT_USER: " + rs.getString(1));
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
        String oauthLoginUrl = "https://"+endpoint+"/oauth2/default/v1/authorize?client_id="+clientId+"&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A32132&state=state-296bc9a0-a2a2-4a57-be1a-d0e2fd9bb601";
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
                    //System.err.println("::" + rets[i]);
                    if (rets[i].startsWith("GET /?code=")) {
                        // probably should validate state also
                        authCode = rets[i].substring(11, rets[i].indexOf('&'));
                        //System.err.println("found code|"+authCode+"|");
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
            /*Content response = Request.post("https://X.okta.com/oauth2/default/v1/token")
                    .addHeader("Authorization", "Basic "+Base64.getEncoder().encodeToString(authBase64.getBytes(StandardCharsets.UTF_8)))
                    .addHeader("Accept", "application/json")
                    .addHeader("Content-Type", "application/x-www-form-urlencoded")
                    .bodyForm(Form.form().add("code", authCode)
                            .add("grant_type", "authorization_code")
                            .add("redirect_uri", "http://localhost:32132")
                            .build())
                    .execute().returnContent();*/
        Content response = Request.post("https://"+endpoint+"/oauth2/default/v1/token?code="+authCode+"&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A32132")
                .addHeader("Authorization", "Basic "+authBase64)
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .execute().returnContent();
        //System.out.println(response.asString());
        Gson gson = new Gson();
        OAuthResponse oar = gson.fromJson(response.asString(), OAuthResponse.class);
        //System.out.println(oar.access_token + "|" + oar.refresh_token);
        accessToken = oar.access_token;
        refreshToken = oar.refresh_token;
    }
    // go get the token directly with username/password
    public void getTokenNonInteractive() throws Exception {
        //String request = "curl --insecure -d \"client_id=0oa4gdz47lUifBW125d7\" -d \"client_secret=DEeM-SkIFa9MTQwKq0W3NCGwhGlI1uv6zoNYpiaQ\" -d \"username=bud.abbott%40vertica.com\" -d \"password=MFGP1234\" -d \"grant_type=password\" -d \"scope=offline_access%20openid\" https://*2571.okta.com/oauth2/default/v1/token";
        //Content response = Request.get(request).execute().returnContent();
        Content response = Request.post(tokenUrl)
                .bodyForm(Form.form().add("client_id", clientId)
                        .add("client_secret", clientSecret)
                        .add("username", username)
                        .add("password", password)
                        .add("grant_type", grant_type)
                        .add("scope", scope)
                        .build())
                .execute().returnContent();
        //System.out.println(response.asString());
        Gson gson = new Gson();
        OAuthResponse oar = gson.fromJson(response.asString(), OAuthResponse.class);
        //System.out.println(oar.access_token + "|" + oar.refresh_token);
        accessToken = oar.access_token;
        refreshToken = oar.refresh_token;
    }
}
