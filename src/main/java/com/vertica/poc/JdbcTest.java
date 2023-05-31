package com.vertica.poc;

// Maven: build with "mvn clean package assembly:single"
// Cmd: run with "java -jar .\target\vertica-jdbc-oauth-methods-0.1-jar-with-dependencies.jar .\voauth.gcp.properties browser"

public class JdbcTest {

    public static void main(String[] args) {
        try {
            OAuthHandler o = new OAuthHandler();
            // init Vertica and OAuth parameters
            if (args.length >= 1) {
                o.init(args[0]);
            }
            // login non-interactively (stored username / password)
            if (args.length == 1 || args[1].equalsIgnoreCase("password")) {
                o.doAuth(false);
            }
            // login interactively with browser and callback
            if (args.length == 1 || args[1].equalsIgnoreCase("browser")) {
                o.doAuth(true);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
