package org.mozilla.jss.tests;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

public class JSSConnectionPostgres {

    private Properties props;
    private String url;

    public Connection conn;
    public JSSConnectionPostgres(String user, String password, String url) {
        this.props = new Properties();
        props.setProperty("user", user);
        props.setProperty("password", password);
	this.url = url;
    }

    public void testConnect() throws SQLException {
        conn = DriverManager.getConnection(url, props);
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery(
                "SELECT * FROM pg_catalog.pg_tables");
        while (rs.next()) {
            System.out.println(rs.getString(2));
        }
        rs.close();
        st.close();
    }


    public boolean testPostgres(String url) {

        return false;
    }


    public static void main(String[] args) throws SQLException {
        String socketFactory;
        if(args.length != 3) {
            System.out.println( "\nUSAGE:\n" +
                    "java org.mozilla.jss.tests.JSSConnectionPostgres" +
                    " <user> <password> <url>");
	    System.exit(2);
        }

        if(!args[2].startsWith("jdbc:postgresql:")) {
            System.err.println("Server not supported");
	    System.exit(2);
	}
	System.out.println("Connect");
        JSSConnectionPostgres conn = new JSSConnectionPostgres(args[0], args[1], args[2]);
        System.out.println("Accessing the db");
	conn.testConnect();
        System.out.println("Connection DONE");
    }
}

