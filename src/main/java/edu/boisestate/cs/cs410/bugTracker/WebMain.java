package edu.boisestate.cs.cs410.bugTracker;

import org.apache.commons.dbcp2.*;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Service;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Main class for the bug tracker web application.
 */
public class WebMain {
    private static final Logger logger = LoggerFactory.getLogger(WebMain.class);

    public static void main(String[] args) throws URISyntaxException, ClassNotFoundException {
//        if (args.length == 0) {
//            logger.error("no database URI specified");
//            logger.info("provide a database URI as a command line argument");
//            logger.info("expected URI format: postgresql://user:password@localhost/bugTracker");
//            throw new IllegalArgumentException("no URI specified");
//        }

        // PostgreSQL driver doesn't know how to get user & password from URI
        // So we hand-mangle that.
        URI dburi = URI.create("postgres://tvjpycburmsxtl:HfLGRY4yNQi3s6ZfxajyQ29DI8@ec2-54-163-239-12.compute-1.amazonaws.com:5432/d7llvuqrgl1673");
        String auth = dburi.getUserInfo();
        String user = null, password = null;
        if (auth != null) {
            String[] parts = auth.split(":", 2);
            user = parts[0];
            password = parts[1];
            dburi = new URI(dburi.getScheme(), null, dburi.getHost(), dburi.getPort(), dburi.getPath(), dburi.getQuery(), dburi.getFragment());
        }

        // Set up the database pool.
        logger.info("using database URI {}", dburi);
        Class.forName("org.postgresql.Driver");
        ConnectionFactory cxnFac = new DriverManagerConnectionFactory("jdbc:" + dburi.toString(), user, password);
        PoolableConnectionFactory pFac = new PoolableConnectionFactory(cxnFac, null);
        GenericObjectPool<PoolableConnection> objPool = new GenericObjectPool<>(pFac);

        PoolingDataSource<PoolableConnection> source = new PoolingDataSource<>(objPool);

        Service http = Service.ignite();
        int port = Integer.parseInt(System.getenv("PORT"));
        http.port(port);

        BugTrackerServer server = new BugTrackerServer(source, http);

        http.exception(Exception.class, (exception, request, response) -> {
            logger.error("request handler failed", exception);
            response.status(500);
            response.type("text/plain");
            StringWriter writer = new StringWriter();
            PrintWriter print = new PrintWriter(writer);
            print.println("Internal server error");
            print.format("Request url: %s\n", request.url());
            exception.printStackTrace(print);
            response.body(writer.toString());
        });

        logger.info("web app initialized and running");
    }
}
