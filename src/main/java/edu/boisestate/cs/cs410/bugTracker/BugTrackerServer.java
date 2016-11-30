package edu.boisestate.cs.cs410.bugTracker;

import com.mitchellbosecke.pebble.loader.ClasspathLoader;

import org.apache.commons.dbcp2.PoolingDataSource;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.*;
import spark.template.pebble.PebbleTemplateEngine;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * Server for the charity database.
 */
public class BugTrackerServer {
    private static final Logger logger = LoggerFactory.getLogger(BugTrackerServer.class);
    private final PoolingDataSource<? extends Connection> pool;
    private final Service http;
    private final TemplateEngine engine;


    public BugTrackerServer(PoolingDataSource<? extends Connection> pds, Service svc) {
        pool = pds;
        http = svc;
        engine = new PebbleTemplateEngine(new ClasspathLoader());

        http.get("/", this::rootPage, engine);
        http.get("/profile/:bt_user", this::profile, engine);
        http.get("/logout", this::logout);
        http.get("/:bt_user/new-bug", this::newBug, engine);
        http.get("/:bt_user/bug/:bt_bug", this::bug, engine);
        http.get("/:bt_user/bug/:bt_bug/edit", this::editBug, engine);
        http.get("/search", this::search, engine);
        http.post("/:bt_user/submit-new-bug", this::submitNewBug);
        http.post("/:bt_user/bug/:bt_bug/submit-edit", this::submitEditBug);
        http.post("/login", this::login);
        http.post("/createUser", this::createUser);
    }

    public String redirectToFolder(Request request, Response response) {
        String path = request.pathInfo();
        response.redirect(path + "/", 301);
        return "Redirecting to " + path + "/";
    }


    /**
     * Get the logged in user
     * @param request
     * @return
     * @throws SQLException
     */
    private User getUser(Request request) throws SQLException {
        Long uid = request.session().attribute("userId");
        if (uid == null) {
            return null;
        }
        String userQuery = "SELECT username FROM bt_user WHERE user_id = ?";
        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setLong(1, uid);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(uid, rs.getString("username"));
                } else {
                    return null;
                }
            }
        }
    }


    /**
     * Query user by id
     * @param id
     * @return
     * @throws SQLException
     */
    private User getUserById(int id) throws SQLException {
        String userQuery = "SELECT username FROM bt_user WHERE user_id = ?";
        try (Connection cxn = pool.getConnection()) {
            try (PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
                stmt.setLong(1, id);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return new User(id, rs.getString("username"));
                    } else {
                        return null;
                    }
                }
            }
        }
    }


    /**
     * Query bug by id
     * @param bugId
     * @return
     * @throws SQLException
     */
    private Bug getBugById(int bugId) throws SQLException {
        Bug bug = new Bug(bugId);
        int creatorId = 0;
        int assigneeId = 0;

        try (Connection cxn = pool.getConnection()) {
            // Get bug details
            try (PreparedStatement ps = cxn.prepareStatement(
                    "SELECT * FROM bug WHERE bug_id = ?")) {
                ps.setInt(1, bugId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        creatorId = rs.getInt("creator");
                        assigneeId = rs.getInt("assignee");
                        bug.setTitle(rs.getString("title"));
                        bug.setDescription(rs.getString("description"));
                        bug.setStatus(rs.getString("status"));
                        bug.setCreated(rs.getDate("creation_date"));
                        bug.setClosed(rs.getDate("close_date"));

                        // Get created by user and assignee user for bug
                        if (creatorId > 0 && assigneeId > 0) {
                            bug.setCreator(getUserById(creatorId));
                            bug.setAssignee(getUserById(assigneeId));
                        }

                    }
                }
            }
        }
        return bug;
    }


    /**
     * View the root page with basic database info.
     */
    ModelAndView rootPage(Request request, Response response) throws SQLException {
        Map<String,Object> fields = new HashMap<>();
        User user = getUser(request);
        fields.put("user", user);
        // initialize CSRF token
        String token = request.session().attribute("csrf_token");
        if (token == null) {
            SecureRandom rng = new SecureRandom();
            byte[] bytes = new byte[8];
            rng.nextBytes(bytes);
            token = Base64.getEncoder().encodeToString(bytes);
            request.session(true).attribute("csrf_token", token);
        }
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "home.html.twig");
    }


    /**
     * Go to profile page
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    ModelAndView profile(Request request, Response response) throws SQLException {
    	int id = Integer.parseInt(request.params("bt_user"));
    	
        Map<String,Object> fields = new HashMap<>();
        fields.put("id", id);

        try (Connection cxn = pool.getConnection()) {
            // User Info
            try (PreparedStatement ps = cxn.prepareStatement("SELECT username, display_name, email "
        													+ "FROM bt_user "
        													+ "WHERE user_id = ?")) {
        		ps.setInt(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                    	fields.put("username", rs.getString("username"));
                    	fields.put("display_name", rs.getString("display_name"));
                    	fields.put("email", rs.getString("email"));
                    }
                }
        	}

            // Get resolved bug count
            try (PreparedStatement ps = cxn.prepareStatement(
                    "SELECT count(*) "
                    + "FROM bug "
                    + "WHERE assignee = ?"
                    + "AND close_date IS NOT NULL")) {
                ps.setInt(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        fields.put("resolved", rs.getInt("count"));
                    }
                }
            }

            // Assigned Bugs
            try (PreparedStatement ps = cxn.prepareStatement("" +
                    "SELECT bug_id, creation_date, close_date, title, description, status " +
                    "FROM bug WHERE assignee = ?")) {
                ps.setInt(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    List<Map<String,Object>> bugs = new ArrayList<>();
                    while (rs.next()) {
                        Map<String,Object> bug = new HashMap<>();
                        bug.put("bugId", rs.getString("bug_id"));
                        bug.put("creationDate", rs.getDate("creation_date"));
                        bug.put("closeDate", rs.getDate("close_date"));
                        bug.put("title", rs.getString("title"));
                        bug.put("description", rs.getString("description"));
                        bug.put("status", rs.getString("status"));
                        bugs.add(bug);
                    }
                    fields.put("bugs", bugs);
                }
            }
        }

        return new ModelAndView(fields, "profile.html");
    }


    /**
     * Search bugs
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    ModelAndView search(Request request, Response response) throws SQLException {
    	String term = request.queryParams("search");
        if (term == null || term.isEmpty()) {
            http.halt(400, "No search term provided");
        }
    	
        Map<String,Object> fields = new HashMap<>();
        User user = getUser(request);
        fields.put("user", user);
        
        if (user != null) {
            try (Connection cxn = pool.getConnection()) {
                try (PreparedStatement ps = cxn.prepareStatement(
                        "SELECT bug_id, creation_date, close_date, title, description, status "
                        + "FROM bug WHERE to_tsvector(title) @@ to_tsquery(?)")) {
                    ps.setString(1, term);
                    try (ResultSet rs = ps.executeQuery()) {
                        List<Map<String, Object>> searchResults = new ArrayList<>();
                        while (rs.next()) {
                            Map<String, Object> searchData = new HashMap<>();
                            searchData.put("bug_id", rs.getInt("bug_id"));
                            searchData.put("creationDate", rs.getDate("creation_date"));
                            searchData.put("closeDate", rs.getDate("close_date"));
                            searchData.put("title", rs.getString("title"));
                            searchData.put("description", rs.getString("description"));
                            searchData.put("status", rs.getString("status"));
                            searchResults.add(searchData);
                        }
                        fields.put("searchResults", searchResults);
                    }
                }
            }
        }
        
     // initialize CSRF token
        String token = request.session().attribute("csrf_token");
        if (token == null) {
            SecureRandom rng = new SecureRandom();
            byte[] bytes = new byte[8];
            rng.nextBytes(bytes);
            token = Base64.getEncoder().encodeToString(bytes);
            request.session(true).attribute("csrf_token", token);
        }
        fields.put("csrf_token", token);

        return new ModelAndView(fields, "home.html.twig");
    }


    /**
     * Get specific bug details
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    ModelAndView bug(Request request, Response response) throws SQLException {
        int userId = Integer.parseInt(request.params("bt_user"));
        int bugId = Integer.parseInt(request.params("bt_bug"));

        Map<String,Object> fields = new HashMap<>();
        fields.put("userId", userId);
        fields.put("bugId", bugId);

        Bug bug = getBugById(bugId);
        fields.put("bug", bug);

        return new ModelAndView(fields, "bug.html");
    }


    /**
     * Route to new bug form page
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    ModelAndView newBug(Request request, Response response) throws SQLException {
        int userId = Integer.parseInt(request.params("bt_user"));

        Map<String,Object> fields = new HashMap<>();
        fields.put("userId", userId);

        return new ModelAndView(fields, "new-bug.html");
    }


    /**
     * Add a bug from the form data
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    String submitNewBug(Request request, Response response) throws SQLException {
        int userId = Integer.parseInt(request.params("bt_user"));
        String bugTitle = request.queryParams("title");
        if (bugTitle == null || bugTitle.isEmpty()) {
            http.halt(400, "No title provided");
        }
        String description = request.queryParams("description");
        if (description == null || description.isEmpty()) {
            http.halt(400, "No details provided");
        }
        String bugTags = request.queryParams("tags");


        String addBug = "INSERT INTO bug (creator, assignee, creation_date, title, description, status) " +
                "VALUES (?, ?, NOW(), ?, ?, ?)" +
                "RETURNING bug_id";

        long bugId;

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addBug)) {
            stmt.setInt(1, userId);
            stmt.setInt(2, userId);
            stmt.setString(3, bugTitle);
            stmt.setString(4, description);
            stmt.setString(5, "open");
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                rs.next();
                bugId = rs.getLong(1);
                logger.info("added bug {} with id {}", bugTitle, bugId);
            }
        }

        Session session = request.session(true);
        session.attribute("bugId", bugId);

        response.redirect("/profile/" + userId, 303);
        return "See you later!";
    }


    /**
     * Go to edit bug page
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    ModelAndView editBug(Request request, Response response) throws SQLException {
        int userId = Integer.parseInt(request.params("bt_user"));
        int bugId = Integer.parseInt(request.params("bt_bug"));

        Map<String,Object> fields = new HashMap<>();
        fields.put("userId", userId);
        fields.put("bugId", bugId);

        Bug bug = getBugById(bugId);
        fields.put("bug", bug);

        return new ModelAndView(fields, "edit-bug.html");
    }


    String submitEditBug(Request request, Response response) throws SQLException {
        int userId = Integer.parseInt(request.params("bt_user"));
        int bugId = Integer.parseInt(request.params("bt_bug"));
        String bugTitle = request.queryParams("title");
        if (bugTitle == null || bugTitle.isEmpty()) {
            http.halt(400, "No title provided");
        }
        String description = request.queryParams("description");
        if (description == null || description.isEmpty()) {
            http.halt(400, "No details provided");
        }
        String status = request.queryParams("status");
        if (status == null || status.isEmpty()) {
            http.halt(400, "No status selected");
        }
        String bugTags = request.queryParams("tags");
        String addBug;

        if (Objects.equals(status, "closed")) {
            addBug = "UPDATE bug SET title = ?, description = ?, status = ?, close_date = NOW() " +
                    "WHERE bug_id = ?";
        } else {
            addBug = "UPDATE bug SET title = ?, description = ?, status = ? " +
                    "WHERE bug_id = ?";
        }

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addBug)) {
            stmt.setString(1, bugTitle);
            stmt.setString(2, description);
            stmt.setString(3, status);
            stmt.setInt(4, bugId);
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                logger.info("edited bug {} with id {}", bugTitle, bugId);
            }
        }

        Session session = request.session(true);
        session.attribute("bugId", bugId);

        response.redirect("/" + userId + "/bug/" + bugId, 303);
        return "See you later!";
    }


    /**
     * Process logout
     * @param request
     * @param response
     * @return
     */
    String logout(Request request, Response response) {
        request.session().removeAttribute("userId");
        response.redirect("/", 303);
        return "Goodbye";
    }


    /**
     * Process login
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    String login(Request request, Response response) throws SQLException {
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }

        String userQuery = "SELECT user_id, password FROM bt_user WHERE username = ?";

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(userQuery)) {
            stmt.setString(1, name);
            logger.debug("looking up user {}", name);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    logger.debug("found user {}", name);
                    String hash = rs.getString("password");
                    if (BCrypt.checkpw(password, hash)) {
                        logger.debug("user {} has valid password", name);
                        request.session(true).attribute("userId", rs.getLong("user_id"));
                        response.redirect("/", 303);
                        return "Hi!";
                    } else {
                        logger.debug("invalid password for user {}", name);
                    }
                } else {
                    logger.debug("no user {} found", name);
                }
            }
        }

        http.halt(400, "invalid username or password");
        return null;
    }


    /**
     * Create a user
     * @param request
     * @param response
     * @return
     * @throws SQLException
     */
    String createUser(Request request, Response response) throws SQLException {
    	String email = request.queryParams("email");
        if (email == null || email.isEmpty()) {
            http.halt(400, "No email provided");
        }
        String displayName = request.queryParams("displayName");
        if (displayName == null || displayName.isEmpty()) {
            http.halt(400, "No display name provided");
        }
        String name = request.queryParams("username");
        if (name == null || name.isEmpty()) {
            http.halt(400, "No user name provided");
        }
        String password = request.queryParams("password");
        if (password == null || password.isEmpty()) {
            http.halt(400, "No password provided");
        }
        if (!password.equals(request.queryParams("confirm"))) {
            http.halt(400, "Password and confirmation do not match.");
        }

        String pwHash = BCrypt.hashpw(password, BCrypt.gensalt(10));

        String addUser = "INSERT INTO bt_user (email, display_name, username, password) " +
                "VALUES (?, ?, ?, ?) " +
                "RETURNING user_id"; // PostgreSQL extension

        long userId;

        try (Connection cxn = pool.getConnection();
             PreparedStatement stmt = cxn.prepareStatement(addUser)) {
        	stmt.setString(1, email);
            stmt.setString(2, displayName);
            stmt.setString(3, name);
            stmt.setString(4, pwHash);
            stmt.execute();
            try (ResultSet rs = stmt.getResultSet()) {
                rs.next();
                userId = rs.getLong(1);
                logger.info("added user {} with id {}", name, userId);
            }
        }

        Session session = request.session(true);
        session.attribute("userId", userId);

        response.redirect("/", 303);
        return "See you later!";
    }
}
