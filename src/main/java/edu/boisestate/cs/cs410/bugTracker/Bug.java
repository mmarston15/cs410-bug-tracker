package edu.boisestate.cs.cs410.bugTracker;
import java.util.Date;

/**
 * Created by Matt on 11/30/2016.
 */
public class Bug {
    private final long id;
    private User creator;
    private User assignee;
    private String title;
    private String description;
    private String status;
    private Date created;
    private Date closed;

    public Bug(long id) {
        this.id = id;
    }

    public Bug(long id, User creator, User assignee, String title, String description, String status, Date created, Date closed) {
        this.id = id;
        this.creator = creator;
        this.assignee = assignee;
        this.title = title;
        this.description = description;
        this.status = status;
        this.created = created;
        this.closed = closed;
    }

    public long getId() {
        return id;
    }
    public User getCreator() {
        return creator;
    }

    public String getCreatorName() {
        return creator.getName();
    }

    public void setCreator(User creator) {
        this.creator = creator;
    }

    public User getAssignee() {
        return assignee;
    }

    public String getAssigneeName() {
        return assignee.getName();
    }

    public void setAssignee(User assignee) {
        this.assignee = assignee;
    }


    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getClosed() {
        return closed;
    }

    public void setClosed(Date closed) {
        this.closed = closed;
    }
}
