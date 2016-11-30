CREATE TABLE bt_user ( 
user_id SERIAL PRIMARY KEY, 
display_name VARCHAR(100) NOT NULL, 
username VARCHAR(100) NOT NULL, 
email VARCHAR(100) NOT NULL, 
password VARCHAR(255) NOT NULL
); 

CREATE TABLE bug ( 
bug_id SERIAL PRIMARY KEY, 
creator INTEGER NOT NULL REFERENCES bt_user, 
assignee INTEGER REFERENCES bt_user, 
creation_date DATE NOT NULL,
close_date DATE,
title VARCHAR(100) NOT NULL,
description TEXT NOT NULL,
status VARCHAR(100) NOT NULL
); 

CREATE TABLE comment ( 
comment_id SERIAL PRIMARY KEY, 
author INTEGER NOT NULL REFERENCES bt_user, 
bug_id INTEGER NOT NULL REFERENCES bug, 
comment_text TEXT NOT NULL,
post_date DATE NOT NULL
); 


CREATE TABLE user_subscribes_bug ( 
subscription_id SERIAL PRIMARY KEY, 
user_id INTEGER NOT NULL REFERENCES bt_user, 
bug_id INTEGER NOT NULL REFERENCES bug, 
subscription_status BOOLEAN NOT NULL
);

CREATE TABLE tag ( 
tag_id SERIAL PRIMARY KEY, 
bug_id INTEGER NOT NULL REFERENCES bug, 
name VARCHAR(100) NOT NULL
);
