INSERT INTO users(username, password, enabled) VALUES ('admin', '{bcrypt}$2a$10$X5wFBtLrL/kHcmrOGGTrGufsBX8CJ0WpQpF3pgeuxBB/H73BK1DW6', true);

INSERT INTO authorities(username, authority) VALUES ('admin', 'ROLE_ADMIN');
INSERT INTO authorities(username, authority) VALUES ('admin', 'ROLE_USER');
