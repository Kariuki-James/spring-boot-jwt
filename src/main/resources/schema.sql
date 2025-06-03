drop table if exists authorities;
drop table if exists users;
drop index if exists ix_auth_username;

create table if not exists users (
    id bigserial primary key,
    username varchar(50) not null unique,
    password varchar(300) not null,
    enabled boolean not null
);

create table if not exists authorities (
    id bigserial primary key,
    username varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key(username) references users(username)
);

create unique index if not exists ix_auth_username on authorities (username,authority);