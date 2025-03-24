create database di_task1;
use di_task1;

create table users(
	uid int primary key auto_increment,
    username varchar(50) unique,
    `password` varchar(256),
    twofa_secret varchar(256));

create table products(
	pid int primary key auto_increment,
    `name` varchar(100),
    `description` varchar(255),
    price decimal(10,2),
    stock int );
alter table products add column created_at timestamp null;