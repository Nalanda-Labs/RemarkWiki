create table users (
  id uuid primary key default gen_random_uuid(),
  email varchar(255) not null,
  username varchar(64) not null,
  password_hash varchar(255) not null,
  first_name varchar(255) default '' not null,
  last_name varchar(255) default '' not null,
  is_admin boolean default false not null,
  created_date timestamptz default now() not null,
  modified_date timestamptz default now() not null,
  created_by uuid default null,
  status varchar(100) default '' not null
);