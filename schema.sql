-- FRESH SETUP (naya project). Agar v1 pehle se chal raha hai to sirf migration.sql chalao.
create extension if not exists pgcrypto;
create table users(id uuid primary key default gen_random_uuid(), name text not null, number text unique not null, pass_hash text not null, status text not null default 'pending', created_at timestamptz default now());
create table subjects(id uuid primary key default gen_random_uuid(), name text unique not null);
create table units(id uuid primary key default gen_random_uuid(), subject_id uuid references subjects(id) on delete cascade, name text not null, created_at timestamptz default now());
create table uploads(id uuid primary key default gen_random_uuid(), subject_id uuid references subjects(id) on delete cascade, unit_id uuid references units(id) on delete cascade, type text, title text, path text, content_type text, user_id uuid, user_name text, created_at timestamptz default now());
alter table users enable row level security;
alter table subjects enable row level security;
alter table units enable row level security;
alter table uploads enable row level security;
